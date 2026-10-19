#if os(macOS)
import XCTest
import Foundation
import Darwin
import CProcessCoordination
@testable import SignumCore

final class ProcessCoordinationTests: XCTestCase {
    private var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    // The first process blocks in Initialize after acquiring its complete lease.
    // A compile-time fixture lets subsequent processes run once the lease allows.
    private func withOwner(_ body: (MockModule, Process) throws -> Void) throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let mock = try MockModule(certificate: der, workerPhase: 0, workerEffect: 7, audit: true)
        let owner = Process(), pipe = Pipe()
        owner.executableURL = worker; owner.standardInput = pipe
        owner.standardOutput = FileHandle.nullDevice; owner.standardError = FileHandle.nullDevice
        try owner.run()
        defer {
            try? pipe.fileHandleForWriting.close()
            if owner.isRunning { kill(owner.processIdentifier, SIGKILL) }
            try? FixtureProcess.wait(owner)
        }
        let request = PKCS11WorkerRequest(action: .certificates, provider: mock.path.path, slot: 7)
        try pipe.fileHandleForWriting.write(contentsOf: JSONEncoder().encode(request)); try pipe.fileHandleForWriting.close()
        let marker = mock.folder.appendingPathComponent("operations.once")
        let deadline = ProcessInfo.processInfo.systemUptime + 4
        while !FileManager.default.fileExists(atPath: marker.path) && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.005) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path)); XCTAssertTrue(owner.isRunning)
        try body(mock, owner)
    }
    func testTwoProcessesSameTokenAndProviderAliasesAreExcludedBeforeInitialize() throws {
        try withOwner { mock, _ in
            let client = IsolatedPKCS11Client(executable: worker, leaseWaitMilliseconds: 50)
            let alias = mock.folder.appendingPathComponent("alias.dylib")
            try FileManager.default.linkItem(at: mock.path, to: alias)
            for path in [mock.path, alias] {
                XCTAssertThrowsError(try client.certificates(provider: path.path, slot: 7)) { error in
                    XCTAssertTrue(error is IsolatedPKCS11Client.Failure)
                }
            }
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertEqual(audit.filter { $0 == "0" }.count, 1)
            XCTAssertFalse(audit.contains("8"))
        }
    }
    func testDifferentTokensProceedWhileSameProviderTokenIsBusy() throws {
        try withOwner { mock, owner in
            let client = IsolatedPKCS11Client(executable: worker, leaseWaitMilliseconds: 50)
            XCTAssertFalse(try client.certificates(provider: mock.path.path, slot: 8).isEmpty)
            XCTAssertTrue(owner.isRunning)
        }
    }
    func testDiscoveryWaitsForActiveTokenAndCrashReleasesBothLeases() throws {
        try withOwner { mock, owner in
            let client = IsolatedPKCS11Client(executable: worker, leaseWaitMilliseconds: 50)
            XCTAssertThrowsError(try client.scan(provider: mock.path.path))
            XCTAssertEqual(kill(owner.processIdentifier, SIGKILL), 0); try FixtureProcess.wait(owner)
            XCTAssertEqual(try client.scan(provider: mock.path.path).tokens.count, 1)
            XCTAssertFalse(try client.certificates(provider: mock.path.path, slot: 7).isEmpty)
        }
    }
    func testCancellationWhileWaitingNeverInitializesOrAuthenticates() throws {
        try withOwner { mock, owner in
            let start = ProcessInfo.processInfo.systemUptime
            let client = IsolatedPKCS11Client(executable: worker)
            XCTAssertThrowsError(try client.certificates(provider: mock.path.path, slot: 7, isCancelled: {
                ProcessInfo.processInfo.systemUptime - start > 0.15
            })) { error in XCTAssertEqual(error as? SupervisedProcess.Failure, .cancelled) }
            XCTAssertTrue(owner.isRunning)
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertEqual(audit.filter { $0 == "0" }.count, 1); XCTAssertFalse(audit.contains("8"))
        }
    }
    func testBusySigningJobFailsBeforeProviderAuthenticationAndPublishesNothing() throws {
        try withOwner { mock, _ in
            let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: folder) }
            let source = folder.appendingPathComponent("source"); try Data("synthetic".utf8).write(to: source)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: folder)
            let der = try CertificateEligibilityTests.fixtures.get().der("valid")
            let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7,
                certificate: SignumCertificate(label: "Synthetic", identifier: Data([1])), certificateDER: der,
                destination: folder.appendingPathComponent("result.p7m"))
            let operation = SigningOperation(), client = IsolatedPKCS11Client(executable: worker, leaseWaitMilliseconds: 50)
            XCTAssertThrowsError(try job.signCAdES(using: client, pin: "synthetic-fixture", operation: operation)) { error in
                XCTAssertTrue(error is IsolatedPKCS11Client.Failure)
            }
            XCTAssertEqual(operation.state, .failed)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertFalse(audit.contains("8"))
        }
    }
    func testLeaseFailureDoesNotTouchProviderOrFollowProviderSymlinkIdentityDifferently() throws {
        let mock = try MockModule()
        let alias = mock.folder.appendingPathComponent("symlink.dylib")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: mock.path)
        let lease = try XCTUnwrap(sg_token_lease_acquire(mock.path.path, 7, 0, 0))
        defer { sg_token_lease_release(lease) }
        XCTAssertNil(sg_token_lease_acquire(alias.path, 7, 0, 0)); XCTAssertEqual(errno, ETIMEDOUT)
        let other = try XCTUnwrap(sg_token_lease_acquire(mock.path.path, 8, 0, 0))
        sg_token_lease_release(other); XCTAssertEqual(mock.count(0), 0)
    }
}
#endif
