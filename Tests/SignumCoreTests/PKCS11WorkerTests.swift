#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

final class PKCS11WorkerTests: XCTestCase {
    private var executable: URL {
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
    }
    func testDiscoveryAndCertificatesRunOnlyInChild() throws {
        let cert = try CertificateEligibilityTests.fixtures.get().der("valid")
        let mock = try MockModule(certificate: cert), client = IsolatedPKCS11Client(executable: executable)
        let scan = try client.scan(provider: mock.path.path)
        XCTAssertEqual(scan.tokens.map(\.slot), [7]); XCTAssertEqual(scan.provider, mock.path.resolvingSymlinksInPath().path)
        let found = try client.certificates(provider: scan.provider, slot: 7)
        XCTAssertEqual(found.first?.der, cert)
        // The parent has loaded only the fixture's control symbols, never Init.
        XCTAssertEqual(mock.count(0), 0)
    }
    func testBlockedInitializeAndFinalizeAreKilledByDeadline() throws {
        for phase in [0, 1] {
            let mock = try MockModule(workerPhase: phase, workerEffect: 2)
            let start = ProcessInfo.processInfo.systemUptime
            XCTAssertThrowsError(try IsolatedPKCS11Client(executable: executable).scan(provider: mock.path.path, timeout: 0.15)) { error in
                XCTAssertEqual(error as? SupervisedProcess.Failure, .timeout)
            }
            XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 3)
            XCTAssertEqual(mock.count(0), 0)
        }
    }
    func testDelayedAndNoisyProviderCannotCorruptReply() throws {
        for effect in [1, 5] {
            let mock = try MockModule(workerPhase: 2, workerEffect: effect)
            let scan = try IsolatedPKCS11Client(executable: executable).scan(provider: mock.path.path)
            XCTAssertEqual(scan.tokens.count, 1)
        }
    }
    func testCrashAndProviderErrorNeverBecomeSuccess() throws {
        for effect in [3, 4] {
            let mock = try MockModule(workerPhase: 0, workerEffect: effect)
            XCTAssertThrowsError(try IsolatedPKCS11Client(executable: executable).scan(provider: mock.path.path, timeout: 2))
            XCTAssertEqual(mock.count(0), 0)
        }
    }
    func testFakeSignatureRejectedAgainstApprovedCertificate() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let mock = try MockModule(certificate: der, audit: true)
        let client = IsolatedPKCS11Client(executable: executable)
        let found = try XCTUnwrap(client.certificates(provider: mock.path.path, slot: 7).first)
        XCTAssertThrowsError(try client.sign(provider: mock.path.path, slot: 7, certificate: found.certificate, der: der,
            attributes: Data([0x31, 0]), pin: "synthetic-fixture", id: UUID()))
        XCTAssertEqual(mock.count(8), 0)
        let operations = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8)
            .split(separator: "\n").compactMap { Int($0) }
        XCTAssertEqual(operations.filter { $0 == 8 }.count, 1)
        XCTAssertEqual(operations.filter { $0 == 16 }.count, 1)
    }
    func testRealSoftwareRSASignatureIsVerifiedInParent() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("signum-worker-key-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let signer = try SoftwareSigner(folder: folder)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER())
        let client = IsolatedPKCS11Client(executable: executable)
        let found = try XCTUnwrap(client.certificates(provider: mock.path.path, slot: 7).first)
        let prepared = try CAdES.Prepared(document: Data("Approved synthetic bytes".utf8), certificateDER: signer.der)
        let signature = try client.sign(provider: mock.path.path, slot: 7, certificate: found.certificate, der: signer.der,
            attributes: prepared.attributesToSign, pin: "synthetic-fixture", id: UUID())
        XCTAssertEqual(signature.count, 256)
        let cms = try prepared.finish(signature: signature)
        try CAdESVerifier.verifyAttached(data: cms, expectedDocument: Data("Approved synthetic bytes".utf8))
        XCTAssertEqual(mock.count(8), 0); XCTAssertEqual(mock.count(16), 0)
    }
    func testBlockedAuthenticationAndSigningDoNotHangParent() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        for phase in [8, 16] {
            let mock = try MockModule(certificate: der, workerPhase: phase, workerEffect: 2)
            let client = IsolatedPKCS11Client(executable: executable)
            let found = try XCTUnwrap(client.certificates(provider: mock.path.path, slot: 7).first)
            XCTAssertThrowsError(try client.sign(provider: mock.path.path, slot: 7, certificate: found.certificate, der: der,
                attributes: Data([0x31, 0]), pin: "synthetic-fixture", id: UUID(), timeout: 0.15)) { error in
                XCTAssertEqual(error as? SupervisedProcess.Failure, .timeout)
            }
            XCTAssertEqual(mock.count(0), 0)
        }
    }
    func testReplyWithDifferentRequestIdentityIsRejected() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let script = folder.appendingPathComponent("peer")
        let reply = PKCS11WorkerResponse(version: 1, id: UUID(), action: .scan, provider: "/synthetic", tokens: [],
            unavailable: 0, certificates: [], signature: nil, succeeded: true)
        let json = String(decoding: try JSONEncoder().encode(reply), as: UTF8.self)
        try Data(("#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s' '" + json + "'\n").utf8).write(to: script)
        XCTAssertEqual(chmod(script.path, 0o700), 0)
        XCTAssertThrowsError(try IsolatedPKCS11Client(executable: script).scan(provider: "/synthetic")) { error in
            XCTAssertEqual(error as? SupervisedProcess.Failure, .protocolViolation)
        }
    }
    func testProtocolRejectsVersionBoundsAndCredentialsOnPublicRequest() throws {
        let request = PKCS11WorkerRequest(action: .scan, provider: "/synthetic", pin: "synthetic-fixture")
        XCTAssertFalse(request.valid)
        var input = try JSONEncoder().encode(request)
        XCTAssertThrowsError(try SupervisedProcess.run(executable: executable, input: &input, timeout: 2))
        var malformed = Data("{\"version\":999}".utf8)
        XCTAssertThrowsError(try SupervisedProcess.run(executable: executable, input: &malformed, timeout: 2))
    }
}

final class SupervisedProcessTests: XCTestCase {
    private func run(_ script: String, input: inout Data, timeout: TimeInterval = 1,
                     maximumOutput: Int = 131072, cancelled: () -> Bool = { false }) throws -> Data {
        try SupervisedProcess.run(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", script],
            input: &input, maximumOutput: maximumOutput, timeout: timeout, isCancelled: cancelled)
    }
    func testDuplexLargeWriteAndReadWithoutDeadlock() throws {
        var input = Data(repeating: 0x53, count: 100000)
        let expected = input
        let result = try run("/bin/cat", input: &input)
        XCTAssertEqual(result, expected); XCTAssertTrue(input.allSatisfy { $0 == 0 })
    }
    func testNonreadingAndTermIgnoringChildIsKilled() throws {
        var input = Data(repeating: 0x53, count: 100000)
        let start = ProcessInfo.processInfo.systemUptime
        XCTAssertThrowsError(try run("trap '' TERM; while :; do :; done", input: &input, timeout: 0.1)) { error in
            XCTAssertEqual(error as? SupervisedProcess.Failure, .timeout)
        }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 3)
        XCTAssertTrue(input.allSatisfy { $0 == 0 })
    }
    func testCancellationBeforeAndDuringChild() throws {
        for before in [true, false] {
            var input = Data()
            let start = ProcessInfo.processInfo.systemUptime
            XCTAssertThrowsError(try run("while :; do :; done", input: &input, cancelled: {
                before || ProcessInfo.processInfo.systemUptime - start > 0.1
            })) { error in XCTAssertEqual(error as? SupervisedProcess.Failure, .cancelled) }
        }
    }
    func testNoisyOutputAndBrokenInputAndSignalAndLaunchFailures() throws {
        for script in ["while :; do printf 123456789; done", "exit 2", "kill -KILL $$"] {
            var input = Data(repeating: 0x53, count: 100000)
            XCTAssertThrowsError(try run(script, input: &input, maximumOutput: 512))
        }
        var input = Data()
        XCTAssertThrowsError(try SupervisedProcess.run(executable: URL(fileURLWithPath: "/nonexistent/signum-worker"), input: &input))
    }
    func testOversizedInputRejectedBeforeLaunch() throws {
        var input = Data(repeating: 0x53, count: 131073)
        XCTAssertThrowsError(try run("exit 0", input: &input)) { error in
            XCTAssertEqual(error as? SupervisedProcess.Failure, .protocolViolation)
        }
    }
    func testUnexpectedStderrIsDiscarded() throws {
        var input = Data()
        let result = try run("/usr/bin/head -c 262144 /dev/zero >&2; printf structured", input: &input)
        XCTAssertEqual(result, Data("structured".utf8))
    }
}
#endif
