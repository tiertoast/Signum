#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

final class SigningOperationTests: XCTestCase {
    private var worker: IsolatedPKCS11Client {
        .init(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
    }
    private func withJob(phase: Int? = nil, effect: Int = 0,
                         _ body: (SigningJob, MockModule, SoftwareSigner) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let signer = try SoftwareSigner(folder: folder)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase, workerEffect: effect, audit: true)
        let source = folder.appendingPathComponent("source"); try Data("Approved synthetic bytes".utf8).write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: folder)
        defer { snapshot.close() }
        let cert = try XCTUnwrap(worker.certificates(provider: mock.path.path, slot: 7).first)
        let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7, certificate: cert.certificate,
                                certificateDER: cert.der, destination: folder.appendingPathComponent("signed.p7m"))
        try body(job, mock, signer)
    }
    func testIsolatedJobPublishesOnlyApprovedBytesAndCompletesOnce() throws {
        try withJob { job, mock, _ in
            var states: [SigningOperationPhase] = []
            let operation = SigningOperation { states.append($0) }
            try Data("Changed original".utf8).write(to: job.snapshot.originalURL)
            try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation)
            XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved synthetic bytes".utf8))
            XCTAssertEqual(states, [.preparing, .waitingForAuthentication, .signing, .verifying, .completed])
            XCTAssertEqual(operation.state, .completed); XCTAssertFalse(operation.requestCancellation())
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation))
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertEqual(audit.filter { $0 == "8" }.count, 1); XCTAssertEqual(mock.count(0), 0)
        }
    }
    func testCancellationBeforeSigningNeverAuthenticatesOrPublishes() throws {
        try withJob { job, mock, _ in
            let operation = SigningOperation(); XCTAssertTrue(operation.requestCancellation())
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation))
            XCTAssertEqual(operation.state, .cancelled)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertFalse(audit.contains("8"))
        }
    }
    func testCancellationAfterSignatureBeforeCommitLeavesNoOutput() throws {
        try withJob { job, _, _ in
            var operation: SigningOperation!
            operation = SigningOperation { phase in if phase == .verifying { operation.requestCancellation() } }
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation))
            XCTAssertEqual(operation.state, .cancelled)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
        }
    }
    func testTimeoutOrCrashDuringSignIsUncertainWithoutOutputOrRetry() throws {
        for effect in [2, 3] {
            try withJob(phase: 16, effect: effect) { job, mock, _ in
                let operation = SigningOperation()
                XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation, timeout: 0.15))
                XCTAssertEqual(operation.state, .outcomeUncertain)
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
                let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
                XCTAssertEqual(audit.filter { $0 == "8" }.count, 1); XCTAssertEqual(audit.filter { $0 == "16" }.count, 1)
            }
        }
    }
    func testStateCallbacksReentrantAndCommitBarrierRejectsLateCancel() throws {
        var operation: SigningOperation!
        operation = SigningOperation { phase in XCTAssertEqual(operation.state, phase) }
        XCTAssertFalse(operation.transition(to: .signing))
        XCTAssertTrue(operation.transition(to: .preparing)); XCTAssertTrue(operation.transition(to: .verifying))
        XCTAssertTrue(operation.beginPublication()); XCTAssertFalse(operation.requestCancellation())
        XCTAssertTrue(operation.transition(to: .completed)); XCTAssertFalse(operation.transition(to: .failed))
        let native = SigningOperation(); native.transition(to: .preparing); native.requestCancellation()
        native.recordPublished(); XCTAssertEqual(native.state, .completed)
    }
    func testMainQueueRemainsResponsiveDuringBlockedVendor() throws {
        let mock = try MockModule(workerPhase: 0, workerEffect: 2)
        let done = expectation(description: "worker bounded"), heartbeat = expectation(description: "main queue responsive")
        let client = worker
        DispatchQueue.global().async {
            do { _ = try client.scan(provider: mock.path.path, timeout: 0.3); XCTFail("Blocked provider succeeded") }
            catch { XCTAssertEqual(error as? SupervisedProcess.Failure, .timeout) }
            done.fulfill()
        }
        DispatchQueue.main.async { heartbeat.fulfill() }
        wait(for: [heartbeat, done], timeout: 4)
    }
    func testCLIInterruptAndParentCrashDoNotLeaveOrphanWorker() throws {
        for signalNumber in [SIGINT, SIGKILL] {
            let mock = try MockModule(workerPhase: 0, workerEffect: 2, audit: true)
            let process = Process()
            process.executableURL = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumCLI")
            process.arguments = ["list", mock.path.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run()
            defer { if process.isRunning { kill(process.processIdentifier, SIGKILL) } }
            let pidFile = mock.folder.appendingPathComponent("operations.pid")
            let start = ProcessInfo.processInfo.systemUptime
            var child: Int32?
            while child == nil && ProcessInfo.processInfo.systemUptime - start < 4 {
                child = (try? String(contentsOf: pidFile, encoding: .utf8)).flatMap(Int32.init)
                Thread.sleep(forTimeInterval: 0.005)
            }
            let pid = try XCTUnwrap(child)
            XCTAssertEqual(kill(process.processIdentifier, signalNumber), 0)
            let deadline = ProcessInfo.processInfo.systemUptime + 4
            while (process.isRunning || kill(pid, 0) == 0) && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.01) }
            XCTAssertFalse(process.isRunning); XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH)
        }
    }
}
#endif
