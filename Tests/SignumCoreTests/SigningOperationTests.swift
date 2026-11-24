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
            let states = FixtureLocked<[SigningOperationPhase]>([])
            let operation = SigningOperation { phase in states.withValue { $0.append(phase) } }
            try Data("Changed original".utf8).write(to: job.snapshot.originalURL)
            try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation)
            XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved synthetic bytes".utf8))
            XCTAssertEqual(states.withValue { $0 }, [.preparing, .waitingForAuthentication, .signing, .verifying, .completed])
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
            let reference = FixtureLocked<SigningOperation?>(nil)
            let operation = SigningOperation { phase in if phase == .verifying { reference.withValue { $0 }?.requestCancellation() } }
            reference.withValue { $0 = operation }; defer { reference.withValue { $0 = nil } }
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
        let reference = FixtureLocked<SigningOperation?>(nil)
        let operation = SigningOperation { phase in XCTAssertEqual(reference.withValue { $0 }?.state, phase) }
        reference.withValue { $0 = operation }; defer { reference.withValue { $0 = nil } }
        XCTAssertFalse(operation.transition(to: .signing))
        XCTAssertTrue(operation.transition(to: .preparing)); XCTAssertTrue(operation.transition(to: .verifying))
        XCTAssertTrue(operation.beginPublication()); XCTAssertFalse(operation.requestCancellation())
        XCTAssertTrue(operation.transition(to: .completed)); XCTAssertFalse(operation.transition(to: .failed))
        let native = SigningOperation(); native.transition(to: .preparing); native.requestCancellation()
        native.recordPublished(); XCTAssertEqual(native.state, .completed)
    }
    func testMainQueueRemainsResponsiveDuringBlockedVendor() throws {
        let mock = try MockModule(workerPhase: 0, workerEffect: 10, audit: true)
        let base = mock.folder.appendingPathComponent("operations").path
        guard mkfifo(base + ".main-ready", 0o600) == 0,
              mkfifo(base + ".main-ping", 0o600) == 0 else { throw POSIXError(.EIO) }
        let ready = open(base + ".main-ready", O_RDWR | O_NONBLOCK | O_CLOEXEC)
        let ping = open(base + ".main-ping", O_RDWR | O_NONBLOCK | O_CLOEXEC)
        guard ready >= 0, ping >= 0 else {
            if ready >= 0 { close(ready) }; if ping >= 0 { close(ping) }
            throw POSIXError(.EIO)
        }
        let done = expectation(description: "worker bounded"), heartbeat = expectation(description: "main queue responsive")
        let submitted = ProcessInfo.processInfo.systemUptime
        let timeline = FixtureLocked<[String: TimeInterval]>([:])
        let workerPID = FixtureLocked<pid_t?>(nil)
        let source = DispatchSource.makeReadSource(fileDescriptor: ready, queue: .main)
        source.setCancelHandler { close(ready) }
        defer { source.cancel(); close(ping) }
        source.setEventHandler {
            XCTAssertTrue(Thread.isMainThread)
            var pid: pid_t = 0
            let count = withUnsafeMutableBytes(of: &pid) { read(ready, $0.baseAddress, $0.count) }
            guard count == MemoryLayout<pid_t>.size, pid > 0 else {
                XCTFail("Invalid blocked-provider checkpoint"); source.cancel(); return
            }
            let first = workerPID.withValue { value in
                if let previous = value { XCTAssertEqual(pid, previous); return false }
                value = pid; return true
            }
            timeline.withValue { events in
                XCTAssertNil(events["scan_return"], "Heartbeat must precede scan completion")
                events[first ? "provider_ready_on_main" : "heartbeat_ack_on_main"] = ProcessInfo.processInfo.systemUptime
            }
            if first {
                XCTAssertEqual(kill(pid, 0), 0)
                var message: UInt8 = 72 // 'H'; only the main queue sends it.
                XCTAssertEqual(write(ping, &message, 1), 1)
            } else {
                // The child can only acknowledge after this main queue has
                // handled its readiness message. It never leaves Initialize.
                heartbeat.fulfill(); source.cancel()
            }
        }
        source.resume()
        let client = worker
        DispatchQueue.global().async {
            timeline.withValue { $0["scan_enter"] = ProcessInfo.processInfo.systemUptime }
            do {
                _ = try client.scan(provider: mock.path.path, timeout: 0.3, isCancelled: {
                    // The first check precedes launch; subsequent checks run
                    // after Process.run(), before checking the deadline.
                    timeline.withValue { events in
                        let now = ProcessInfo.processInfo.systemUptime
                        if events["prelaunch_check"] == nil { events["prelaunch_check"] = now }
                        else {
                            if events["supervision_enter"] == nil { events["supervision_enter"] = now }
                            events["last_deadline_check"] = now
                        }
                    }
                    return false
                })
                XCTFail("Blocked provider succeeded")
            }
            catch { XCTAssertEqual(error as? SupervisedProcess.Failure, .timeout) }
            timeline.withValue { $0["scan_return"] = ProcessInfo.processInfo.systemUptime }
            done.fulfill()
        }
        wait(for: [heartbeat, done], timeout: 4)
        let pid = try XCTUnwrap(workerPID.withValue { $0 })
        XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH)
        XCTAssertEqual(mock.count(0), 0) // Initialize ran only in the child.
        let audit = try String(contentsOfFile: base, encoding: .utf8).split(separator: "\n")
        XCTAssertEqual(audit.filter { $0 == "0" }.count, 1)
        let events = timeline.withValue { $0 }
        print("M3_TIMELINE seconds_since_submit " + events.keys.sorted().map { "\($0)=\(events[$0]! - submitted)" }.joined(separator: " "))
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
