#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

final class SigningOperationTests: XCTestCase {
    private var worker: IsolatedPKCS11Client {
        .init(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
    }
    private func withJob(phase: Int? = nil, effect: Int = 0, useUnrelatedKey: Bool = false,
                         scanCertificate: Bool = true, alwaysAuth: Bool = false,
                         _ body: (SigningJob, MockModule, SoftwareSigner) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let signer = try SoftwareSigner(folder: folder)
        let keyOwner: SoftwareSigner
        if useUnrelatedKey {
            let other = folder.appendingPathComponent("unrelated")
            try FileManager.default.createDirectory(at: other, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            keyOwner = try SoftwareSigner(folder: other)
        } else {
            keyOwner = signer
        }
        let mock = try MockModule(certificate: signer.der, privateKey: keyOwner.rsaPrivateDER(),
                                  workerPhase: phase, workerEffect: effect, audit: true,
                                  alwaysAuth: alwaysAuth, strictContext: alwaysAuth)
        let source = folder.appendingPathComponent("source"); try Data("Approved synthetic bytes".utf8).write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: folder)
        defer { snapshot.close() }
        let certificate: SignumCertificate
        if scanCertificate {
            certificate = try XCTUnwrap(worker.certificates(provider: mock.path.path, slot: 7).first).certificate
        } else {
            certificate = .init(label: "fixture", identifier: Data([0x53]))
        }
        let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7, certificate: certificate,
                                certificateDER: signer.der, destination: folder.appendingPathComponent("signed.p7m"))
        try body(job, mock, signer)
    }
    func testIsolatedJobPublishesOnlyApprovedBytesAndCompletesOnce() throws {
        try withJob { job, mock, _ in
            let states = FixtureLocked<[SigningOperationPhase]>([])
            let operation = SigningOperation { phase in states.withValue { $0.append(phase) } }
            try Data("Changed original".utf8).write(to: job.snapshot.originalURL)
            try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-fixture", operation: operation)
            XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved synthetic bytes".utf8))
            XCTAssertEqual(states.withValue { $0 }, [.preparing, .waitingForAuthentication, .signing, .verifying, .completed])
            XCTAssertEqual(operation.state, .completed); XCTAssertFalse(operation.requestCancellation())
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-fixture", operation: operation))
            let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
            XCTAssertEqual(audit.filter { $0 == "8" }.count, 1); XCTAssertEqual(mock.count(0), 0)
        }
    }
    func testCancellationBeforeSigningNeverAuthenticatesOrPublishes() throws {
        try withJob { job, mock, _ in
            let operation = SigningOperation(); XCTAssertTrue(operation.requestCancellation())
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-fixture", operation: operation))
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
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-fixture", operation: operation))
            XCTAssertEqual(operation.state, .cancelled)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
        }
    }
    func testTimeoutOrCrashDuringSignIsUncertainWithoutOutputOrRetry() throws {
        for effect in [2, 3] {
            try withJob(phase: 16, effect: effect) { job, mock, _ in
                let operation = SigningOperation()
                XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-fixture", operation: operation, timeout: 0.15))
                XCTAssertEqual(operation.state, .outcomeUncertain)
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
                let audit = try String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8).split(separator: "\n")
                XCTAssertEqual(audit.filter { $0 == "8" }.count, 1); XCTAssertEqual(audit.filter { $0 == "16" }.count, 1)
            }
        }
    }
    private func auditDirectory(for job: SigningJob) -> URL {
        job.snapshot.originalURL.deletingLastPathComponent().appendingPathComponent("Signum-CAdES-Worker-Audit-v1")
    }

    private func auditFile(for job: SigningJob) -> URL {
        auditDirectory(for: job).appendingPathComponent(job.id.uuidString + ".jsonl")
    }

    private func auditedWorker(for job: SigningJob, executable: URL? = nil) -> IsolatedPKCS11Client {
        .init(executable: executable ?? worker.executable, auditSupportDirectory: job.snapshot.originalURL.deletingLastPathComponent())
    }

    private func entries(for job: SigningJob) throws -> [CAdESWorkerAudit.Entry] {
        let text = try String(contentsOf: auditFile(for: job), encoding: .utf8)
        return try text.split(separator: "\n").map { try JSONDecoder().decode(CAdESWorkerAudit.Entry.self, from: Data($0.utf8)) }
    }

    func testAuditRecordsVerifiedSigningAndContainsOnlyDiagnosticFields() throws {
        try withJob(alwaysAuth: true) { job, mock, _ in
            try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret", operation: .init())
            let audit = try entries(for: job)
            let pid = try XCTUnwrap(audit.first { $0.event == .workerLaunched }?.workerPID)
            XCTAssertGreaterThan(pid, 0)
            XCTAssertTrue(audit.allSatisfy { $0.jobID == job.id && $0.action == "rsaSHA256" && $0.timestampMs > 0 })
            XCTAssertTrue(audit.dropFirst().allSatisfy { $0.workerPID == pid })
            let functions = [
                "C_Initialize", "C_OpenSession", "C_CloseSession", // Public certificate binding.
                "C_OpenSession", "C_Login", "C_SignInit", "C_Login", "C_Sign", "C_CloseSession", "C_Finalize"
            ]
            XCTAssertEqual(audit.filter { $0.event == .pkcs11Enter }.compactMap(\.function), functions)
            XCTAssertEqual(audit.filter { $0.event == .pkcs11Return }.compactMap(\.function), functions)
            XCTAssertEqual(audit.filter { $0.event == .pkcs11Return }.compactMap(\.code), Array(repeating: 0, count: functions.count))
            let sign = try XCTUnwrap(audit.first { $0.event == .pkcs11Enter && $0.function == "C_Sign" })
            XCTAssertEqual(sign.mechanism, 0x40)
            XCTAssertGreaterThan(try XCTUnwrap(sign.inputBytes), 51)
            let module = try XCTUnwrap(audit.first { $0.event == .moduleLoaded })
            XCTAssertEqual(module.moduleName, mock.path.lastPathComponent)
            var identity = stat()
            XCTAssertEqual(stat(mock.path.path, &identity), 0)
            XCTAssertEqual(module.moduleDevice, identity.st_dev)
            XCTAssertEqual(module.moduleInode, identity.st_ino)
            XCTAssertTrue(audit.contains { $0.event == .responseReceived })
            XCTAssertTrue(audit.contains { $0.event == .signatureVerified })
            XCTAssertEqual(audit.last?.phase, SigningOperationPhase.completed.rawValue)
            XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved synthetic bytes".utf8))

            let text = try String(contentsOf: auditFile(for: job), encoding: .utf8)
            let allowedFields: Set<String> = ["timestampMs", "jobID", "workerPID", "action", "event", "function", "code", "phase",
                                              "mechanism", "inputBytes", "moduleName", "moduleDevice", "moduleInode"]
            for line in text.split(separator: "\n") {
                let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
                XCTAssertTrue(Set(object.keys).isSubset(of: allowedFields))
            }
            for secret in ["synthetic-secret", "Approved synthetic bytes", mock.path.path, job.certificateDER.base64EncodedString()] {
                XCTAssertFalse(text.contains(secret))
            }
            for (url, mode) in [(auditDirectory(for: job), 0o700), (auditFile(for: job), 0o600)] {
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, mode)
            }
        }
    }

    func testAuditDistinguishesNoLaunchFromFailureBeforeSign() throws {
        try withJob { job, _, _ in
            let operation = SigningOperation()
            operation.requestCancellation()
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret", operation: operation))
            let audit = try entries(for: job)
            XCTAssertEqual(audit.map(\.event), [.jobStarted, .requestNotStarted, .jobEnded])
            XCTAssertTrue(audit.allSatisfy { $0.workerPID == nil })
            XCTAssertEqual(audit.last?.phase, SigningOperationPhase.cancelled.rawValue)
        }
        for (fault, function) in [(0, "C_Initialize"), (8, "C_Login")] {
            try withJob(phase: fault, effect: 4, scanCertificate: false) { job, _, _ in
                let operation = SigningOperation()
                XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret", operation: operation))
                let audit = try entries(for: job)
                XCTAssertTrue(audit.contains { $0.event == .requestAccepted })
                XCTAssertTrue(audit.contains { $0.event == .pkcs11Return && $0.function == function && $0.code == 5 })
                XCTAssertFalse(audit.contains { $0.function == "C_Sign" })
                XCTAssertTrue(audit.contains { $0.event == .providerRejected })
                XCTAssertEqual(operation.state, .outcomeUncertain)
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            }
        }
    }

    func testAuditRetainsSignEntryAfterTimeoutOrCrashWithoutRetry() throws {
        for (effect, timedOut) in [(2, true), (3, false)] {
            try withJob(phase: 16, effect: effect) { job, _, _ in
                let operation = SigningOperation()
                XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret",
                                                      operation: operation, timeout: 2))
                let audit = try entries(for: job)
                XCTAssertEqual(audit.filter { $0.event == .pkcs11Enter && $0.function == "C_Sign" }.count, 1)
                XCTAssertFalse(audit.contains { $0.event == .pkcs11Return && $0.function == "C_Sign" })
                XCTAssertTrue(audit.contains { $0.event == .workerSignalled && $0.code == UInt64(timedOut ? SIGTERM : SIGABRT) })
                XCTAssertEqual(audit.contains { $0.event == .timeout }, timedOut)
                XCTAssertEqual(audit.contains { $0.event == .terminationRequested }, timedOut)
                XCTAssertFalse(audit.contains { $0.event == .responseReceived || $0.event == .signatureVerified })
                XCTAssertEqual(operation.state, .outcomeUncertain)
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            }
        }
    }

    func testAuditRecordsCancellationWhileSignIsBlocked() throws {
        try withJob(phase: 16, effect: 2) { job, _, _ in
            let operation = SigningOperation()
            let file = auditFile(for: job)
            let observed = expectation(description: "Observed C_Sign and requested cancellation")
            DispatchQueue.global().async {
                let deadline = ProcessInfo.processInfo.systemUptime + 4
                while ProcessInfo.processInfo.systemUptime < deadline {
                    if let data = try? String(contentsOf: file, encoding: .utf8),
                       data.split(separator: "\n").contains(where: { line in
                           let entry = try? JSONDecoder().decode(CAdESWorkerAudit.Entry.self, from: Data(line.utf8))
                           return entry?.event == .pkcs11Enter && entry?.function == "C_Sign"
                       }) {
                        operation.requestCancellation()
                        observed.fulfill()
                        return
                    }
                    Thread.sleep(forTimeInterval: 0.005)
                }
            }
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret",
                                                   operation: operation, timeout: 5))
            wait(for: [observed], timeout: 1)
            let audit = try entries(for: job)
            XCTAssertTrue(audit.contains { $0.event == .cancelled })
            XCTAssertTrue(audit.contains { $0.event == .terminationRequested })
            XCTAssertEqual(audit.filter { $0.event == .pkcs11Enter && $0.function == "C_Sign" }.count, 1)
            XCTAssertFalse(audit.contains { $0.event == .pkcs11Return && $0.function == "C_Sign" })
            XCTAssertEqual(operation.state, .outcomeUncertain)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
        }
    }

    func testAuditDistinguishesFailedCleanupFromRejectedSignature() throws {
        for failedCleanup in [true, false] {
            try withJob(phase: failedCleanup ? 1 : nil, effect: 4,
                        useUnrelatedKey: !failedCleanup, scanCertificate: false) { job, _, _ in
                let operation = SigningOperation()
                XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret", operation: operation))
                let audit = try entries(for: job)
                XCTAssertEqual(audit.filter { $0.event == .pkcs11Enter && $0.function == "C_Sign" }.count, 1)
                XCTAssertTrue(audit.contains { $0.event == .pkcs11Return && $0.function == "C_Sign" && $0.code == 0 })
                XCTAssertTrue(audit.contains { $0.event == .pkcs11Return && $0.function == "C_Finalize" && $0.code == (failedCleanup ? 5 : 0) })
                XCTAssertTrue(audit.contains { $0.event == .responseReceived })
                XCTAssertTrue(audit.contains { $0.event == (failedCleanup ? .providerRejected : .signatureRejected) })
                XCTAssertFalse(audit.contains { $0.event == .signatureVerified })
                XCTAssertEqual(operation.state, .outcomeUncertain)
                XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            }
        }
    }

    func testAuditRecordsInvalidIPCResponseAndRefusesLinkedAuditDirectory() throws {
        try withJob { job, _, _ in
            let helper = job.snapshot.originalURL.deletingLastPathComponent().appendingPathComponent("invalid-reply")
            try Data("#!/bin/sh\n/bin/cat >/dev/null\nprintf invalid\n".utf8).write(to: helper)
            XCTAssertEqual(chmod(helper.path, 0o700), 0)
            XCTAssertThrowsError(try job.signCAdES(using: auditedWorker(for: job, executable: helper),
                                                   pin: "synthetic-secret", operation: .init()))
            let audit = try entries(for: job)
            XCTAssertTrue(audit.contains { $0.event == .responseReceived })
            XCTAssertTrue(audit.contains { $0.event == .responseRejected })
            XCTAssertFalse(audit.contains { $0.event == .requestAccepted || $0.event == .signatureVerified })
        }
        try withJob { job, _, _ in
            let decoy = job.snapshot.originalURL.deletingLastPathComponent().appendingPathComponent("decoy")
            try FileManager.default.createDirectory(at: decoy, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            try FileManager.default.createSymbolicLink(at: auditDirectory(for: job), withDestinationURL: decoy)
            let operation = SigningOperation()
            try job.signCAdES(using: auditedWorker(for: job), pin: "synthetic-secret", operation: operation)
            XCTAssertEqual(operation.state, .completed)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: decoy.path).isEmpty)
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
