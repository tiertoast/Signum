#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

/// Each iteration creates a fresh approved batch, provider and private output root.
@MainActor final class TaskCancellationLifecycleTests: XCTestCase {
    private var worker: IsolatedPKCS11Client {
        .init(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
    }
    private func repeated(_ name: String = #function, _ body: () async throws -> Void) async throws {
        let count = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1, count) {
            let before = testRun?.failureCount ?? 0
            try await body()
            print("PHASE3_REPEAT \(name) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-before)")
        }
    }
    private func fixture(blocked: Bool = false, _ body: (BatchSigningCoordinator, BatchApproval, MockModule) async throws -> Void) async throws {
        let root = try FixtureFiles.directory("task-lifecycle")
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: blocked ? 16 : nil, workerEffect: blocked ? 2 : 0, audit: true)
        let certificate = try XCTUnwrap(worker.certificates(provider: mock.path.path, slot: 7).first)
        try CertificateEligibility.requireEligible(certificateDER: certificate.der)
        let files = try (1...3).map { index -> URL in
            let file = root.appendingPathComponent("source-\(index).txt")
            try Data("Synthetic approved \(index)".utf8).write(to: file); return file
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments(files, format: .cades)
        let approval = try await batch.prepareApproval(provider: mock.path.path, slot: 7, certificate: certificate.certificate, der: certificate.der)
        try batch.confirm(approval)
        try await body(batch, approval, mock)
    }
    private func audit(_ mock: MockModule, _ code: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(code) }.count
    }
    /// Explicit checkpoint, not a timed pause. The deadline only bounds a broken fixture.
    private final class Gate: @unchecked Sendable {
        let reached: XCTestExpectation
        private let condition = NSCondition()
        private var open = false
        init(_ reached: XCTestExpectation) { self.reached = reached }
        func enter() throws {
            condition.lock(); reached.fulfill()
            defer { condition.unlock() }
            let deadline = Date().addingTimeInterval(10)
            while !open { guard condition.wait(until: deadline) else { throw SupervisedProcess.Failure.timeout } }
        }
        func release() { condition.lock(); open = true; condition.broadcast(); condition.unlock() }
    }
    func testFixtureSignsApprovedBytesWithoutCancellation() async throws {
        try await repeated {
            try await fixture { batch, plan, mock in
                let worker = worker
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: worker, pin: pin, operation: operation)
                }
                XCTAssertEqual(batch.documents.map(\.state), [.completed, .waitingForAuthorization, .pending])
                XCTAssertEqual(try CAdESVerifier.verify(file: plan.jobs[0].destination).originalDocument, Data("Synthetic approved 1".utf8))
                XCTAssertEqual(audit(mock, 8), 1); XCTAssertEqual(audit(mock, 16), 1)
                batch.cancelPending()
            }
        }
    }
    func testAlreadyCancelledTaskNeverEntersExecution() async throws {
        try await repeated {
            try await fixture { batch, plan, mock in
                let calls = FixtureLocked(0)
                let task = Task { @MainActor in
                    try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in calls.withValue { $0 += 1 }; throw SupervisedProcess.Failure.cancelled }
                }
                task.cancel() // MainActor has not yielded to the task yet.
                _ = try? await task.value
                XCTAssertEqual(calls.withValue { $0 }, 0)
                XCTAssertEqual(batch.documents[0].state, .cancelled)
                XCTAssertEqual(audit(mock, 8), 0); XCTAssertEqual(audit(mock, 16), 0)
                XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
                batch.cancelPending()
            }
        }
    }
    func testCancellationReachesOwnedWorkBeforePrivateRequest() async throws {
        try await repeated {
            try await fixture { batch, _, mock in
                let gate = Gate(expectation(description: "execute entered before private request"))
                defer { gate.release() }
                let observed = FixtureLocked<SigningOperation?>(nil)
                let task = Task { try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, operation in
                    observed.withValue { $0 = operation }; try gate.enter(); try operation.checkCancellation()
                    throw SignumError.module("Fixture reached uncancelled work")
                } }
                await fulfillment(of: [gate.reached], timeout: 5)
                task.cancel()
                XCTAssertTrue(observed.withValue { $0?.isCancellationRequested == true })
                gate.release(); try await task.value
                XCTAssertEqual(batch.documents[0].state, .cancelled)
                XCTAssertEqual(audit(mock, 8), 0); XCTAssertEqual(audit(mock, 16), 0)
                XCTAssertFalse(batch.isRunning); XCTAssertNil(batch.activeOperation); batch.cancelPending()
            }
        }
    }
    func testPrivateReplyCheckpointFixturePublishesWhenNotCancelled() async throws {
        try await privateReply(cancel: false)
    }
    func testCancellationAfterPrivateReplyPreservesUncertaintyWithoutPublication() async throws {
        try await privateReply(cancel: true)
    }
    private func privateReply(cancel: Bool) async throws {
        try await repeated("privateReply(cancel: \(cancel))") {
            try await fixture { batch, plan, mock in
                let gate = Gate(expectation(description: "private signature verified before publication"))
                defer { gate.release() }
                let worker = worker
                let task = Task { try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.executeCAdES(isCancelled: { operation.isCancellationRequested }) { bytes in
                        let prepared = try CAdES.Prepared(document: bytes, certificateDER: job.certificateDER)
                        operation.transition(to: .signing)
                        let signature = try worker.sign(provider: job.providerPath, slot: job.slot, certificate: job.certificate, der: job.certificateDER, attributes: prepared.attributesToSign, pin: pin, id: job.id, isCancelled: { operation.isCancellationRequested })
                        operation.transition(to: .verifying)
                        try gate.enter(); try operation.checkCancellation()
                        return try prepared.finish(signature: signature)
                    }
                    operation.transition(to: .completed)
                } }
                await fulfillment(of: [gate.reached], timeout: 5)
                if cancel { task.cancel() }; gate.release(); try await task.value
                XCTAssertEqual(batch.documents[0].state, cancel ? .uncertain : .completed); XCTAssertEqual(batch.needsOutcomeReview, cancel)
                XCTAssertEqual(audit(mock, 8), 1); XCTAssertEqual(audit(mock, 16), 1)
                XCTAssertEqual(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path), !cancel)
                if !cancel { XCTAssertEqual(try CAdESVerifier.verify(file: plan.jobs[0].destination).originalDocument, Data("Synthetic approved 1".utf8)) }
                batch.cancelPending()
            }
        }
    }
    func testCancellationAfterConfirmedPublicationKeepsOutputAndCompletion() async throws {
        try await repeated {
            try await fixture { batch, plan, mock in
                let gate = Gate(expectation(description: "verified output already published"))
                defer { gate.release() }
                let worker = worker
                let task = Task { try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: worker, pin: pin, operation: operation); try gate.enter()
                } }
                await fulfillment(of: [gate.reached], timeout: 5)
                task.cancel(); gate.release(); try await task.value
                XCTAssertEqual(batch.documents[0].state, .completed); XCTAssertFalse(batch.needsOutcomeReview)
                XCTAssertEqual(try CAdESVerifier.verify(file: plan.jobs[0].destination).originalDocument, Data("Synthetic approved 1".utf8))
                XCTAssertEqual(audit(mock, 16), 1); batch.cancelPending()
            }
        }
    }
    func testExplicitCancellationFixtureTerminatesBlockedWorker() async throws {
        try await blockedWorker(cancelParent: false)
    }
    func testCancellationTerminatesBlockedWorkerAndDoesNotRetry() async throws {
        try await blockedWorker(cancelParent: true)
    }
    private func blockedWorker(cancelParent: Bool) async throws {
        try await repeated("blockedWorker(cancelParent: \(cancelParent))") {
            try await fixture(blocked: true) { batch, plan, mock in
                // The append audit is flushed immediately before the mock blocks in C_Sign.
                let file = mock.folder.appendingPathComponent("operations")
                let descriptor = open(file.path, O_EVTONLY)
                XCTAssertGreaterThanOrEqual(descriptor, 0)
                guard descriptor >= 0 else { return }
                let reached = expectation(description: "worker entered C_Sign")
                let delivered = FixtureLocked(false)
                let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: descriptor, eventMask: .write, queue: .global())
                source.setEventHandler {
                    let lines = (try? String(contentsOf: file)) ?? ""
                    if lines.split(separator: "\n").contains("16"), delivered.withValue({ value in if value { return false }; value = true; return true }) { reached.fulfill() }
                }
                source.setCancelHandler { close(descriptor) }; source.resume()
                defer { source.cancel() }
                let worker = worker
                let task = Task { try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: worker, pin: pin, operation: operation, timeout: 3)
                } }
                await fulfillment(of: [reached], timeout: 5)
                let pid = try XCTUnwrap((try? String(contentsOf: mock.folder.appendingPathComponent("operations.pid"))).flatMap(Int32.init))
                if cancelParent { task.cancel() } else { batch.cancelAll() }
                XCTAssertTrue(batch.activeOperation?.isCancellationRequested == true)
                // Drain baseline red safely; the assertion above precedes this cleanup.
                if batch.activeOperation?.isCancellationRequested != true { batch.cancelAll() }
                try await task.value
                XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH)
                XCTAssertTrue(batch.needsOutcomeReview); XCTAssertEqual(batch.documents[0].state, .uncertain)
                XCTAssertEqual(audit(mock, 16), 1)
                XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
                batch.cancelPending()
            }
        }
    }
    func testAlreadyCancelledContinuationRetiresCapabilityWithoutNextSubmit() async throws {
        try await repeated {
            try await fixture { batch, plan, mock in
                let identity = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false).identity
                let session = try BatchCAdESSession(approval: plan, serial: "SYNTHETIC-0001", moduleIdentity: identity, executable: worker.executable)
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in try session.signCAdES(job: job, pin: pin, operation: operation) }
                XCTAssertTrue(session.canContinue)
                let task = Task { await batch.continueAuthenticatedBatch(using: session) }
                task.cancel(); await task.value; await session.stopAndWait()
                XCTAssertEqual(audit(mock, 16), 1); XCTAssertEqual(audit(mock, 8), 1)
                XCTAssertFalse(session.canContinue); XCTAssertFalse(batch.isContinuingAuthenticated)
                XCTAssertEqual(batch.documents[0].state, .completed)
                XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path)); batch.cancelPending()
            }
        }
    }
}
#endif
