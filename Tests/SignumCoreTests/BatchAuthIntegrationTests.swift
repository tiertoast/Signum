#if os(macOS)
import XCTest
@testable import SignumCore

@MainActor final class BatchAuthIntegrationTests: XCTestCase {
    private var worker: URL { ProcessInfo.processInfo.environment["SIGNUM_TEST_BATCH_WORKER"].map { URL(fileURLWithPath: $0) } ?? Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    private func count(_ mock: MockModule, _ op: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(op) }.count
    }
    private func fixture(always: Bool = false, phase: Int? = nil, effect: Int = 0, after: Int = 0, temporary: Bool = false, documents: Int = 3, includeSigningTime: Bool = true,
        _ body: (URL, MockModule, BatchSigningCoordinator, BatchApproval, BatchCAdESSession) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase,
            workerEffect: effect, audit: true, alwaysAuth: always, faultAfter: after, strictContext: temporary)
        let files = try (1...documents).map { index -> URL in
            let file = root.appendingPathComponent("synthetic-\(index).txt"); try Data("Approved batch \(index)".utf8).write(to: file); return file
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments(files, format: .cades)
        let plan = try await batch.prepareApproval(provider: mock.path.path, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der, includeSigningTime: includeSigningTime)
        try batch.confirm(plan)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let session = try BatchCAdESSession(approval: plan, serial: "SYNTHETIC-0001", moduleIdentity: inspected.identity, temporaryPIN: temporary, executable: worker)
        do { try await body(root, mock, batch, plan, session) }
        catch { await session.stopAndWait(); throw error }
        await session.stopAndWait()
    }
    private func first(_ batch: BatchSigningCoordinator, _ session: BatchCAdESSession, timeout: TimeInterval = 120) async throws {
        try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
            try session.signCAdES(job: job, pin: pin, operation: operation, timeout: timeout)
        }
    }
    func testThreeCAdESWithOnePINVerifyBeforePublicationAndKeepApprovedBytes() async throws {
        try await fixture { root, mock, batch, plan, session in
            for job in plan.jobs { try Data("Changed original after approval".utf8).write(to: job.snapshot.originalURL) }
            try await first(batch, session); XCTAssertTrue(session.canContinue)
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .completed, .completed])
            for (index, job) in plan.jobs.enumerated() {
                XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved batch \(index+1)".utf8))
            }
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 3); XCTAssertEqual(count(mock, 1), 1)
            XCTAssertFalse(session.canContinue); XCTAssertFalse(batch.isContinuingAuthenticated)
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.hasPrefix(".signum-staging-") })
        }
    }
    func testSigningTimeToggleSurvivesBatchDelayWithoutChangingApprovedAttributes() async throws {
        for include in [true, false] {
            try await fixture(documents: 2, includeSigningTime: include) { _, _, batch, plan, session in
                XCTAssertTrue(plan.jobs.allSatisfy { $0.includeSigningTime == include })
                try await first(batch, session)
                try await Task.sleep(nanoseconds: 1_100_000_000)
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertEqual(batch.documents.map(\.state), [.completed, .completed])
                let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
                for job in plan.jobs {
                    let result = try SignumVerificationService.verify(file: job.destination, helper: URL(fileURLWithPath: helper))
                    XCTAssertEqual(result.integrity, .verified)
                    XCTAssertEqual(result.signatures.first?.declaredTime.isEmpty, !include)
                    XCTAssertTrue(result.signatures.first?.evidence?.timestampTokens.isEmpty == true)
                }
            }
        }
    }
    func testAlwaysAuthenticateRequiresThreeExplicitPINsAndContextLogins() async throws {
        try await fixture(always: true) { _, mock, batch, _, session in
            try await first(batch, session); XCTAssertFalse(session.canContinue)
            let worker = worker
            for _ in 0..<2 {
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
                }
            }
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .completed, .completed])
            XCTAssertEqual(count(mock, 8), 3); XCTAssertEqual(count(mock, 9), 3); XCTAssertEqual(count(mock, 16), 3)
        }
    }
    func testCancelledQueuedDocumentIsSkippedWithoutSigningIt() async throws {
        try await fixture { _, mock, batch, _, session in
            try await first(batch, session)
            batch.cancelDocument(batch.documents[1].id)
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .cancelled, .completed])
            XCTAssertEqual(count(mock, 16), 2); XCTAssertEqual(count(mock, 8), 1)
        }
    }
    func testCancelAllAfterFirstClosesSessionAndCannotSignMore() async throws {
        try await fixture { _, mock, batch, _, session in
            try await first(batch, session); batch.cancelAll()
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .cancelled, .cancelled])
            XCTAssertEqual(count(mock, 16), 1); XCTAssertFalse(session.canContinue); XCTAssertEqual(count(mock, 1), 1)
        }
    }
    func testCollisionOnSecondStopsWithoutSigningSecondOrThird() async throws {
        try await fixture { _, mock, batch, plan, session in
            try await first(batch, session)
            try Data("PRESERVE".utf8).write(to: plan.jobs[1].destination)
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .failed, .waitingForAuthorization])
            XCTAssertEqual(count(mock, 16), 1)
            XCTAssertEqual(try String(contentsOf: plan.jobs[1].destination), "PRESERVE")
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[2].destination.path))
        }
    }
    func testSecondSignatureFailureIsUncertainAndNeverRetried() async throws {
        try await fixture(phase: 16, effect: 4, after: 1) { _, mock, batch, plan, session in
            try await first(batch, session); await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .uncertain, .waitingForAuthorization])
            XCTAssertTrue(batch.needsOutcomeReview); XCTAssertEqual(count(mock, 16), 2)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(count(mock, 16), 2)
        }
    }
    func testTimeoutAndCrashNeverPublishOrRetry() async throws {
        for effect in [2, 3] {
            try await fixture(phase: 16, effect: effect) { _, mock, batch, plan, session in
                try await first(batch, session, timeout: 0.2)
                XCTAssertEqual(batch.documents[0].state, .uncertain)
                XCTAssertTrue(batch.needsOutcomeReview); XCTAssertEqual(count(mock, 16), 1)
                XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertEqual(count(mock, 16), 1)
            }
        }
    }
    func testCorruptSnapshotCannotUseAuthenticatedSession() async throws {
        try await fixture { _, mock, batch, plan, session in
            try await first(batch, session)
            let snapshot = plan.jobs[1].snapshot
            XCTAssertEqual(chmod(snapshot.fileURL.path, 0o600), 0)
            try Data("corruption".utf8).write(to: snapshot.fileURL)
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents[1].state, .failed); XCTAssertEqual(count(mock, 16), 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
        }
    }
    func testCancellationDuringPrivateOperationStopsWorkerAndDoesNotAdvance() async throws {
        try await fixture(phase: 16, effect: 2) { _, mock, batch, plan, session in
            let task = Task { try await first(batch, session) }
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while count(mock, 16) == 0 && ProcessInfo.processInfo.systemUptime < deadline { await Task.yield() }
            XCTAssertEqual(count(mock, 16), 1) // Audit is the barrier before the mock blocks in Sign.
            batch.cancelAll(); session.requestStop()
            try await task.value
            await session.stopAndWait()
            XCTAssertTrue(batch.needsOutcomeReview)
            XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 8), 1)
            XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
        }
    }
    func testUnconfirmedTeardownRemainsVisibleAndBlocksFurtherAuthentication() async throws {
        try await fixture(phase: 1, effect: 2) { _, mock, batch, _, session in
            try await first(batch, session)
            batch.cancelPending()
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertTrue(session.cleanupUncertain); XCTAssertTrue(batch.needsOutcomeReview)
            XCTAssertFalse(batch.authenticationNotice.isEmpty); XCTAssertFalse(batch.isContinuingAuthenticated)
            XCTAssertEqual(count(mock, 16), 1)
        }
    }

    func testTemporaryPINThreeAndSevenCAdESHaveDistinctContextLoginsAndVerifiedOutputs() async throws {
        for documents in [3, 7] {
            try await fixture(always: true, temporary: true, documents: documents) { root, mock, batch, plan, session in
                try await first(batch, session)
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertTrue(batch.documents.allSatisfy { $0.state == .completed })
                for (index, job) in plan.jobs.enumerated() {
                    XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, Data("Approved batch \(index+1)".utf8))
                }
                XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), documents)
                XCTAssertEqual(count(mock, 16), documents); XCTAssertEqual(count(mock, 1), 1)
                XCTAssertFalse(session.canContinue)
                XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.hasPrefix(".signum-staging-") })
            }
        }
    }
    func testTemporarySecondFailureAndCollisionDoNotAdvanceOrOverwrite() async throws {
        for collision in [false, true] {
            try await fixture(always: true, phase: collision ? nil : 9, effect: 4, after: 1, temporary: true) { _, mock, batch, plan, session in
                try await first(batch, session)
                if collision { try Data("PRESERVE".utf8).write(to: plan.jobs[1].destination) }
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertEqual(batch.documents.map(\.state), [.completed, collision ? .failed : .uncertain, .waitingForAuthorization])
                XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 9), collision ? 1 : 2)
                XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[2].destination.path))
                if collision { XCTAssertEqual(try String(contentsOf: plan.jobs[1].destination), "PRESERVE") }
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertEqual(count(mock, 16), 1)
            }
        }
    }
    func testTemporaryCancellationDuringSignNeverContinuesOrPublishes() async throws {
        try await fixture(always: true, phase: 16, effect: 2, temporary: true) { _, mock, batch, plan, session in
            let task = Task { try await first(batch, session) }
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while count(mock, 16) == 0 && ProcessInfo.processInfo.systemUptime < deadline { await Task.yield() }
            XCTAssertEqual(count(mock, 16), 1)
            batch.cancelAll(); session.requestStop(); try await task.value; await session.stopAndWait()
            XCTAssertTrue(batch.needsOutcomeReview); XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 9), 1)
            XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
        }
    }
    func testTemporaryCrashAndTimeoutNeverRetryOrPublish() async throws {
        for effect in [2, 3] {
            try await fixture(always: true, phase: 16, effect: effect, temporary: true) { _, mock, batch, plan, session in
                try await first(batch, session, timeout: 0.2)
                XCTAssertEqual(batch.documents[0].state, .uncertain)
                await batch.continueAuthenticatedBatch(using: session)
                XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 9), 1)
                XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath: $0.destination.path) })
            }
        }
    }

}
#endif
