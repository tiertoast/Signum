#if os(macOS)
import XCTest
import Security
@testable import SignumCore

@MainActor final class BatchCleanupContractTests: XCTestCase {
    enum Fault: Error { case cleanup }
    final class Connection: BatchSigningConnection {
        var next = 0, finishCalls = 0, abortCalls = 0
        var reusable = true
        let key: SecKey
        var beforeReturn: (() throws -> Void)?
        var failCleanup: Bool
        init(key: SecKey, failCleanup: Bool) { self.key = key; self.failCleanup = failCleanup }
        func sign(jobID: UUID, attributes: Data, pin: String?, timeout: TimeInterval, isCancelled: () -> Bool) throws -> Data {
            next += 1
            try beforeReturn?()
            return try XCTUnwrap(SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, attributes as CFData, nil)) as Data
        }
        func skip(isCancelled: () -> Bool) throws { next += 1 }
        func finish() throws { finishCalls += 1; if failCleanup { throw Fault.cleanup }; reusable = false }
        func abort() { abortCalls += 1; reusable = false }
    }
    func testLocalFailureAndCleanupOutcomeSurviveRetirementAndReachCoordinator() async throws {
        for failCleanup in [false, true] {
            let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: root) }
            let signer = try SoftwareSigner(folder: root)
            let key = try XCTUnwrap(SecKeyCreateWithData(try signer.rsaPrivateDER() as CFData,
                [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil))
            let connection = Connection(key: key, failCleanup: failCleanup)
            let module = root.appendingPathComponent("synthetic-module"); try Data("Not executable".utf8).write(to: module)
            let modulePath = try MiddlewareFileSecurity.inspect(module.path, automatic: false).canonicalPath
            let files = try (0..<3).map { index -> URL in
                let file = root.appendingPathComponent("synthetic-\(index).txt")
                try Data("Approved synthetic \(index)".utf8).write(to: file); return file
            }
            let batch = BatchSigningCoordinator(); defer { batch.reset() }
            await batch.addDocuments(files, format: .cades)
            let plan = try await batch.prepareApproval(provider: modulePath, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
            try batch.confirm(plan)
            let session = try BatchCAdESSession(approval: plan, serial: "SYNTHETIC", moduleIdentity: MiddlewareFileSecurity.inspect(module.path, automatic: false).identity)
            session.makeConnection = { _, _ in connection }
            try await batch.authorizeNext(pin: "synthetic") { job, pin, operation in
                try session.signCAdES(job: job, pin: pin, operation: operation)
            }
            XCTAssertEqual(batch.documents[0].state, .completed, batch.documents[0].result)
            XCTAssertFalse(session.cleanupUncertain)
            try FileManager.default.removeItem(at: module) // Local inspection fails before second submit.
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .failed, .waitingForAuthorization])
            XCTAssertEqual(connection.next, 1)
            XCTAssertEqual(connection.finishCalls, 1); XCTAssertEqual(connection.abortCalls, 1)
            XCTAssertEqual(session.cleanupUncertain, failCleanup)
            XCTAssertEqual(batch.needsOutcomeReview, failCleanup)
            XCTAssertEqual(batch.authenticationNotice.isEmpty, !failCleanup)
            await session.stopAndWait(); await session.stopAndWait()
            XCTAssertEqual(session.cleanupUncertain, failCleanup)
            XCTAssertEqual(connection.finishCalls, 1)
            XCTAssertFalse(session.canContinue)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
        }
    }
    func testFirstDocumentLocalPublicationFailureStillReportsSessionOutcomeBeforeNextAuthorization() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let key = try XCTUnwrap(SecKeyCreateWithData(try signer.rsaPrivateDER() as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil))
        let connection = Connection(key: key, failCleanup: true)
        let module = root.appendingPathComponent("synthetic-module"); try Data("Not executable".utf8).write(to: module)
        let inspected = try MiddlewareFileSecurity.inspect(module.path, automatic: false)
        let files = try (0..<2).map { index -> URL in
            let file = root.appendingPathComponent("synthetic-\(index).txt"); try Data("Synthetic \(index)".utf8).write(to: file); return file
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }; await batch.addDocuments(files, format: .cades)
        let plan = try await batch.prepareApproval(provider: inspected.canonicalPath, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
        try batch.confirm(plan)
        connection.beforeReturn = { try Data("Preserve synthetic collision".utf8).write(to: plan.jobs[0].destination) }
        let session = try BatchCAdESSession(approval: plan, serial: "SYNTHETIC", moduleIdentity: inspected.identity)
        session.makeConnection = { _, _ in connection }
        try await batch.authorizeNext(pin: "synthetic") { job, pin, operation in
            try session.signCAdES(job: job, pin: pin, operation: operation)
        }
        XCTAssertEqual(batch.documents[0].state, .failed)
        XCTAssertTrue(session.cleanupUncertain); XCTAssertFalse(session.canContinue)
        let retirement = batch.retireAuthenticatedSession(using: session)
        XCTAssertTrue(batch.isContinuingAuthenticated) // Revocation/authorization gate is synchronous.
        await retirement.value
        XCTAssertTrue(batch.needsOutcomeReview); XCTAssertFalse(batch.authenticationNotice.isEmpty)
        XCTAssertFalse(batch.isContinuingAuthenticated)
        XCTAssertEqual(connection.next, 1); XCTAssertEqual(connection.finishCalls, 1)
        XCTAssertEqual(try String(contentsOf: plan.jobs[0].destination), "Preserve synthetic collision")
        XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
    }

}
#endif
