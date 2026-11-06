#if os(macOS)
import XCTest
import SwiftUI
import Security
@testable import SignumApp
@testable import SignumCore

@MainActor final class SessionDocumentRemovalTests: XCTestCase {
    private let verifier: VerificationWorkspace.Verifier = { url, _ in
        .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .unknown,
              signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: Data(url.lastPathComponent.utf8))
    }
    func testVerificationRemovalPreservesOtherReportsAndSelectsNeighbourUntilEmpty() async throws {
        let root = try FixtureFiles.directory("removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let files = try (0..<3).map { i -> URL in
            let url = root.appendingPathComponent("input-\(i).txt")
            try Data("Original \(i)".utf8).write(to: url); return url
        }
        let exported = root.appendingPathComponent("exported.txt")
        try Data("Export preserved".utf8).write(to: exported)
        let workspace = VerificationWorkspace()
        await workspace.verify(files, using: verifier)
        let rows = workspace.rows
        workspace.selectedDocument = rows[1].id
        XCTAssertTrue(workspace.remove(rows[0].id))
        XCTAssertEqual(workspace.selectedDocument, rows[1].id)
        XCTAssertEqual(workspace.rows[1].report?.id, rows[2].report?.id)
        XCTAssertEqual(workspace.rows[1].report?.originalContent, rows[2].report?.originalContent)
        XCTAssertTrue(workspace.remove(rows[1].id))
        XCTAssertEqual(workspace.selectedDocument, rows[2].id)
        XCTAssertTrue(workspace.remove(rows[2].id))
        XCTAssertTrue(workspace.rows.isEmpty); XCTAssertNil(workspace.selectedDocument)
        XCTAssertFalse(workspace.remove(rows[0].id))
        for (i, file) in files.enumerated() { XCTAssertEqual(try Data(contentsOf: file), Data("Original \(i)".utf8)) }
        XCTAssertEqual(try Data(contentsOf: exported), Data("Export preserved".utf8))
        await workspace.verify(files, using: verifier)
        XCTAssertEqual(workspace.selectedDocument, workspace.rows.first?.id)
    }
    func testRemovalDuringVerificationDiscardsLateResultAndContinuesQueue() async throws {
        let workspace = VerificationWorkspace(), entered = expectation(description: "verifier entered")
        let release = DispatchSemaphore(value: 0)
        let task = workspace.start([URL(fileURLWithPath: "/synthetic/input"), URL(fileURLWithPath: "/synthetic/next")]) { url, _ in
            if url.lastPathComponent == "input" { entered.fulfill(); _ = release.wait(timeout: .now() + 3) }
            return .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .unknown, signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: nil)
        }
        await fulfillment(of: [entered], timeout: 2)
        let id = try XCTUnwrap(workspace.rows.first?.id)
        XCTAssertTrue(workspace.remove(id)); XCTAssertEqual(workspace.rows.count, 1)
        release.signal(); await task.value
        XCTAssertEqual(workspace.rows.first?.name, "next")
        XCTAssertTrue(workspace.rows.first?.finished == true)
        XCTAssertFalse(workspace.rows.contains { $0.id == id })
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        let ready = expectation(description: "acquiring"), drop = ControlledDrop(1, ready: ready)
        let acquisition = workspace.acquire(using: { await drop.resolve() }, verifier: verifier)
        await fulfillment(of: [ready], timeout: 2)
        XCTAssertFalse(workspace.remove(UUID())); XCTAssertTrue(workspace.acquiring)
        drop.send(0, "new"); await acquisition.value
        XCTAssertEqual(workspace.rows.count, 1)
    }
    func testDetachedReportRetainsOriginalAssociationWhenAnotherRowIsRemoved() async throws {
        let workspace = VerificationWorkspace()
        let original = Data("detached verified original".utf8)
        await workspace.verify([URL(fileURLWithPath: "/synthetic/first"), URL(fileURLWithPath: "/synthetic/signature.p7s")]) { url, _ in
            .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .cades, signatures: [], documentState: "unsigned", issue: "", previewPDF: nil, originalContent: original)
        }
        let detached = workspace.rows[1]
        workspace.selectedDocument = detached.id
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        XCTAssertEqual(workspace.rows[0].id, detached.id)
        XCTAssertEqual(workspace.rows[0].report?.id, detached.report?.id)
        XCTAssertEqual(workspace.rows[0].report?.originalContent, original)
    }
    func testLastVerificationRemovalCancelsWorkAndLateCompletionCannotClearNewActivity() async throws {
        let workspace = VerificationWorkspace(), verify = verifier
        let entered = expectation(description: "old verification active"), release = DispatchSemaphore(value: 0)
        let control = FixtureLocked<SigningOperation?>(nil)
        defer { release.signal() }
        let old = workspace.start([URL(fileURLWithPath: "/synthetic/old")]) { url, operation in
            control.withValue { $0 = operation }; entered.fulfill()
            XCTAssertEqual(release.wait(timeout: .now() + 5), .success)
            return try verify(url, operation)
        }
        await fulfillment(of: [entered], timeout: 3)
        XCTAssertTrue(workspace.remove(try XCTUnwrap(workspace.rows.first?.id)))
        XCTAssertTrue(old.isCancelled); XCTAssertTrue(control.withValue { $0?.isCancellationRequested == true })
        XCTAssertTrue(workspace.rows.isEmpty); XCTAssertNil(workspace.selectedDocument)
        XCTAssertFalse(workspace.busy); XCTAssertFalse(workspace.acquiring)

        let newEntered = expectation(description: "new verification active"), newRelease = DispatchSemaphore(value: 0)
        defer { newRelease.signal() }
        let next = workspace.start([URL(fileURLWithPath: "/synthetic/new")]) { url, operation in
            newEntered.fulfill()
            XCTAssertEqual(newRelease.wait(timeout: .now() + 5), .success)
            XCTAssertFalse(operation.isCancellationRequested)
            return try verify(url, operation)
        }
        await fulfillment(of: [newEntered], timeout: 3)
        release.signal(); await old.value
        XCTAssertEqual(workspace.rows.map(\.name), ["new"])
        XCTAssertTrue(workspace.busy); XCTAssertNil(workspace.rows[0].report)
        newRelease.signal(); await next.value
        XCTAssertEqual(workspace.rows.map(\.name), ["new"])
        XCTAssertTrue(workspace.rows[0].finished); XCTAssertNotNil(workspace.rows[0].report)
        XCTAssertFalse(workspace.busy)
    }
    func testRemovingMultipleVerificationRowsCancelsOnlyWhenLastQueuedRowIsRemoved() async throws {
        let workspace = VerificationWorkspace(), verify = verifier
        let entered = expectation(description: "verification active"), release = DispatchSemaphore(value: 0)
        let control = FixtureLocked<SigningOperation?>(nil)
        defer { release.signal() }
        let active = workspace.start([URL(fileURLWithPath: "/synthetic/active")]) { url, operation in
            control.withValue { $0 = operation }; entered.fulfill()
            XCTAssertEqual(release.wait(timeout: .now() + 5), .success)
            return try verify(url, operation)
        }
        await fulfillment(of: [entered], timeout: 3)
        let queued = workspace.start([URL(fileURLWithPath: "/synthetic/queued")]) { url, operation in
            XCTFail("Removed queued document was verified")
            return try verify(url, operation)
        }
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        XCTAssertTrue(workspace.busy); XCTAssertFalse(active.isCancelled)
        XCTAssertTrue(control.withValue { $0?.isCancellationRequested == false })
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        XCTAssertTrue(active.isCancelled); XCTAssertTrue(queued.isCancelled)
        XCTAssertTrue(control.withValue { $0?.isCancellationRequested == true })
        XCTAssertFalse(workspace.busy); XCTAssertTrue(workspace.rows.isEmpty)
        release.signal(); await active.value; await queued.value
        XCTAssertTrue(workspace.rows.isEmpty); XCTAssertFalse(workspace.busy)
    }
    func testLastVerificationRemovalPreservesAcquisitionAndRetiresWorkIfItResolvesEmpty() async throws {
        for empty in [false, true] {
            let workspace = VerificationWorkspace(), verify = verifier
            let entered = expectation(description: "verification active"), release = DispatchSemaphore(value: 0)
            let control = FixtureLocked<SigningOperation?>(nil)
            defer { release.signal() }
            let active = workspace.start([URL(fileURLWithPath: "/synthetic/removed")]) { url, operation in
                control.withValue { $0 = operation }; entered.fulfill()
                XCTAssertEqual(release.wait(timeout: .now() + 5), .success)
                return try verify(url, operation)
            }
            await fulfillment(of: [entered], timeout: 3)
            let ready = expectation(description: "acquisition pending"), drop = ControlledDrop(1, ready: ready)
            let resolved = expectation(description: "acquisition resolved")
            let acquisition = workspace.acquire(using: {
                let urls = await drop.resolve(); resolved.fulfill(); return urls
            }, verifier: verify)
            await fulfillment(of: [ready], timeout: 3)
            XCTAssertTrue(workspace.remove(workspace.rows[0].id))
            XCTAssertTrue(workspace.rows.isEmpty); XCTAssertTrue(workspace.busy); XCTAssertTrue(workspace.acquiring)
            XCTAssertFalse(active.isCancelled); XCTAssertFalse(acquisition.isCancelled)
            XCTAssertTrue(control.withValue { $0?.isCancellationRequested == false })
            if empty { drop.fire() } else { drop.send(0, "acquired") }
            await fulfillment(of: [resolved], timeout: 3)
            if empty {
                await acquisition.value
                XCTAssertTrue(active.isCancelled)
                XCTAssertTrue(control.withValue { $0?.isCancellationRequested == true })
                XCTAssertFalse(workspace.busy); XCTAssertFalse(workspace.acquiring)
            } else {
                XCTAssertEqual(workspace.rows.map(\.name), ["acquired"])
                XCTAssertTrue(workspace.busy); XCTAssertFalse(workspace.acquiring)
                XCTAssertFalse(active.isCancelled)
            }
            release.signal(); await active.value; await acquisition.value
            XCTAssertEqual(workspace.rows.map(\.name), empty ? [] : ["acquired"])
            XCTAssertTrue(workspace.rows.allSatisfy { $0.finished && $0.report != nil })
            XCTAssertFalse(workspace.busy); XCTAssertFalse(workspace.acquiring)
        }
    }
    func testSigningRemovalRetiresSnapshotAndRejectsStaleApprovalWithoutDeletingFiles() async throws {
        let root = try FixtureFiles.directory("signing-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        let files = try (0..<3).map { i -> URL in
            let url = root.appendingPathComponent("input-\(i).txt")
            try Data("Original \(i)".utf8).write(to: url); return url
        }
        let output = root.appendingPathComponent("existing-signed.p7m")
        try Data("Keep output".utf8).write(to: output)
        await batch.addDocuments(files, format: .cades)
        let certificate = SignumCertificate(label: "Synthetic", identifier: Data([1]))
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7, certificate: certificate, der: der, destination: .originalFolders)
        let first = batch.documents[0].snapshot
        batch.remove(first.identity.id)
        XCTAssertTrue(first.isRetired); XCTAssertNil(batch.review)
        XCTAssertThrowsError(try batch.freezeReview(plan))
        XCTAssertFalse(batch.isApproved)
        for id in batch.documents.map(\.id) { batch.remove(id) }
        XCTAssertTrue(batch.documents.isEmpty)
        for (i, file) in files.enumerated() { XCTAssertEqual(try Data(contentsOf: file), Data("Original \(i)".utf8)) }
        XCTAssertEqual(try Data(contentsOf: output), Data("Keep output".utf8))
    }
    func testFrozenRemovalRevokesPlanAndRejectsStaleConsent() async throws {
        let root = try FixtureFiles.directory("frozen-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("input.txt"); try Data("input".utf8).write(to: file)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments([file], format: .cades)
        let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: CertificateEligibilityTests.fixtures.get().der("valid"), destination: .originalFolders)
        try batch.freezeReview(plan)
        let id = batch.documents[0].id
        batch.remove(id)
        XCTAssertTrue(batch.documents.isEmpty); XCTAssertFalse(batch.isFrozen)
        XCTAssertFalse(batch.isApproved); XCTAssertNil(batch.review)
        XCTAssertThrowsError(try batch.confirm(plan))
    }
    func testCompletedAndPendingVerificationRemovalLeavesUnrelatedActiveWork() async throws {
        let workspace = VerificationWorkspace(), entered = expectation(description: "second active")
        let release = DispatchSemaphore(value: 0)
        let task = workspace.start(["completed", "active", "pending"].map { URL(fileURLWithPath: "/synthetic/" + $0) }) { url, control in
            if url.lastPathComponent == "active" { entered.fulfill(); _ = release.wait(timeout: .now() + 5); XCTAssertFalse(control.isCancellationRequested) }
            if url.lastPathComponent == "pending" { XCTFail("Removed pending row was verified") }
            return .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .unknown,
                signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: nil)
        }
        await fulfillment(of: [entered], timeout: 3)
        XCTAssertTrue(workspace.rows[0].finished)
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        XCTAssertTrue(workspace.remove(workspace.rows[1].id))
        release.signal(); await task.value
        XCTAssertEqual(workspace.rows.count, 1); XCTAssertEqual(workspace.rows[0].name, "active")
        XCTAssertTrue(workspace.rows[0].finished)
    }
    func testPendingSigningRemovalRevokesFutureJobsButActiveJobCompletes() async throws {
        let root = try FixtureFiles.directory("active-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        let files = try (0..<3).map { i -> URL in
            let file = root.appendingPathComponent("input-\(i)"); try Data("input \(i)".utf8).write(to: file); return file
        }
        await batch.addDocuments(files, format: .cades)
        let certificate = SignumCertificate(label: "Synthetic", identifier: Data([1])), der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let plan = try await batch.prepareApproval(provider: "/synthetic", slot: 7, certificate: certificate, der: der)
        try batch.confirm(plan)
        let entered = expectation(description: "active"), release = DispatchSemaphore(value: 0)
        let task = Task { try await batch.authorizeNext(pin: "synthetic") { job, _, control in
            control.transition(to: .signing); entered.fulfill(); _ = release.wait(timeout: .now() + 5)
            XCTAssertFalse(control.isCancellationRequested)
            try Data("published".utf8).write(to: job.destination)
            control.transition(to: .verifying); control.transition(to: .completed)
        } }
        await fulfillment(of: [entered], timeout: 3)
        let removed = batch.documents[1].snapshot, remaining = batch.documents[2].id
        batch.remove(removed.identity.id)
        XCTAssertTrue(removed.isRetired); XCTAssertFalse(batch.isApproved); XCTAssertTrue(batch.isRunning)
        release.signal(); try await task.value
        XCTAssertEqual(batch.documents[0].state, .completed); XCTAssertEqual(batch.nextDocument?.id, remaining)
        XCTAssertFalse(batch.isFrozen)
        do { try await batch.authorizeNext(pin: "synthetic") { _, _, _ in XCTFail("Revoked approval executed") }; XCTFail("Revoked consent accepted") } catch {}
        let renewed = try await batch.prepareReview(provider: "/synthetic", slot: 7, certificate: certificate, der: der, destination: .originalFolders)
        XCTAssertEqual(renewed.jobs.map(\.snapshotIdentity.id), [remaining])
        XCTAssertThrowsError(try batch.freezeReview(plan))
        try batch.freezeReview(renewed); try batch.confirm(renewed)
    }
    func testActiveSigningRemovalKeepsUncertainOutcomeVisibleWithoutRetry() async throws {
        let root = try FixtureFiles.directory("uncertain-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("input"); try Data("input".utf8).write(to: file)
        let batch = BatchSigningCoordinator(); await batch.addDocuments([file], format: .cades)
        let plan = try await batch.prepareApproval(provider: "/synthetic", slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: CertificateEligibilityTests.fixtures.get().der("valid"))
        try batch.confirm(plan)
        let id = batch.documents[0].id, entered = expectation(description: "private operation"), release = DispatchSemaphore(value: 0)
        let task = Task { try await batch.authorizeNext(pin: "synthetic") { _, _, control in
            control.transition(to: .signing); entered.fulfill(); _ = release.wait(timeout: .now() + 5)
            XCTAssertTrue(control.isCancellationRequested); throw SupervisedProcess.Failure.cancelled
        } }
        await fulfillment(of: [entered], timeout: 3)
        batch.remove(id); XCTAssertEqual(batch.documents.count, 1)
        release.signal(); try await task.value
        XCTAssertEqual(batch.documents[0].state, .uncertain); XCTAssertTrue(batch.needsOutcomeReview)
        XCTAssertFalse(batch.canRemove(id)); XCTAssertFalse(batch.isApproved)
        XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path))
        batch.acknowledgeUncertainOutcome(); batch.reset()
    }

    func testSelectiveRemovalRetiresAuthenticatedCapabilityAfterCurrentPublication() async throws {
        for failCleanup in [false, true] {
            let root = try FixtureFiles.directory("removal-authenticated")
            defer { try? FileManager.default.removeItem(at: root) }
            let signer = try SoftwareSigner(folder: root)
            let key = try XCTUnwrap(SecKeyCreateWithData(try signer.rsaPrivateDER() as CFData,
                [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil))
            let connection = BatchCleanupContractTests.Connection(key: key, failCleanup: failCleanup)
            let module = root.appendingPathComponent("synthetic-module"); try Data("Synthetic module identity".utf8).write(to: module)
            let inspected = try MiddlewareFileSecurity.inspect(module.path, automatic: false)
            let files = try (0..<3).map { i -> URL in
                let file = root.appendingPathComponent("input-\(i)"); try Data("input \(i)".utf8).write(to: file); return file
            }
            let batch = BatchSigningCoordinator(); defer { batch.reset() }
            await batch.addDocuments(files, format: .cades)
            let plan = try await batch.prepareApproval(provider: inspected.canonicalPath, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
            try batch.confirm(plan)
            let session = try BatchCAdESSession(approval: plan, serial: "SYNTHETIC", moduleIdentity: inspected.identity)
            session.makeConnection = { _, _ in connection }
            let entered = expectation(description: "authenticated signature"), release = DispatchSemaphore(value: 0)
            connection.beforeReturn = { entered.fulfill(); _ = release.wait(timeout: .now() + 5) }
            let work = Task { try await batch.authorizeNext(pin: "synthetic") { job, pin, operation in
                try session.signCAdES(job: job, pin: pin, operation: operation)
            } }
            await fulfillment(of: [entered], timeout: 3)
            batch.remove(batch.documents[1].id)
            XCTAssertThrowsError(try batch.confirm(plan))
            release.signal(); try await work.value
            XCTAssertEqual(batch.documents[0].state, .completed)
            XCTAssertEqual(try CAdESVerifier.verify(file: plan.jobs[0].destination).originalDocument, Data("input 0".utf8))
            await batch.continueAuthenticatedBatch(using: session)
            XCTAssertEqual(connection.next, 1); XCTAssertEqual(connection.finishCalls, 1)
            XCTAssertFalse(session.canContinue); XCTAssertFalse(batch.isApproved)
            XCTAssertEqual(batch.needsOutcomeReview, failCleanup)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[2].destination.path))
        }
    }
    func testActiveRemovalBeforePrivateOperationDrainsThenRetiresRow() async throws {
        let root = try FixtureFiles.directory("removal-before-private")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("input"); try Data("input".utf8).write(to: source)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments([source], format: .cades)
        let plan = try await batch.prepareApproval(provider: "/synthetic", slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: CertificateEligibilityTests.fixtures.get().der("valid"))
        try batch.confirm(plan)
        let snapshot = batch.documents[0].snapshot, entered = expectation(description: "preparing"), release = DispatchSemaphore(value: 0)
        let work = Task { try await batch.authorizeNext(pin: "synthetic") { _, _, operation in
            entered.fulfill(); _ = release.wait(timeout: .now() + 5)
            XCTAssertFalse(operation.hasRequestedPrivateOperation)
            try operation.checkCancellation()
        } }
        await fulfillment(of: [entered], timeout: 3)
        batch.remove(snapshot.identity.id)
        XCTAssertFalse(snapshot.isRetired); XCTAssertEqual(batch.documents.count, 1)
        XCTAssertThrowsError(try batch.confirm(plan))
        release.signal(); try await work.value
        XCTAssertTrue(batch.documents.isEmpty); XCTAssertTrue(snapshot.isRetired)
        XCTAssertFalse(batch.needsOutcomeReview); XCTAssertFalse(batch.isFrozen)
        XCTAssertEqual(try Data(contentsOf: source), Data("input".utf8))
    }

}
#endif
