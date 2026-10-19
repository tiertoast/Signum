#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class SigningReviewTests: XCTestCase {
    private func fixture(_ body: (URL, BatchSigningCoordinator, SigningReviewContext) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("synthetic.txt"); try Data("review bytes".utf8).write(to: file)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments([file], format: .cades)
        let context = SigningReviewContext(revision: batch.revision, provider: "/synthetic/provider.dylib", slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: try CertificateEligibilityTests.fixtures.get().der("valid"),
            destination: .originalFolders, routeID: "synthetic-route", discoveryID: UUID())
        try await body(root, batch, context)
    }
    func testNewContextCancelsAnOwnedPublicSubprocessInsteadOfWaitingItsDeadline() async throws {
        try await fixture { root,batch,context in
            let engine = root.appendingPathComponent("slow-public")
            try Data("#!/bin/sh\nexec /bin/sleep 4\n".utf8).write(to:engine)
            XCTAssertEqual(chmod(engine.path,0o700),0)
            let entered = expectation(description:"public work entered"), advanced = expectation(description:"new context advanced")
            let review = SigningReview()
            let old = Task { await review.prepare(context,batch:batch,validate:{
                entered.fulfill()
                var bytes = Data()
                _ = try SupervisedProcess.run(executable:engine,input:&bytes,timeout:3,isCancelled:{Task.isCancelled})
            }) }
            await fulfillment(of:[entered],timeout:2)
            let newest = Task { await review.prepare(context,batch:batch,validate:{advanced.fulfill()}) }
            await fulfillment(of:[advanced],timeout:1)
            await old.value; await newest.value
            XCTAssertNotNil(review.approval);XCTAssertFalse(review.isPreparing)
        }
    }
    func testRapidContextsCoalesceAndCloseCancelsWithoutPublishingOldApproval() async throws {
        try await fixture { _,batch,context in
            let review = SigningReview(), entered = expectation(description:"first entered"), release = DispatchSemaphore(value:0)
            let first = Task { await review.prepare(context,batch:batch,validateCancellable:{ control in
                entered.fulfill()
                let deadline = ProcessInfo.processInfo.systemUptime+3
                while !control.isCancellationRequested, ProcessInfo.processInfo.systemUptime < deadline {
                    guard release.wait(timeout:.now()+0.01) == .timedOut else { return }
                }
                throw SupervisedProcess.Failure.cancelled
            }) }
            await fulfillment(of:[entered],timeout:2)
            let second = Task { await review.prepare(context,batch:batch,validate:{XCTFail("Intermediate request must coalesce")}) }
            let third = Task { await review.prepare(context,batch:batch,validate:{}) }
            await first.value;await second.value;await third.value
            XCTAssertEqual(review.preflightsStarted,2);XCTAssertNotNil(review.approval)
            review.cancel();XCTAssertNil(review.approval);XCTAssertNil(review.context);XCTAssertFalse(review.isPreparing)
        }
    }
    func testCancellationReachesSupervisedPublicScanAndDERAndPreservesAvailabilityMeaning() async throws {
        try await fixture { _,_,_ in
            let der = try CertificateEligibilityTests.fixtures.get().der("valid")
            let worker = Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
            for phase in [2,14] {
                let mock = try MockModule(certificate:der,workerPhase:phase,workerEffect:2,audit:true)
                let inspection = try MiddlewareFileSecurity.inspect(mock.path.path,automatic:false)
                // Build the observed route from the fixture's real public scan;
                // phase 12 only blocks DER, so discovery metadata stays truthful.
                let scanMock = try MockModule(certificate:der)
                let client = IsolatedPKCS11Client(executable:worker)
                let observed = try client.scan(provider:scanMock.path.path).tokens[0]
                let definition = MiddlewareDefinition(id:"synthetic",name:"Synthetic",manufacturer:"Tests",candidatePaths:[mock.path.path])
                let provider = DiscoveredMiddleware(id:"synthetic",definition:definition,origin:.manual,candidatePath:mock.path.path,inspection:inspection,status:.ready,
                    tokens:[.init(token:observed,certificates:[.init(certificate:.init(label:"Synthetic",identifier:Data([1])),der:der)],certificateState:.readable)],version:nil,unavailableSlots:0)
                let route = try XCTUnwrap(DeviceCertificate.collect([provider]).first?.routes.first)
                let operation = SigningOperation(), entered = expectation(description:"blocked public operation \(phase)")
                let work = Task.detached { Result { try route.requireCurrentCredential(client:client,isCancelled:{operation.isCancellationRequested}) } }
                let deadline = ProcessInfo.processInfo.systemUptime+3
                while ProcessInfo.processInfo.systemUptime < deadline {
                    let audit = (try? String(contentsOf:mock.folder.appendingPathComponent("operations"))) ?? ""
                    if audit.split(separator:"\n").contains(String(phase)[...]) { entered.fulfill(); break }
                    try await Task.sleep(nanoseconds:1_000_000)
                }
                await fulfillment(of:[entered],timeout:0.1)
                operation.requestCancellation()
                let result = await work.value
                if case .failure(let error) = result { XCTAssertEqual(error as? SupervisedProcess.Failure,.cancelled) }
                else { XCTFail("Blocked public operation must cancel") }
                let audit = try String(contentsOf:mock.folder.appendingPathComponent("operations"))
                XCTAssertFalse(audit.split(separator:"\n").contains("8"));XCTAssertFalse(audit.split(separator:"\n").contains("16"))
            }
        }
    }
    func testPrincipalClickApprovesDisplayedPlanWithoutModalOrPrivateOperation() async throws {
        try await fixture { root, batch, context in
            let review = SigningReview(), interaction = SigningInteraction()
            XCTAssertFalse(interaction.canSubmitPIN("synthetic", batch: batch))
            await review.prepare(context, batch: batch, validate: {})
            let plan = try XCTUnwrap(review.approval)
            XCTAssertTrue(review.matches(context, batch: batch)); XCTAssertFalse(batch.isFrozen); XCTAssertFalse(batch.isApproved)
            XCTAssertEqual(plan.jobs[0].destination.lastPathComponent, "synthetic.txt.p7m")
            XCTAssertTrue(plan.technicalDetails.contains(plan.jobs[0].contentSHA256))
            XCTAssertTrue(try interaction.approveDisplayed(batch: batch, approval: plan, additionalConfirmation: false,
                isCurrent: { review.matches(context, batch: batch) }, present: { _ in XCTFail("Default must not show a second confirmation"); return false }))
            XCTAssertTrue(batch.isFrozen); XCTAssertTrue(batch.isApproved)
            XCTAssertEqual(batch.approval?.id, plan.id); XCTAssertEqual(batch.documents[0].destination, plan.jobs[0].destination)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path))
            await batch.addDocuments([root.appendingPathComponent("extra")], format: .cades)
            XCTAssertEqual(batch.documents.count, 1)
        }
    }
    func testOptionalConfirmationCanDeclineAndPreferencePersistsWithoutChangingApprovedJobs() async throws {
        let name = UUID().uuidString, defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let preferences = SigningExperiencePreferences(defaults: defaults)
        XCTAssertFalse(preferences.additionalConfirmation)
        preferences.additionalConfirmation = true
        XCTAssertTrue(SigningExperiencePreferences(defaults: defaults).additionalConfirmation)
        try await fixture { _, batch, context in
            let review = SigningReview(), interaction = SigningInteraction()
            await review.prepare(context, batch: batch, validate: {})
            let plan = try XCTUnwrap(review.approval); var shown = 0
            XCTAssertFalse(try interaction.approveDisplayed(batch: batch, approval: plan, additionalConfirmation: true,
                isCurrent: { true }, present: { _ in shown += 1; return false }))
            XCTAssertEqual(shown, 1); XCTAssertFalse(batch.isApproved); XCTAssertFalse(batch.isFrozen)
            XCTAssertTrue(try interaction.approveDisplayed(batch: batch, approval: plan, additionalConfirmation: true,
                isCurrent: { true }, present: { _ in shown += 1; return true }))
            preferences.additionalConfirmation = false
            XCTAssertTrue(batch.isApproved); XCTAssertEqual(batch.approval?.id, plan.id)
        }
    }
    func testChangedProviderCertificateDestinationDiscoveryOrRevisionCannotApproveOldSummary() async throws {
        try await fixture { _, batch, original in
            let review = SigningReview(), interaction = SigningInteraction()
            await review.prepare(original, batch: batch, validate: {})
            let plan = try XCTUnwrap(review.approval)
            for index in 0..<7 {
                let changed = SigningReviewContext(revision: index == 0 ? UUID() : original.revision,
                    provider: index == 1 ? "/other/provider" : original.provider, slot: index == 2 ? 8 : original.slot,
                    certificate: index == 3 ? .init(label: "replacement", identifier: Data([2])) : original.certificate,
                    der: index == 4 ? Data([0]) : original.der,
                    destination: index == 5 ? .commonDirectory(URL(fileURLWithPath: "/other")) : original.destination,
                    routeID: original.routeID, discoveryID: index == 6 ? UUID() : original.discoveryID)
                XCTAssertFalse(review.matches(changed, batch: batch))
                XCTAssertThrowsError(try interaction.approveDisplayed(batch: batch, approval: plan, additionalConfirmation: false,
                    isCurrent: { review.matches(changed, batch: batch) }, present: { _ in XCTFail("Stale summary"); return true }))
                XCTAssertFalse(batch.isApproved); XCTAssertFalse(batch.isFrozen)
            }
        }
    }
    func testDocumentRemovedOrAddedInvalidatesReviewAndLatePreparationIsDiscarded() async throws {
        try await fixture { _, batch, context in
            let review = SigningReview(), entered = expectation(description: "validation entered"), release = DispatchSemaphore(value: 0)
            let task = Task { await review.prepare(context, batch: batch, validate: { entered.fulfill(); _ = release.wait(timeout:.now()+5) }) }
            await fulfillment(of: [entered], timeout: 5)
            XCTAssertTrue(review.isPreparing); XCTAssertNil(review.approval)
            batch.remove(batch.documents[0].id)
            release.signal(); await task.value
            XCTAssertNil(review.approval); XCTAssertNil(batch.review); XCTAssertFalse(batch.isApproved)
            XCTAssertFalse(review.matches(context, batch: batch))
        }
    }
    func testSelectionChangedInsideOptionalModalCannotBeApproved() async throws {
        try await fixture { _, batch, context in
            let review = SigningReview(), interaction = SigningInteraction()
            await review.prepare(context, batch: batch, validate: {})
            var current = true
            XCTAssertThrowsError(try interaction.approveDisplayed(batch: batch, approval: XCTUnwrap(review.approval), additionalConfirmation: true,
                isCurrent: { current }, present: { _ in current = false; return true }))
            XCTAssertFalse(batch.isApproved); XCTAssertFalse(batch.isFrozen); XCTAssertNil(batch.approval)
        }
    }
    func testQueuedAcquisitionInvalidatesConsentBeforeItsTaskCanStart() async throws {
        try await fixture { root, batch, context in
            let review = SigningReview()
            await review.prepare(context, batch: batch, validate: {})
            let old = try XCTUnwrap(review.approval)
            let file = root.appendingPathComponent("queued.txt"); try Data("queued synthetic document".utf8).write(to: file)
            let acquisition = try XCTUnwrap(batch.enqueueDocuments([file], format: .cades))
            XCTAssertTrue(batch.isPreparing) // No await: reservation is already visible.
            XCTAssertNil(batch.review); XCTAssertFalse(review.matches(context, batch: batch))
            XCTAssertThrowsError(try batch.freezeReview(old))
            XCTAssertNil(batch.enqueueDocuments([file], format: .pades))
            batch.cancelAll() // Cancel before the queued task can start.
            await acquisition.value
            XCTAssertFalse(batch.isPreparing); XCTAssertFalse(batch.isApproved)
            XCTAssertEqual(batch.documents.count, 1)
            XCTAssertFalse(batch.documents.contains { $0.snapshot.originalURL.lastPathComponent == "queued.txt" })
        }
    }
    func testPreflightCollisionNameIsVisibleBeforeClickAndLateCollisionDoesNotRename() async throws {
        try await fixture { root, batch, context in
            let existing = root.appendingPathComponent("synthetic.txt.p7m"); try Data("preserve".utf8).write(to: existing)
            let review = SigningReview(), interaction = SigningInteraction()
            await review.prepare(context, batch: batch, validate: {})
            let plan = try XCTUnwrap(review.approval)
            XCTAssertEqual(plan.jobs[0].destination.lastPathComponent, "synthetic (2).txt.p7m")
            _ = try interaction.approveDisplayed(batch: batch, approval: plan, additionalConfirmation: false, isCurrent: { true }, present: { _ in XCTFail(); return true })
            try Data("late collision".utf8).write(to: plan.jobs[0].destination)
            try await batch.authorizeNext(pin: "synthetic") { _, _, _ in XCTFail("No authentication after collision") }
            XCTAssertEqual(batch.documents[0].state, .failed)
            XCTAssertEqual(batch.approval?.jobs[0].destination, plan.jobs[0].destination)
            XCTAssertEqual(try String(contentsOf: existing), "preserve")
        }
    }
}
#endif
