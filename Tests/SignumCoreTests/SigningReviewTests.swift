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
            let task = Task { await review.prepare(context, batch: batch, validate: { entered.fulfill(); release.wait() }) }
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
