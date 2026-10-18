#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class SigningInteractionTests: XCTestCase {
    private var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    private func fixture(_ body: (URL, SoftwareSigner, MockModule, BatchSigningCoordinator, SigningInteraction) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        let files = try (1...3).map { index -> URL in
            let path = root.appendingPathComponent("document-\(index).txt")
            try Data("Synthetic document \(index)".utf8).write(to: path); return path
        }
        await batch.addDocuments(files, format: .cades)
        try await body(root, signer, mock, batch, SigningInteraction())
    }
    private func prepare(_ batch: BatchSigningCoordinator, _ signer: SoftwareSigner, _ mock: MockModule) async throws -> BatchApproval {
        try await batch.prepareApproval(provider: mock.path.path, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
    }
    private func audit(_ mock: MockModule, _ code: String) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == code }.count
    }
    func testOneConfirmationThenThreePINSubmissionsPublishWithoutMoreApprovals() async throws {
        try await fixture { _, signer, mock, batch, interaction in
            var presentations = 0
            let approval = try await interaction.prepareAndConfirm(batch: batch, prepare: {
                XCTAssertEqual(SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: true).stage, .preparing)
                return try await prepare(batch, signer, mock)
            }, present: { plan in
                presentations += 1; XCTAssertFalse(batch.isApproved); XCTAssertTrue(batch.isFrozen)
                XCTAssertEqual(SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: true).stage, .confirming)
                XCTAssertTrue(plan.jobs.allSatisfy { !FileManager.default.fileExists(atPath: $0.destination.path) })
                XCTAssertTrue(plan.technicalDetails.contains("Provider:")); XCTAssertTrue(plan.technicalDetails.contains("SHA-256:"))
                return true
            })
            XCTAssertNotNil(approval); XCTAssertEqual(presentations, 1)
            do { _ = try await interaction.prepareAndConfirm(batch: batch, prepare: { XCTFail("Already approved"); return try await prepare(batch, signer, mock) }, present: { _ in presentations += 1; return true }); XCTFail("Second approval forbidden") } catch {}
            let worker = worker
            for index in 0..<3 {
                let view = SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: false)
                XCTAssertEqual(view.pinPrompt, "Firma \(index + 1) di 3 — Inserisci PIN")
                var pin = "synthetic-fixture"
                let task = try XCTUnwrap(interaction.submitPIN(&pin, batch: batch, execute: { job, pin, operation in
                    try job.signCAdES(using: .init(executable: worker), pin: pin, operation: operation)
                }))
                XCTAssertTrue(pin.isEmpty); XCTAssertTrue(interaction.isSubmittingPIN)
                var second = "synthetic-fixture"
                XCTAssertNil(interaction.submitPIN(&second, batch: batch, execute: { _, _, _ in XCTFail("Concurrent submission") }))
                XCTAssertTrue(second.isEmpty)
                await task.value
                XCTAssertFalse(interaction.isSubmittingPIN)
                XCTAssertEqual(batch.documents[index].state, .completed)
                XCTAssertEqual(audit(mock, "8"), index + 1); XCTAssertEqual(audit(mock, "16"), index + 1)
                XCTAssertEqual(presentations, 1)
            }
            let final = SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: false)
            XCTAssertEqual(final.stage, .completed); XCTAssertNil(final.pinPrompt)
            XCTAssertEqual(final.resultSummary, "3 documenti firmati correttamente"); XCTAssertEqual(audit(mock, "10"), 0)
        }
    }
    func testCancelledConsentLeavesSelectionEditableWithoutAuthentication() async throws {
        try await fixture { _, signer, mock, batch, interaction in
            var presentations = 0
            let result = try await interaction.prepareAndConfirm(batch: batch, prepare: { try await prepare(batch, signer, mock) }, present: { _ in presentations += 1; return false })
            XCTAssertNil(result); XCTAssertEqual(presentations, 1)
            XCTAssertFalse(batch.isApproved); XCTAssertFalse(batch.isFrozen)
            XCTAssertNil(batch.approval); XCTAssertEqual(audit(mock, "8"), 0)
            XCTAssertTrue(batch.documents.allSatisfy { FileManager.default.fileExists(atPath: $0.snapshot.fileURL.path) })
        }
    }
    func testPreparationFailureNeverPresentsConsentAndRecoversFlags() async throws {
        try await fixture { _, _, _, batch, interaction in
            do { _ = try await interaction.prepareAndConfirm(batch: batch, prepare: { throw SupervisedProcess.Failure.cancelled }, present: { _ in XCTFail("No plan, no popup"); return true }); XCTFail("Expected failure") } catch {}
            XCTAssertFalse(interaction.isRequestingApproval); XCTAssertFalse(interaction.isShowingConfirmation)
            XCTAssertFalse(batch.isApproved)
        }
    }
    func testPINCannotMoveToNextDocumentIfCurrentIsCancelledBeforeTaskStarts() async throws {
        try await fixture { _, signer, mock, batch, interaction in
            _ = try await interaction.prepareAndConfirm(batch: batch, prepare: { try await prepare(batch, signer, mock) }, present: { _ in true })
            let first = try XCTUnwrap(batch.nextDocument?.id)
            var pin = "synthetic-fixture"
            let task = try XCTUnwrap(interaction.submitPIN(&pin, batch: batch, execute: { _, _, _ in XCTFail("PIN retargeted after cancellation") }))
            batch.cancelDocument(first)
            await task.value
            XCTAssertTrue(pin.isEmpty); XCTAssertEqual(audit(mock, "8"), 0)
            XCTAssertEqual(batch.documents[0].state, .cancelled)
            XCTAssertFalse(batch.documents[1].state.isTerminal)
            XCTAssertEqual(SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: false).pinPrompt, "Firma 2 di 3 — Inserisci PIN")
        }
    }
    func testUncertainOutcomeStopsPINRequestsAndNeverRetriesTheDocument() async throws {
        try await fixture { _, signer, mock, batch, interaction in
            _ = try await interaction.prepareAndConfirm(batch: batch, prepare: { try await prepare(batch, signer, mock) }, present: { _ in true })
            var pin = "synthetic-fixture"
            let task = try XCTUnwrap(interaction.submitPIN(&pin, batch: batch, execute: { _, _, _ in throw SignumError.outputUncertain("Synthetic uncertain operation") }))
            await task.value
            XCTAssertEqual(batch.documents[0].state, .uncertain); XCTAssertTrue(pin.isEmpty)
            let view = SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: false)
            XCTAssertEqual(view.stage, .uncertain); XCTAssertNil(view.pinPrompt)
            pin = "synthetic-fixture"
            XCTAssertNil(interaction.submitPIN(&pin, batch: batch, execute: { _, _, _ in XCTFail("No retry after uncertainty") }))
            XCTAssertTrue(pin.isEmpty)
            batch.acknowledgeUncertainOutcome()
            XCTAssertEqual(batch.nextDocument?.id, batch.documents[1].id)
            XCTAssertEqual(audit(mock, "8"), 0)
        }
    }
    func testPresentationCoversEmptyMissingDestinationReadyAndNewSession() async throws {
        let batch = BatchSigningCoordinator(), interaction = SigningInteraction()
        XCTAssertEqual(SigningPresentation(batch: batch, interaction: interaction, destinationReady: true, canApprove: false).stage, .empty)
        try await fixture { _, _, _, selected, flow in
            XCTAssertEqual(SigningPresentation(batch: selected, interaction: flow, destinationReady: false, canApprove: false).stage, .destinationRequired)
            XCTAssertEqual(SigningPresentation(batch: selected, interaction: flow, destinationReady: true, canApprove: false).stage, .selectionRequired)
            XCTAssertEqual(SigningPresentation(batch: selected, interaction: flow, destinationReady: true, canApprove: true).stage, .ready)
            XCTAssertEqual(SigningPresentation(batch: selected, interaction: flow, destinationReady: true, canApprove: true).signButtonTitle, "Firma 3 documenti")
            selected.reset()
            XCTAssertEqual(SigningPresentation(batch: selected, interaction: flow, destinationReady: true, canApprove: false).stage, .empty)
        }
    }
}
#endif
