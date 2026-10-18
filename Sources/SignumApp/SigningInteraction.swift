#if os(macOS)
import Foundation
import Combine
import SignumCore

/// App interaction state, separate from immutable Core jobs. Never stores a PIN.
@MainActor final class SigningInteraction: ObservableObject {
    @Published private(set) var isRequestingApproval = false
    @Published private(set) var isShowingConfirmation = false
    @Published private(set) var isSubmittingPIN = false

    /// The principal button is consent for the exact main-screen review. The
    /// optional modal adds confirmation, never substitutes a changed plan.
    func approveDisplayed(batch: BatchSigningCoordinator, approval: BatchApproval,
                          additionalConfirmation: Bool, isCurrent: () -> Bool,
                          present: (BatchApproval) -> Bool) throws -> Bool {
        guard !isRequestingApproval, !isSubmittingPIN, isCurrent() else {
            throw SignumError.module("Il riepilogo è cambiato. Controlla la nuova lista prima di firmare.")
        }
        isRequestingApproval = true
        defer { isRequestingApproval = false; isShowingConfirmation = false }
        try batch.freezeReview(approval)
        do {
            if additionalConfirmation {
                isShowingConfirmation = true
                guard present(approval) else { batch.declineApproval(); return false }
            }
            guard isCurrent() else { throw SignumError.module("La selezione è cambiata. Controlla il riepilogo aggiornato.") }
            try batch.confirm(approval)
            return true
        } catch { batch.declineApproval(); throw error }
    }

    func prepareAndConfirm(batch: BatchSigningCoordinator,
                           prepare: () async throws -> BatchApproval,
                           present: (BatchApproval) -> Bool) async throws -> BatchApproval? {
        guard !isRequestingApproval, !isSubmittingPIN, !batch.isApproved, !batch.isFrozen else {
            throw SignumError.module("La sessione è già in preparazione o approvata.")
        }
        isRequestingApproval = true
        defer { isRequestingApproval = false; isShowingConfirmation = false }
        let approval = try await prepare()
        if Task.isCancelled { batch.declineApproval(); throw SupervisedProcess.Failure.cancelled }
        isShowingConfirmation = true
        if present(approval) {
            try batch.confirm(approval)
            return approval
        }
        batch.declineApproval()
        return nil
    }

    func canSubmitPIN(_ pin: String, batch: BatchSigningCoordinator) -> Bool {
        !isRequestingApproval && !isSubmittingPIN && batch.isApproved && !batch.isRunning &&
            !batch.needsOutcomeReview && batch.nextDocument != nil &&
            !pin.isEmpty && pin.utf8.count <= 64 && !pin.utf8.contains(0)
    }

    /// The field is cleared synchronously, before scheduling any private work.
    /// Capture the current document so cancellation cannot apply its PIN to the next.
    @discardableResult func submitPIN(_ pin: inout String, batch: BatchSigningCoordinator,
        execute: @escaping @Sendable (SigningJob, String, SigningOperation) throws -> Void,
        completion: @escaping @MainActor (Result<Void, Error>) -> Void = { _ in }) -> Task<Void, Never>? {
        let accepted = canSubmitPIN(pin, batch: batch)
        let secret = pin; pin = ""
        guard accepted, let document = batch.nextDocument else { return nil }
        isSubmittingPIN = true
        return Task { @MainActor in
            defer { isSubmittingPIN = false }
            do {
                guard !Task.isCancelled else { throw SupervisedProcess.Failure.cancelled }
                try await batch.authorizeNext(pin: secret, expectedDocumentID: document.id, execute: execute)
                completion(.success(()))
            } catch { completion(.failure(error)) }
        }
    }
}

@MainActor struct SigningPresentation {
    enum Stage: Equatable {
        case empty, destinationRequired, selectionRequired, ready, preparing, confirming, awaitingPIN, signing, uncertain, completed
    }
    let batch: BatchSigningCoordinator
    let interaction: SigningInteraction
    let destinationReady: Bool
    let canApprove: Bool
    var stage: Stage {
        if batch.needsOutcomeReview { return .uncertain }
        if batch.isRunning || batch.isContinuingAuthenticated || interaction.isSubmittingPIN { return .signing }
        if interaction.isShowingConfirmation { return .confirming }
        if batch.isPreparing || interaction.isRequestingApproval { return .preparing }
        if batch.isApproved { return batch.nextDocument == nil ? .completed : .awaitingPIN }
        if batch.documents.isEmpty { return .empty }
        if !destinationReady { return .destinationRequired }
        return canApprove ? .ready : .selectionRequired
    }
    var signButtonTitle: String {
        batch.documents.count <= 1 ? "Firma documento" : "Firma \(batch.documents.count) documenti"
    }
    var pinPrompt: String? {
        guard stage == .awaitingPIN, let next = batch.nextDocument,
              let index = batch.documents.firstIndex(where: { $0.id == next.id }) else { return nil }
        return "Firma \(index + 1) di \(batch.documents.count) — Inserisci PIN"
    }
    var resultSummary: String {
        BatchWorkspaceSummary.summary(batch.documents.map(\.state))
    }
}
#endif
