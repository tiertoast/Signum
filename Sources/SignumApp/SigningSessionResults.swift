#if os(macOS)
import Foundation
import Combine
import SignumCore

struct SigningReceipt: Identifiable {
    let id: UUID
    let name: String
    let format: String
    let state: BatchDocumentState
    let detail: String
    let output: URL?
}

/// Retains only presentation values, never jobs, snapshots, approval or secrets.
@MainActor final class SigningSessionResults: ObservableObject {
    @Published private(set) var receipts: [SigningReceipt] = []
    /// Discards presentation history only. Active/uncertain work remains owned by the coordinator.
    func clear() { receipts.removeAll() }

    @discardableResult
    func releaseIfFinished(_ batch: BatchSigningCoordinator, interactionBusy: Bool,
                           hasAuthenticationContext: Bool, otherWork: Bool = false, allowRevokedSelection: Bool = false) -> Bool {
        guard (batch.isApproved || (allowRevokedSelection && batch.documents.allSatisfy { $0.state == .cancelled })), !batch.documents.isEmpty,
              batch.documents.allSatisfy({ $0.state.isTerminal }),
              !batch.isRunning, !batch.isPreparing, !batch.isContinuingAuthenticated,
              !batch.needsOutcomeReview, !interactionBusy, !hasAuthenticationContext, !otherWork else { return false }
        let values = batch.documents.map {
            SigningReceipt(id: $0.id, name: $0.snapshot.originalURL.lastPathComponent,
                format: SignumFormat(rawValue: $0.format.rawValue)?.displayTitle ?? $0.format.shortTitle, state: $0.state, detail: $0.result,
                output: $0.destination)
        }
        batch.reset()
        guard !batch.isFrozen, batch.approval == nil else { return false }
        receipts.append(contentsOf: values)
        return true
    }
}
#endif
