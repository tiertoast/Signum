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
    /// Where the document was chosen from, and how; used only to read it again on "Riprova".
    var source: URL? = nil
    var signingFormat: SigningFormat? = nil

    /// Only a document cancelled before any signing request reached the token
    /// may be retried. "Da verificare" never: a signature may already exist.
    /// ASiC containers are rebuilt from several files, so they are excluded.
    var canRetry: Bool {
        state == .cancelled && source != nil && signingFormat.map { !$0.isASiC } == true
    }
}

/// Retains only presentation values, never jobs, snapshots, approval or secrets.
@MainActor final class SigningSessionResults: ObservableObject {
    @Published private(set) var receipts: [SigningReceipt] = []
    /// Discards presentation history only. Active/uncertain work remains owned by the coordinator.
    func clear() { receipts.removeAll() }
    /// Removes and returns the retryable receipts among `ids`; others stay.
    func takeRetryable(_ ids: Set<UUID>) -> [SigningReceipt] {
        let taken = receipts.filter { ids.contains($0.id) && $0.canRetry }
        let gone = Set(taken.map(\.id))
        receipts.removeAll { gone.contains($0.id) }
        return taken
    }

    @discardableResult
    func releaseIfFinished(_ batch: BatchSigningCoordinator, interactionBusy: Bool,
                           hasAuthenticationContext: Bool, otherWork: Bool = false, allowRevokedSelection: Bool = false) -> Bool {
        guard (batch.isApproved || batch.hasRevokedAuthorization || (allowRevokedSelection && batch.documents.allSatisfy { $0.state == .cancelled })), !batch.documents.isEmpty,
              batch.documents.allSatisfy({ $0.state.isTerminal }),
              !batch.isRunning, !batch.isPreparing, !batch.isContinuingAuthenticated,
              !batch.needsOutcomeReview, !interactionBusy, !hasAuthenticationContext, !otherWork else { return false }
        let values = batch.documents.map {
            SigningReceipt(id: $0.id, name: $0.snapshot.originalURL.lastPathComponent,
                format: SignumFormat(rawValue: $0.format.rawValue)?.displayTitle ?? $0.format.shortTitle, state: $0.state, detail: $0.result,
                output: $0.destination, source: $0.snapshot.originalURL, signingFormat: $0.format)
        }
        batch.reset()
        guard !batch.isFrozen, batch.approval == nil else { return false }
        receipts.append(contentsOf: values)
        return true
    }
}
#endif
