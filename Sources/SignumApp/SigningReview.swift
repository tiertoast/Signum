#if os(macOS)
import Foundation
import Combine
import SignumCore

struct SigningReviewContext: Equatable {
    let revision: UUID
    let provider: String
    let slot: UInt
    let certificate: SignumCertificate
    let der: Data
    let destination: BatchOutputDestination
    let routeID: String
    let discoveryID: UUID
    var appearanceHashes: [UUID:String] = [:]
    static func == (a: Self, b: Self) -> Bool {
        a.revision == b.revision && a.provider == b.provider && a.slot == b.slot &&
        a.certificate.identifier == b.certificate.identifier && a.der == b.der &&
        a.destination == b.destination && a.routeID == b.routeID && a.discoveryID == b.discoveryID && a.appearanceHashes == b.appearanceHashes
    }
}

@MainActor final class SigningReview: ObservableObject {
    @Published private(set) var context: SigningReviewContext?
    @Published private(set) var approval: BatchApproval?
    @Published private(set) var isPreparing = false
    @Published private(set) var issue = ""
    private var request = UUID()
    func prepare(_ context: SigningReviewContext?, batch: BatchSigningCoordinator,
                 appearances: [UUID: RenderedPAdESAppearance] = [:],
                 validate: @escaping @Sendable () throws -> Void) async {
        guard !batch.isFrozen else { return }
        let id = UUID(); request = id
        self.context = context; approval = nil; issue = ""; isPreparing = context != nil
        batch.invalidateReview()
        guard let context else { return }
        defer { if request == id { isPreparing = false } }
        do {
            guard context.appearanceHashes == appearances.mapValues({ $0.approvalIdentity }) else {
                throw SignumError.module("L’appearance è cambiata. Attendi la nuova anteprima prima di approvare.")
            }
            try await Task.detached(priority: .userInitiated) { try validate() }.value
            guard request == id, !Task.isCancelled, context.revision == batch.revision else { return }
            let plan = try await batch.prepareReview(provider: context.provider, slot: context.slot,
                certificate: context.certificate, der: context.der, destination: context.destination, appearances: appearances)
            guard request == id, !Task.isCancelled else { return }
            approval = plan
        } catch { if request == id, !Task.isCancelled { issue = error.localizedDescription } }
    }
    func matches(_ current: SigningReviewContext?, batch: BatchSigningCoordinator) -> Bool {
        !isPreparing && context == current && approval != nil && approval?.id == batch.review?.id
    }
}
#endif
