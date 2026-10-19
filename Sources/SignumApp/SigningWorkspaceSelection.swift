#if os(macOS)
import Foundation
import Combine
import SignumCore

/// Current document is independent of the acquisition default. Generation also
/// rejects callbacks from a previous mounting of the same snapshot.
@MainActor final class SigningWorkspaceSelection: ObservableObject {
    @Published private(set) var snapshot: DocumentSnapshot?
    @Published private(set) var format: SigningFormat?
    @Published private(set) var generation = UUID()
    @Published var showingPDFPreview: Bool
    var showsPAdESPreview: Bool { format == .pades && showingPDFPreview }
    init(snapshot: DocumentSnapshot? = nil, format: SigningFormat? = nil) {
        let kind = snapshot.map { format ?? $0.format }
        self.snapshot = snapshot; self.format = kind; showingPDFPreview = kind == .pades
    }
    func updateFormat(_ value: SigningFormat?) {
        guard format != value else { return }
        generation = UUID(); format = value; showingPDFPreview = value == .pades
    }
    func select(_ value: DocumentSnapshot?, format chosen: SigningFormat? = nil) {
        let kind = value.map { chosen ?? $0.format }
        if format != kind { updateFormat(kind) }
        guard snapshot?.identity.id != value?.identity.id else {
            if kind == .pades, !showingPDFPreview { generation = UUID() }
            showingPDFPreview = kind == .pades
            return
        }
        generation = UUID(); snapshot = value; format = kind
        showingPDFPreview = kind == .pades
    }
    func accepts(_ id: UUID, generation: UUID) -> Bool {
        snapshot?.identity.id == id && self.generation == generation
    }
}
#endif
