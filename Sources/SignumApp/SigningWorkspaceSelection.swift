#if os(macOS)
import Foundation
import Combine
import SignumCore

/// Current document is independent of the acquisition default. Generation also
/// rejects callbacks from a previous mounting of the same snapshot.
@MainActor final class SigningWorkspaceSelection: ObservableObject {
    @Published private(set) var snapshot: DocumentSnapshot?
    @Published private(set) var generation = UUID()
    @Published var showingPDFPreview: Bool
    var showsPAdESPreview: Bool { snapshot?.format == .pades && showingPDFPreview }
    init(snapshot: DocumentSnapshot? = nil) {
        self.snapshot = snapshot; showingPDFPreview = snapshot?.format == .pades
    }
    func select(_ value: DocumentSnapshot?) {
        guard snapshot?.identity.id != value?.identity.id else {
            if value?.format == .pades, !showingPDFPreview { generation = UUID() }
            showingPDFPreview = value?.format == .pades
            return
        }
        generation = UUID(); snapshot = value
        showingPDFPreview = value?.format == .pades
    }
    func accepts(_ id: UUID, generation: UUID) -> Bool {
        snapshot?.identity.id == id && self.generation == generation
    }
}
#endif
