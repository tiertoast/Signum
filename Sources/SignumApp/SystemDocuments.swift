#if os(macOS)
import AppKit
import Combine
import Foundation

enum SystemDocumentAction { case sign, verify }
struct SystemDocumentRequest: Identifiable {
    let id = UUID()
    let urls: [URL]
    let action: SystemDocumentAction
}
/// Receives events before any window exists. Never authorizes a signing operation.
@MainActor final class SystemDocuments: ObservableObject {
    static let shared = SystemDocuments()
    @Published private(set) var revision = 0
    private var pending: [SystemDocumentRequest] = []
    func receive(_ urls: [URL], action: SystemDocumentAction = .verify) {
        let files = urls.filter(\.isFileURL)
        guard !files.isEmpty else { return }
        // Keep events separate and bound each acquisition to the workspace limit.
        for offset in stride(from: 0, to: files.count, by: 32) {
            pending.append(.init(urls: Array(files[offset..<min(offset + 32, files.count)]), action: action))
        }
        revision += 1
    }
    func next() -> SystemDocumentRequest? { pending.isEmpty ? nil : pending.removeFirst() }
}

@MainActor final class SignumServices: NSObject {
    @objc func signDocuments(_ pasteboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        receive(pasteboard, action: .sign, error: error)
    }
    @objc func verifyDocuments(_ pasteboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        receive(pasteboard, action: .verify, error: error)
    }
    private func receive(_ pasteboard: NSPasteboard, action: SystemDocumentAction, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        guard !urls.isEmpty else { error.pointee = "Nessun documento locale disponibile."; return }
        SystemDocuments.shared.receive(urls, action: action)
        NSApp.activate(ignoringOtherApps: true)
        NSApp.windows.first(where: { $0.canBecomeMain })?.makeKeyAndOrderFront(nil)
    }
}
#endif
