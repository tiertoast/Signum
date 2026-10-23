#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration

private extension Result {
    var isSuccess: Bool { if case .success = self { return true }; return false }
}

func signingApprovalMessage(holder: String, job: SigningJob) -> String {
    "Firmatario: \(holder)\n" + job.approvalDescription
}


@MainActor final class SignumLifecycle: NSObject, NSApplicationDelegate {
    let services = SignumServices()
    let trustedLists = try? TrustedListsModel.developmentPreview()
    func applicationDidFinishLaunching(_ notification: Notification) { trustedLists?.start(); NSApp.servicesProvider = services; NSUpdateDynamicServices() }
    func application(_ application: NSApplication, open urls: [URL]) { SystemDocuments.shared.receive(urls) }
    func applicationWillTerminate(_ notification: Notification) { trustedLists?.stop() }
}

@main
struct SignumApp: App {
    @NSApplicationDelegateAdaptor(SignumLifecycle.self) private var lifecycle
    var body: some Scene {
        WindowGroup("Signum") {
            SignumWindow(trustedLists: lifecycle.trustedLists)
                .frame(minWidth: 980, minHeight: 650)
        }
        .defaultSize(width: 1320, height: 830)
        .commands {
            CommandGroup(after: .appSettings) {
                Button("Impostazioni…") { NotificationCenter.default.post(name: .signumShowSettings, object: nil) }
                    .keyboardShortcut(",", modifiers: .command)
            }
        }
        // No contentSize restriction: the user can freely resize the window.
    }
}


#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
