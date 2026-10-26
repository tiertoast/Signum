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


/// A single AppKit owner for NSWindow/NSToolbar. SwiftUI remains the content,
/// without a second SwiftUI Window scene controller observing/replacing the bar.
@MainActor final class SignumLifecycle: NSObject, NSApplicationDelegate {
    let services = SignumServices()
    let trustedLists = try? TrustedListsModel.developmentPreview()
    private(set) var mainWindowController: SignumMainWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        configureMenus()
        trustedLists?.start()
        NSApp.servicesProvider = services
        NSUpdateDynamicServices()
        showMainWindow()
    }
    func applicationWillTerminate(_ notification: Notification) { trustedLists?.stop() }
    func application(_ application: NSApplication, open urls: [URL]) {
        SystemDocuments.shared.receive(urls)
        showMainWindow()
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showMainWindow(); return true
    }
    func showMainWindow() {
        if mainWindowController == nil {
            let content = SignumWindow(trustedLists: trustedLists)
                .frame(minWidth: 980, minHeight: 650)
            mainWindowController = SignumMainWindowController(content: AnyView(content))
        }
        mainWindowController?.showWindow(nil)
        mainWindowController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    @objc func openSettings() {
        showMainWindow()
        NotificationCenter.default.post(name: .signumShowSettings, object: nil)
    }
    private func configureMenus() {
        let menu = NSMenu()
        let application = NSMenu(title: "Signum")
        application.addItem(withTitle: "Informazioni su Signum", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        application.addItem(.separator())
        let settings = application.addItem(withTitle: "Impostazioni…", action: #selector(openSettings), keyEquivalent: ",")
        settings.target = self
        application.addItem(.separator())
        let servicesMenu = NSMenu(title: "Servizi")
        application.addItem(withTitle: "Servizi", action: nil, keyEquivalent: "").submenu = servicesMenu
        NSApp.servicesMenu = servicesMenu
        application.addItem(.separator())
        application.addItem(withTitle: "Nascondi Signum", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let others = application.addItem(withTitle: "Nascondi altre", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        others.keyEquivalentModifierMask = [.command, .option]
        application.addItem(withTitle: "Mostra tutte", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        application.addItem(.separator())
        application.addItem(withTitle: "Esci da Signum", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(withTitle: "Signum", action: nil, keyEquivalent: "").submenu = application
        let file = NSMenu(title: "File")
        file.addItem(withTitle: "Chiudi finestra", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        menu.addItem(withTitle: "File", action: nil, keyEquivalent: "").submenu = file
        let edit = NSMenu(title: "Modifica")
        for (title, action, key) in [("Annulla", "undo:", "z"), ("Ripristina", "redo:", "Z"),
                                     ("Taglia", "cut:", "x"), ("Copia", "copy:", "c"), ("Incolla", "paste:", "v"),
                                     ("Seleziona tutto", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: NSSelectorFromString(action), keyEquivalent: key)
        }
        menu.addItem(withTitle: "Modifica", action: nil, keyEquivalent: "").submenu = edit
        let view = NSMenu(title: "Vista")
        view.addItem(withTitle: "Mostra/nascondi sidebar", action: #selector(NSSplitViewController.toggleSidebar(_:)), keyEquivalent: "s").keyEquivalentModifierMask = [.command, .control]
        let fullScreen = view.addItem(withTitle: "Attiva/disattiva schermo intero", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        fullScreen.keyEquivalentModifierMask = [.command, .control]
        menu.addItem(withTitle: "Vista", action: nil, keyEquivalent: "").submenu = view
        let windows = NSMenu(title: "Finestra")
        windows.addItem(withTitle: "Contrai", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windows.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windows.addItem(.separator())
        windows.addItem(withTitle: "Porta tutte in primo piano", action: #selector(NSApplication.arrangeInFront(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Finestra", action: nil, keyEquivalent: "").submenu = windows
        NSApp.windowsMenu = windows
        let help = NSMenu(title: "Aiuto")
        menu.addItem(withTitle: "Aiuto", action: nil, keyEquivalent: "").submenu = help
        NSApp.helpMenu = help
        NSApp.mainMenu = menu
    }
}

@main
struct SignumApp {
    @MainActor static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.regular)
        let lifecycle = SignumLifecycle()
        application.delegate = lifecycle
        withExtendedLifetime(lifecycle) { application.run() }
    }
}


#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
