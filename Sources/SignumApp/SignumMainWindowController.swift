#if os(macOS)
import AppKit
import SwiftUI

extension Notification.Name { static let signumWindowOpened = Notification.Name("signum.window.opened") }

/// The window and toolbar have one AppKit owner. The hosting controller renders
/// content only: it must not bridge title/toolbar preferences to this window.
@MainActor final class SignumMainWindowController: NSWindowController, NSWindowDelegate {
    let signingSession: SigningWindowSession?
    override var window: NSWindow? {
        didSet {
            if let oldValue, oldValue !== window { signingSession?.revoke(); oldValue.delegate = nil }
            window?.delegate = self
        }
    }
    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        NotificationCenter.default.post(name: .signumWindowOpened, object: window)
    }
    func windowWillClose(_ notification: Notification) { signingSession?.revoke() }
    let contentHost: NSHostingController<AnyView>
    init(content: AnyView, session: SigningWindowSession? = nil) {
        signingSession = session
        contentHost = NSHostingController(rootView: content)
        contentHost.sizingOptions = []
        if #available(macOS 14, *) { contentHost.sceneBridgingOptions = [] }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1320, height: 830),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.identifier = NSUserInterfaceItemIdentifier("signum-main")
        window.title = "Signum"
        window.contentViewController = contentHost
        // AppKit ignores contentMinSize when Auto Layout is in use. Export the
        // same minimum as real root-view constraints, including native tiling.
        NSLayoutConstraint.activate([
            contentHost.view.widthAnchor.constraint(greaterThanOrEqualToConstant: 980),
            contentHost.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 650)
        ])
        window.contentMinSize = NSSize(width: 980, height: 650)
        window.setContentSize(NSSize(width: 1320, height: 830))
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName((Bundle.main.bundleIdentifier ?? "Signum") + ".main")
        super.init(window: window)
        window.delegate = self
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
}
#endif
