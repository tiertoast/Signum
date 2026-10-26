#if os(macOS)
import AppKit
import SwiftUI

/// The window and toolbar have one AppKit owner. The hosting controller renders
/// content only: it must not bridge title/toolbar preferences to this window.
@MainActor final class SignumMainWindowController: NSWindowController {
    let contentHost: NSHostingController<AnyView>
    init(content: AnyView) {
        contentHost = NSHostingController(rootView: content)
        contentHost.sizingOptions = []
        if #available(macOS 14, *) { contentHost.sceneBridgingOptions = [] }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1320, height: 830),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.identifier = NSUserInterfaceItemIdentifier("signum-main")
        window.title = "Signum"
        window.contentViewController = contentHost
        window.contentMinSize = NSSize(width: 980, height: 650)
        window.setContentSize(NSSize(width: 1320, height: 830))
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName((Bundle.main.bundleIdentifier ?? "Signum") + ".main")
        super.init(window: window)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
}
#endif
