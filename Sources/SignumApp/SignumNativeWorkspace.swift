#if os(macOS)
import SwiftUI
import AppKit

/// AppKit owns collapse animation, pane constraints, tracking separator and the
/// single toolbar. Hosting controllers and toolbar items live for the window's
/// lifetime; a SwiftUI column transition cannot create a second toolbar.
struct SignumNativeWorkspace: NSViewControllerRepresentable {
    struct Controls {
        var showAdd: Bool
        var showBack: Bool
        var locked: Bool
        var searching: Bool
        var initiallyCollapsed: Bool
        var add: () -> Void
        var refresh: () -> Void
        var settings: () -> Void
        var back: () -> Void
        var close: () -> Void = {}
    }
    let sidebar: AnyView
    let detail: AnyView
    let controls: Controls
    func makeNSViewController(context: Context) -> SignumNativeWorkspaceController {
        .init(sidebar: sidebar, detail: detail, controls: controls)
    }
    func updateNSViewController(_ controller: SignumNativeWorkspaceController, context: Context) {
        controller.sidebarContent.content = sidebar
        controller.detailContent.content = detail
        controller.update(controls)
    }
}

@MainActor final class SignumHostedContentStore: ObservableObject {
    @Published var content: AnyView
    init(_ content: AnyView) { self.content = content }
}
struct SignumHostedContent: View {
    @ObservedObject var store: SignumHostedContentStore
    var body: some View { store.content }
}
final class SignumNativeWorkspaceController: NSSplitViewController, NSToolbarDelegate {
    let sidebarContent: SignumHostedContentStore
    let detailContent: SignumHostedContentStore
    let sidebarHost: NSHostingController<SignumHostedContent>
    let detailHost: NSHostingController<SignumHostedContent>
    private var closeObserver: NSObjectProtocol?
    private var controls: SignumNativeWorkspace.Controls
    private let nativeToolbar = NSToolbar(identifier: "signum.window.toolbar")
    private var items: [NSToolbarItem.Identifier: NSToolbarItem] = [:]
    private var installed = false
    private static let toggle = NSToolbarItem.Identifier("signum.sidebar")
    private static let separator = NSToolbarItem.Identifier("signum.sidebar.separator")
    private static let backID = NSToolbarItem.Identifier("signum.back")
    private static let addID = NSToolbarItem.Identifier("signum.add")
    private static let refreshID = NSToolbarItem.Identifier("signum.refresh")
    private static let settingsID = NSToolbarItem.Identifier("signum.settings")

    init(sidebar: AnyView, detail: AnyView, controls: SignumNativeWorkspace.Controls) {
        sidebarContent = .init(sidebar)
        detailContent = .init(detail)
        sidebarHost = .init(rootView: .init(store: sidebarContent))
        detailHost = .init(rootView: .init(store: detailContent))
        self.controls = controls
        super.init(nibName: nil, bundle: nil)
        sidebarHost.sizingOptions = []
        detailHost.sizingOptions = []
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
    override func viewDidLoad() {
        super.viewDidLoad()
        splitView.isVertical = true
        splitView.dividerStyle = .thin
        let sidebar = NSSplitViewItem(sidebarWithViewController: sidebarHost)
        sidebar.minimumThickness = 200
        sidebar.maximumThickness = 240
        sidebar.preferredThicknessFraction = 200 / 1320
        sidebar.holdingPriority = .defaultHigh
        sidebar.collapseBehavior = .preferResizingSiblingsWithFixedSplitView
        sidebar.canCollapseFromWindowResize = false
        sidebar.allowsFullHeightLayout = true
        sidebar.isCollapsed = controls.initiallyCollapsed
        let detail = NSSplitViewItem(viewController: detailHost)
        detail.minimumThickness = 710
        if #available(macOS 26, *) { detail.automaticallyAdjustsSafeAreaInsets = true }
        addSplitViewItem(sidebar)
        addSplitViewItem(detail)
        nativeToolbar.delegate = self
        nativeToolbar.displayMode = .iconOnly
        nativeToolbar.allowsUserCustomization = false
        nativeToolbar.autosavesConfiguration = false
    }
    override func viewDidAppear() {
        super.viewDidAppear()
        guard let window = view.window else { return }
        if !installed {
            installed = true
            closeObserver = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.controls.close() }
            }
            window.toolbar = nativeToolbar
            window.toolbarStyle = .unified
            window.title = "Signum"
            window.titleVisibility = .visible
            if !splitViewItems[0].isCollapsed { splitView.setPosition(200, ofDividerAt: 0) }
        }
        update(controls)
    }
    deinit { if let closeObserver { NotificationCenter.default.removeObserver(closeObserver) } }
    func update(_ controls: SignumNativeWorkspace.Controls) {
        self.controls = controls
        for item in items.values { item.isEnabled = !controls.locked }
        items[Self.refreshID]?.isEnabled = !controls.locked && !controls.searching
        items[Self.refreshID]?.toolTip = controls.searching ? "Ricerca dispositivi in corso…" : "Aggiorna dispositivi, token e certificati senza PIN"
        // Section changes may add/remove commands. Sidebar toggles never do.
        setVisible(Self.addID, controls.showAdd, at: max(0, nativeToolbar.items.count - 2))
        setVisible(Self.backID, controls.showBack, at: min(2, nativeToolbar.items.count))
    }
    private func setVisible(_ id: NSToolbarItem.Identifier, _ visible: Bool, at index: Int) {
        guard installed else { return }
        let current = nativeToolbar.items.firstIndex { $0.itemIdentifier == id }
        if visible, current == nil { nativeToolbar.insertItem(withItemIdentifier: id, at: index) }
        else if !visible, let current { nativeToolbar.removeItem(at: current) }
    }
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.toggle, Self.separator, .flexibleSpace] + (controls.showAdd ? [Self.addID] : []) + [Self.refreshID, Self.settingsID]
    }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.toggle, Self.separator, Self.backID, .flexibleSpace, Self.addID, Self.refreshID, Self.settingsID]
    }
    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        if let existing = items[id] { return existing }
        if id == Self.separator {
            let separator = NSTrackingSeparatorToolbarItem(identifier: id, splitView: splitView, dividerIndex: 0)
            items[id] = separator
            return separator
        }
        let item = NSToolbarItem(itemIdentifier: id)
        item.target = self
        item.autovalidates = false
        item.isBordered = true
        item.visibilityPriority = .high
        switch id {
        case Self.toggle:
            item.label = "Sidebar"; item.toolTip = "Mostra o nascondi la sidebar"
            item.image = NSImage(systemSymbolName: "sidebar.left", accessibilityDescription: item.label)
            item.action = #selector(toggleSidebar(_:)); item.isNavigational = true
        case Self.backID:
            item.label = "Indietro"; item.image = NSImage(systemSymbolName: "chevron.backward", accessibilityDescription: item.label)
            item.action = #selector(goBack); item.isNavigational = true
        case Self.addID:
            item.label = "Aggiungi documenti"; item.toolTip = item.label
            item.image = NSImage(systemSymbolName: "plus", accessibilityDescription: item.label)
            item.action = #selector(addDocuments)
        case Self.refreshID:
            item.label = "Aggiorna dispositivi"
            item.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: item.label)
            item.action = #selector(refreshDevices)
        case Self.settingsID:
            item.label = "Impostazioni"
            item.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: item.label)
            item.action = #selector(openSettings)
        default: return nil
        }
        items[id] = item
        return item
    }
    override func validateUserInterfaceItem(_ item: NSValidatedUserInterfaceItem) -> Bool {
        guard !controls.locked else { return false }
        if item.action == #selector(refreshDevices) { return !controls.searching }
        return true
    }
    override func toggleSidebar(_ sender: Any?) {
        guard !controls.locked else { return }
        super.toggleSidebar(sender)
    }
    @objc private func addDocuments() { if !controls.locked { controls.add() } }
    @objc private func refreshDevices() { if !controls.locked && !controls.searching { controls.refresh() } }
    @objc private func openSettings() { if !controls.locked { controls.settings() } }
    @objc private func goBack() { if !controls.locked { controls.back() } }
}
#endif
