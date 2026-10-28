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
        var opened: () -> Void = {}
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
    static func dismantleNSViewController(_ controller: SignumNativeWorkspaceController, coordinator: ()) {
        controller.invalidate()
    }
}

@MainActor final class SignumHostedContentStore: ObservableObject {
    @Published private var current: AnyView
    private var pending: AnyView?
    private var scheduled = false, invalidated = false
    var content: AnyView {
        get { current }
        set {
            guard !invalidated else { return }
            pending = newValue
            guard !scheduled else { return }
            scheduled = true
            // Representable updates may run inside SwiftUI's update cycle.
            // Publish the latest value on the next main-queue turn, keeping the hosts.
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.invalidated, let value = self.pending else { return }
                self.pending = nil; self.scheduled = false; self.current = value
            }
        }
    }
    init(_ content: AnyView) { current = content }
    func invalidate() { invalidated = true; pending = nil }
}
struct SignumHostedContent: View {
    @ObservedObject var store: SignumHostedContentStore
    var body: some View { store.content }
}
/// Foundation owns removal independently of the controller's actor isolation.
/// This non-Sendable owner stays with its creating controller/executor.
final class SignumNotificationObservation {
    private let center: NotificationCenter
    private let token: NSObjectProtocol
    init(center: NotificationCenter = .default, name: Notification.Name, object: Any?,
         queue: OperationQueue? = .main, handler: @escaping @Sendable (Notification) -> Void) {
        self.center = center
        token = center.addObserver(forName: name, object: object, queue: queue, using: handler)
    }
    deinit { center.removeObserver(token) }
}
final class SignumNativeWorkspaceController: NSSplitViewController, NSToolbarDelegate {
    let sidebarContent: SignumHostedContentStore
    let detailContent: SignumHostedContentStore
    let sidebarHost: NSHostingController<SignumHostedContent>
    let detailHost: NSHostingController<SignumHostedContent>
    private var closeObserver: SignumNotificationObservation?
    private var openObserver: SignumNotificationObservation?
    private var controls: SignumNativeWorkspace.Controls
    private let nativeToolbar = NSToolbar(identifier: "signum.window.toolbar")
    private var items: [NSToolbarItem.Identifier: NSToolbarItem] = [:]
    private var installed = false
    private var invalidated = false
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
        // AppKit is the sole owner of the containing window's title and toolbar.
        // Nested SwiftUI controls (notably TabView) must not create a competing
        // scene bridge/BarAppearanceBridge for that same NSToolbar.
        if #available(macOS 14, *) {
            sidebarHost.sceneBridgingOptions = []
            detailHost.sceneBridgingOptions = []
        }
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
        guard !invalidated else { return }
        guard let window = view.window else { return }
        if !installed {
            installed = true
            closeObserver = SignumNotificationObservation(name: NSWindow.willCloseNotification, object: window) { [weak self] _ in
                MainActor.assumeIsolated { self?.controls.close() }
            }
            openObserver = SignumNotificationObservation(name: .signumWindowOpened, object: window) { [weak self] _ in
                MainActor.assumeIsolated { self?.controls.opened() }
            }
            controls.opened()
            window.toolbar = nativeToolbar
            window.toolbarStyle = .unified
            window.title = "Signum"
            window.titleVisibility = .visible
            if !splitViewItems[0].isCollapsed { splitView.setPosition(200, ofDividerAt: 0) }
        }
        update(controls)
    }
    func invalidate() {
        guard !invalidated else { return }
        invalidated = true
        sidebarContent.invalidate(); detailContent.invalidate()
        closeObserver = nil; openObserver = nil
        controls.close()
    }
    func update(_ controls: SignumNativeWorkspace.Controls) {
        guard !invalidated else { return }
        self.controls = controls
        for item in items.values { item.isEnabled = !controls.locked }
        items[Self.refreshID]?.isEnabled = !controls.locked && !controls.searching
        items[Self.refreshID]?.toolTip = controls.searching ? "Ricerca dispositivi in corso…" : "Aggiorna dispositivi, token e certificati senza PIN"
        // The item set is immutable after installation. Updating a hosted view
        // must never insert/remove toolbar items during AppKit constraint layout.
        if #available(macOS 15, *) {
            items[Self.addID]?.isHidden = !controls.showAdd
            items[Self.backID]?.isHidden = !controls.showBack
        }
        items[Self.addID]?.isEnabled = !controls.locked && controls.showAdd
        items[Self.backID]?.isEnabled = !controls.locked && controls.showBack
    }
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.toggle, Self.separator, Self.backID, .flexibleSpace, Self.addID, Self.refreshID, Self.settingsID]
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
    @objc private func addDocuments() { if !controls.locked && controls.showAdd { controls.add() } }
    @objc private func refreshDevices() { if !controls.locked && !controls.searching { controls.refresh() } }
    @objc private func openSettings() { if !controls.locked { controls.settings() } }
    @objc private func goBack() { if !controls.locked && controls.showBack { controls.back() } }
}
#endif
