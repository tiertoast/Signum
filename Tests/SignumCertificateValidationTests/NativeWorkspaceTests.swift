import XCTest
import SwiftUI
import AppKit
@testable import SignumApp

@MainActor final class NativeWorkspaceTests: XCTestCase {
    func controls(locked: Bool = false, add: Bool = true, back: Bool = false) -> SignumNativeWorkspace.Controls {
        .init(showAdd: add, showBack: back, locked: locked, searching: false, initiallyCollapsed: false,
              add: {}, refresh: {}, settings: {}, back: {})
    }
    func host() -> (NSWindow, SignumNativeWorkspaceController) {
        let window = NSWindow(contentRect: NSRect(x: 100, y: 100, width: 980, height: 650),
                              styleMask: [.titled, .closable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        let controller = SignumNativeWorkspaceController(sidebar: AnyView(Text("Sidebar")), detail: AnyView(Text("Detail")), controls: controls())
        window.contentViewController = controller
        window.contentMinSize = NSSize(width: 980, height: 650)
        controller.viewDidAppear()
        window.setContentSize(NSSize(width: 980, height: 650))
        window.contentView?.layoutSubtreeIfNeeded()
        return (window, controller)
    }
    func testCollapseKeepsWindowToolbarAndHostingControllersStable() throws {
        let (window, controller) = host()
        defer { window.contentViewController = nil }
        let toolbar = try XCTUnwrap(window.toolbar), frame = window.frame
        let identities = toolbar.items.map(ObjectIdentifier.init)
        let sidebar = controller.sidebarHost, detail = controller.detailHost
        XCTAssertEqual(controller.splitViewItems[0].behavior, .sidebar)
        XCTAssertEqual(controller.splitViewItems[0].collapseBehavior, .preferResizingSiblingsWithFixedSplitView)
        for _ in 0..<8 {
            controller.splitViewItems[0].isCollapsed.toggle()
            window.contentView?.layoutSubtreeIfNeeded()
            controller.update(controls())
            XCTAssertTrue(window.toolbar === toolbar)
            XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), identities)
            XCTAssertEqual(window.frame, frame)
            XCTAssertTrue(controller.sidebarHost === sidebar)
            XCTAssertTrue(controller.detailHost === detail)
        }
        XCTAssertEqual(Set(toolbar.items.map(\.itemIdentifier)).count, toolbar.items.count)
    }
    func testSectionChangesAndSigningLockDoNotDuplicateCommands() throws {
        let (window, controller) = host()
        defer { window.contentViewController = nil }
        let toolbar = try XCTUnwrap(window.toolbar)
        let originalItems = toolbar.items.map(ObjectIdentifier.init)
        for _ in 0..<4 {
            controller.update(controls(add: false, back: true))
            XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), originalItems)
            if #available(macOS 15, *) {
                XCTAssertTrue(toolbar.items.first { $0.itemIdentifier.rawValue == "signum.add" }!.isHidden)
                XCTAssertFalse(toolbar.items.first { $0.itemIdentifier.rawValue == "signum.back" }!.isHidden)
            }
            XCTAssertEqual(toolbar.items.filter { $0.itemIdentifier.rawValue == "signum.settings" }.count, 1)
            XCTAssertEqual(toolbar.items.filter { $0.itemIdentifier.rawValue == "signum.back" }.count, 1)
            controller.update(controls())
            XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), originalItems)
            XCTAssertEqual(toolbar.items.filter { $0.itemIdentifier.rawValue == "signum.add" }.count, 1)
        }
        controller.update(controls(locked: true))
        let before = controller.splitViewItems[0].isCollapsed
        controller.toggleSidebar(nil)
        XCTAssertEqual(controller.splitViewItems[0].isCollapsed, before)
        XCTAssertTrue(toolbar.items.filter { $0.action != nil }.allSatisfy { !$0.isEnabled })
    }
    func testHostingControllersCannotTakeOwnershipOfSceneToolbars() {
        let (window, controller) = host()
        defer { window.contentViewController = nil }
        if #available(macOS 14, *) {
            XCTAssertTrue(controller.sidebarHost.sceneBridgingOptions.isEmpty)
            XCTAssertTrue(controller.detailHost.sceneBridgingOptions.isEmpty)
        }
        let main = SignumMainWindowController(content: AnyView(Text("Content")))
        defer { main.window?.contentViewController = nil }
        XCTAssertTrue(main.window?.windowController === main)
        XCTAssertTrue(main.window?.contentViewController === main.contentHost)
        if #available(macOS 14, *) { XCTAssertTrue(main.contentHost.sceneBridgingOptions.isEmpty) }
    }
    func testRepeatedSettingsTransitionsKeepExactlyTheSameItems() throws {
        let (window, controller) = host()
        defer { window.contentViewController = nil }
        let toolbar = try XCTUnwrap(window.toolbar)
        let original = toolbar.items.map(ObjectIdentifier.init)
        for _ in 0..<40 {
            controller.update(controls(add: false, back: true))
            window.contentView?.layoutSubtreeIfNeeded()
            controller.update(controls(add: true, back: false))
            window.contentView?.layoutSubtreeIfNeeded()
            XCTAssertTrue(window.toolbar === toolbar)
            XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), original)
        }
    }
    func testContentRefreshRetainsHostingRootAndOnlyOwnedWindowCloseCancels() {
        let (window, controller) = host()
        defer { window.contentViewController = nil }
        let store = controller.detailHost.rootView.store
        var cancellations = 0
        var configuration = controls()
        configuration.close = { cancellations += 1 }
        controller.update(configuration)
        for index in 0..<6 {
            controller.detailContent.content = AnyView(Text("Result \(index)"))
            XCTAssertTrue(controller.detailHost.rootView.store === store)
        }
        NotificationCenter.default.post(name: NSWindow.willCloseNotification, object: NSObject())
        XCTAssertEqual(cancellations, 0)
        NotificationCenter.default.post(name: NSWindow.willCloseNotification, object: window)
        XCTAssertEqual(cancellations, 1)
    }
}
