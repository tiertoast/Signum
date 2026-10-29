import XCTest
import SwiftUI
import AppKit
import Combine
@testable import SignumApp

@MainActor final class HostedPublicationLifecycleTests: XCTestCase {
    private func repeated(_ name: String = #function, _ body: () async throws -> Void) async throws {
        let count = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1, count) {
            let before = testRun?.failureCount ?? 0
            try await body()
            print("PHASE3_REPEAT \(name) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-before)")
        }
    }
    private func fence() async {
        let done = expectation(description: "main queue publication checkpoint")
        DispatchQueue.main.async { done.fulfill() }
        await fulfillment(of: [done], timeout: 3)
    }
    func testFixturePublicationAndStableNativeHosts() async throws {
        try await repeated {
            let (window, controller) = NativeWorkspaceTests().host()
            defer { window.contentViewController = nil }
            let published = expectation(description: "actual content store publication")
            let host = controller.detailHost, store = host.rootView.store
            let toolbar = try XCTUnwrap(window.toolbar), items = toolbar.items.map(ObjectIdentifier.init)
            let observation = store.objectWillChange.sink { published.fulfill() }
            controller.detailContent.content = AnyView(Text("Fixture updated"))
            await fulfillment(of: [published], timeout: 3)
            XCTAssertTrue(controller.detailHost === host); XCTAssertTrue(host.rootView.store === store)
            XCTAssertTrue(window.toolbar === toolbar); XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), items)
            withExtendedLifetime(observation) {}
        }
    }
    func testContentSetterDoesNotPublishInsideRepresentableAssignment() async throws {
        try await repeated {
            let store = SignumHostedContentStore(AnyView(Text("Initial")))
            let publication = expectation(description: "deferred publication")
            var assigning = false
            let observation = store.objectWillChange.sink {
                XCTAssertFalse(assigning, "updateNSViewController uses this same content setter; it must return before publishing")
                publication.fulfill()
            }
            assigning = true
            store.content = AnyView(Text("Next"))
            assigning = false
            await fulfillment(of: [publication], timeout: 3)
            withExtendedLifetime(observation) {}
        }
    }
    func testRapidContentAssignmentsPublishOnlyLatestValueOnce() async throws {
        try await repeated {
            let store = SignumHostedContentStore(AnyView(Text("Initial")))
            var publications = 0
            let observation = store.objectWillChange.sink { publications += 1 }
            for index in 0..<12 { store.content = AnyView(Text("Value \(index)")) }
            await fence()
            XCTAssertEqual(publications, 1)
            let appeared = expectation(description: "latest value reaches retained host")
            // Give the coalesced last value an observable appearance checkpoint.
            store.content = AnyView(Text("Latest").onAppear { appeared.fulfill() })
            let host = NSHostingView(rootView: SignumHostedContent(store: store))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = host; window.orderFront(nil)
            defer { window.close() }
            await fulfillment(of: [appeared], timeout: 3)
            withExtendedLifetime(observation) {}
        }
    }
    func testDismantleInvalidatesQueuedPublicationAndFutureAssignments() async throws {
        try await repeated {
            let (window, controller) = NativeWorkspaceTests().host()
            defer { window.contentViewController = nil }
            var publications = 0, closes = 0
            var controls = NativeWorkspaceTests().controls(); controls.close = { closes += 1 }; controller.update(controls)
            let observation = controller.detailContent.objectWillChange.sink { publications += 1 }
            controller.detailContent.content = AnyView(Text("Queued"))
            SignumNativeWorkspace.dismantleNSViewController(controller, coordinator: ())
            SignumNativeWorkspace.dismantleNSViewController(controller, coordinator: ())
            controller.detailContent.content = AnyView(Text("Late callback"))
            await fence()
            XCTAssertEqual(publications, 0); XCTAssertEqual(closes, 1)
            withExtendedLifetime(observation) {}
        }
    }
    func testSettingsTabViewTransitionsKeepNativeToolbarAndHosts() async throws {
        try await repeated {
            let (window, controller) = NativeWorkspaceTests().host()
            defer { window.contentViewController = nil }
            let toolbar = try XCTUnwrap(window.toolbar), items = toolbar.items.map(ObjectIdentifier.init)
            let sidebar = controller.sidebarHost, detail = controller.detailHost
            for index in 0..<4 {
                let appeared = expectation(description: "settings TabView mounted \(index)")
                controller.detailContent.content = AnyView(TabView {
                    Text("General \(index)").tabItem { Text("General") }
                    Text("Devices").tabItem { Text("Devices") }
                }.frame(width: 710, height: 500).onAppear { appeared.fulfill() })
                await fulfillment(of: [appeared], timeout: 3)
                controller.detailContent.content = AnyView(Text("Documents"))
                await fence()
                XCTAssertTrue(controller.sidebarHost === sidebar); XCTAssertTrue(controller.detailHost === detail)
                XCTAssertTrue(window.toolbar === toolbar); XCTAssertEqual(toolbar.items.map(ObjectIdentifier.init), items)
            }
        }
    }
}
