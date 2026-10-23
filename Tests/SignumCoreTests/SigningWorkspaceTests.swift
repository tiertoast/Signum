#if os(macOS)
import XCTest
import AppKit
import SwiftUI
import PDFKit
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

/// Render only our own views with injected public fixture metadata. Never launch
/// Signum.app or load installed middleware. These are not interactive click tests.
@MainActor final class SigningWorkspaceTests: XCTestCase {
    private func descendants(_ root: NSView) -> [NSView] { [root] + root.subviews.flatMap { descendants($0) } }
    private func fixture(_ body: (URL, UserDefaults, BatchSigningCoordinator, DeviceSelection, ProviderSelection, Data) async throws -> Void) async throws {
        guard !NSScreen.screens.isEmpty else { throw XCTSkip("Native layout rendering requires WindowServer") }
        _ = NSApplication.shared
        let name = "Signum.synthetic.workspace." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        var devices = DeviceSelection(); let request = devices.beginDiscovery()
        devices.accept([DeviceSelectionTests().provider(der: der)], request: request)
        devices.select(routeID: devices.certificates[0].routes[0].id)
        var provider = ProviderSelection(); provider.select(route: try XCTUnwrap(devices.selectedRoute))
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        try await body(root, defaults, batch, devices, provider, der)
    }
    private func render(_ view: SignumWindow, name: String, ready: @MainActor (NSHostingView<SignumWindow>) -> Bool = { @MainActor in !$0.subviews.isEmpty }, verify: @MainActor (NSHostingView<SignumWindow>) throws -> Void) async throws {
        let frame = NSRect(x: 0, y: 0, width: 1100, height: 760)
        let window = NSWindow(contentRect: frame, styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let host = NSHostingView(rootView: view); host.frame = frame; window.contentView = host
        host.wantsLayer = true; host.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        defer { window.close() }
        window.orderFront(nil)
        host.layoutSubtreeIfNeeded()
        // Yield the MainActor to the owned preview Task; a nested synchronous
        // RunLoop keeps the current actor job occupied and cannot observe it.
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        repeat {
            try await Task.sleep(nanoseconds: 10_000_000)
            host.layoutSubtreeIfNeeded()
        } while !ready(host) && ProcessInfo.processInfo.systemUptime < deadline
        XCTAssertTrue(ready(host), "Workspace did not reach its required observable state")
        host.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        try verify(host)
        let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        let bytes = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        let folder = try FixtureFiles.directory("signing-workspace",evidence:true)
        try bytes.write(to: folder.appendingPathComponent(name + ".png"))
    }
    func test07SectionsAndExpandedOptionsRenderAtMinimumSizeInBothAppearances() async throws {
        try await fixture { _, defaults, batch, devices, provider, _ in
            for appearance in [NSAppearance.Name.aqua, .darkAqua] {
                for section in SignumSection.allCases {
                    let frame = NSRect(x: 0, y: 0, width: 980, height: 650)
                    let window = NSWindow(contentRect: frame, styleMask: [.titled, .resizable], backing: .buffered, defer: false)
                    window.isReleasedWhenClosed = false
                    let previousAppearance = NSApp.appearance
                    NSApp.appearance = NSAppearance(named: appearance)
                    defer { NSApp.appearance = previousAppearance }
                    window.appearance = NSAppearance(named: appearance)
                    let view = SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider,
                        automaticallyDiscover: false, defaults: defaults, initialSection: section,
                        initiallyExpandedDetails: true)
                    let host = NSHostingView(rootView: view.environment(\.colorScheme, appearance == .darkAqua ? .dark : .light))
                    host.wantsLayer = true
                    host.frame = frame; window.contentView = host; window.orderFront(nil)
                    defer { window.close() }
                    try await Task.sleep(nanoseconds: 150_000_000)
                    host.layoutSubtreeIfNeeded(); window.displayIfNeeded()
                    // NavigationSplitView installs its titlebar after presentation.
                    // Resize the content once that native toolbar is installed.
                    window.setContentSize(frame.size)
                    host.layoutSubtreeIfNeeded()
                    XCTAssertEqual(host.bounds.width, 980, accuracy: 1)
                    XCTAssertEqual(host.bounds.height, 650, accuracy: 1)
                    XCTAssertFalse(descendants(host).compactMap { $0 as? NSSplitView }.isEmpty,
                                   "Native sidebar must remain present")
                    XCTAssertFalse(batch.isApproved); XCTAssertFalse(batch.isRunning)
                }
            }
        }
    }

    func testPINIsReachableWithoutScrollingThirtyTwoDocuments() async throws {
        try await fixture { root, defaults, batch, devices, provider, der in
            let files = try (1...32).map { number -> URL in
                let file = root.appendingPathComponent("synthetic-\(number).txt")
                try Data("Synthetic approved file \(number)".utf8).write(to: file); return file
            }
            await batch.addDocuments(files, format: .cades)
            let approval = try await batch.prepareApproval(provider: "/synthetic/bit4id.dylib", slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: der)
            try batch.confirm(approval)
            try await render(SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider,
                automaticallyDiscover: false, defaults: defaults), name: "pin-32-documents", ready: { self.descendants($0).contains { $0 is NSSecureTextField } }) { host in
                let fields = descendants(host).compactMap { $0 as? NSSecureTextField }
                XCTAssertEqual(fields.count, 1)
                let field = try XCTUnwrap(fields.first)
                XCTAssertTrue(field.stringValue.isEmpty)
                let rectangle = field.convert(field.bounds, to: host)
                XCTAssertTrue(host.bounds.contains(rectangle), "PIN field must be within the visible workspace")
                XCTAssertFalse(field.isHiddenOrHasHiddenAncestor)
                host.window?.setContentSize(NSSize(width: 1100, height: 650))
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.1))
                XCTAssertTrue(host.bounds.contains(field.convert(field.bounds, to: host)), "PIN remains visible at the minimum window height")
                // No scrolling ancestor: the PIN is outside the sidebar scroll.
                var ancestor = field.superview
                while let current = ancestor {
                    XCTAssertFalse(current is NSScrollView, "PIN should not scroll with the certificate/document list")
                    ancestor = current.superview
                }
            }
            XCTAssertTrue(batch.isApproved); XCTAssertFalse(batch.isRunning)
            XCTAssertTrue(approval.jobs.allSatisfy { !FileManager.default.fileExists(atPath: $0.destination.path) })
        }
    }
    func testPAdESWorkspaceRetainsRealPDFKitPreviewOfTheSnapshot() async throws {
        try await fixture { root, defaults, batch, devices, provider, _ in
            let bytes = NSMutableData(); let sink = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
            var box = CGRect(x: 0, y: 0, width: 400, height: 500)
            let context = try XCTUnwrap(CGContext(consumer: sink, mediaBox: &box, nil))
            context.beginPDFPage(nil); context.setFillColor(CGColor(gray: 0.6, alpha: 1))
            context.fill(CGRect(x: 30, y: 30, width: 50, height: 50)); context.endPDFPage(); context.closePDF()
            let file = root.appendingPathComponent("synthetic-preview.pdf"); try (bytes as Data).write(to: file)
            await batch.addDocuments([file], format: .pades)
            let snapshot = try XCTUnwrap(batch.documents.first?.snapshot)
            try await render(SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider, selectedSnapshot: snapshot,
                automaticallyDiscover: false, defaults: defaults), name: "pades-preview", ready: { self.descendants($0).compactMap { $0 as? PDFView }.first?.document?.pageCount == 1 }) { host in
                let preview = try XCTUnwrap(descendants(host).compactMap { $0 as? PDFView }.first)
                XCTAssertEqual(preview.document?.pageCount, 1)
                XCTAssertNotEqual(preview.document?.documentURL?.path, file.path)
                XCTAssertTrue(host.bounds.intersects(preview.convert(preview.bounds, to: host)))
                XCTAssertEqual(try snapshot.verifiedBytes(), bytes as Data)
            }
        }
    }
    func testCompactFailureWorkspaceHasNoPINAndKeepsErrorDetails() async throws {
        try await fixture { root, defaults, batch, devices, provider, der in
            let source = root.appendingPathComponent("synthetic-long-document-name-for-workspace-layout.txt")
            try Data("Synthetic failure workspace".utf8).write(to: source)
            await batch.addDocuments([source], format: .cades)
            let plan = try await batch.prepareApproval(provider: "/synthetic/bit4id.dylib", slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: der)
            try batch.confirm(plan)
            try await batch.authorizeNext(pin: "synthetic-ui") { _, _, _ in throw SignumError.module("Synthetic error details") }
            let receipts = SigningSessionResults()
            try await render(SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider,
                automaticallyDiscover: false, defaults: defaults, sessionResults: receipts), name: "compact-error") { host in
                XCTAssertTrue(descendants(host).contains { $0 is NSScrollView })
                XCTAssertFalse(descendants(host).contains { $0 is NSSecureTextField })
            }
            XCTAssertFalse(batch.isFrozen)
            XCTAssertTrue(batch.documents.isEmpty)
            XCTAssertEqual(receipts.receipts.first?.state, .failed)
            XCTAssertTrue(receipts.receipts.first?.detail.contains("Synthetic error details") == true)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path))
        }
    }
}
#endif
