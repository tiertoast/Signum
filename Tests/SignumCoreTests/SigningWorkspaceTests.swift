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
    private func render(_ view: SignumWindow, name: String, verify: (NSHostingView<SignumWindow>) throws -> Void) throws {
        let frame = NSRect(x: 0, y: 0, width: 1100, height: 760)
        let window = NSWindow(contentRect: frame, styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let host = NSHostingView(rootView: view); host.frame = frame; window.contentView = host
        host.wantsLayer = true; host.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        defer { window.close() }
        window.orderFront(nil)
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
        host.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        try verify(host)
        let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        let bytes = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let folder = root.appendingPathComponent(".build/04a3-ui")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try bytes.write(to: folder.appendingPathComponent(name + ".png"))
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
            try render(SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider,
                automaticallyDiscover: false, defaults: defaults), name: "pin-32-documents") { host in
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
            try render(SignumWindow(batch: batch, initialDevices: devices, initialProvider: provider, selectedSnapshot: snapshot,
                automaticallyDiscover: false, defaults: defaults), name: "pades-preview") { host in
                let preview = try XCTUnwrap(descendants(host).compactMap { $0 as? PDFView }.first)
                XCTAssertEqual(preview.document?.pageCount, 1)
                XCTAssertNotEqual(preview.document?.documentURL?.path, file.path)
                XCTAssertTrue(host.bounds.intersects(preview.convert(preview.bounds, to: host)))
                XCTAssertEqual(try snapshot.verifiedBytes(), bytes as Data)
            }
        }
    }
}
#endif
