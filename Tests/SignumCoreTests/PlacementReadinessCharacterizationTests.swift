#if os(macOS)
import XCTest
import SwiftUI
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class PlacementReadinessCharacterizationTests: XCTestCase {
    func testDuplicatePaintCompletionIsDeduplicatedWithoutNewRasterization() async throws {
        let count = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1, count) {
            let before = testRun?.failureCount ?? 0
            let root = try FixtureFiles.directory("readiness-characterization")
            defer { try? FileManager.default.removeItem(at: root) }
            let crop = CGRect(x: 0, y: 0, width: 595, height: 842), file = root.appendingPathComponent("synthetic.pdf")
            try PAdESGeometryStabilizationTests.pdf(media: crop, vectors: 100).write(to: file)
            let snapshot = try DocumentSnapshot.capture(source: file, format: .pades); defer { snapshot.close() }
            var config = PAdESAppearanceConfiguration(); config.showSigner = false
            let artwork = try PAdESAppearanceRenderer.render(config, certificateDER: Data(), cropBox: crop)
            var placement: PAdESPlacement? = .init(pageIndex: 0, rectangle: config.rectangle, appearance: artwork)
            let initial = expectation(description: "real pane is ready")
            var ready = 0, initialDelivered = false
            let renderer = PAdESRenderCoordinator()
            let pane = PAdESPlacementPane(snapshot: snapshot, previewReady: { _, value in
                guard value else { return }; ready += 1
                if !initialDelivered { initialDelivered = true; initial.fulfill() }
            }, holder: "Synthetic", placement: Binding(get: { placement }, set: { placement = $0 }), renderCoordinator: renderer)
            let host = NSHostingView(rootView: pane)
            let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 850, height: 700), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = host; window.orderFront(nil)
            defer { window.close() }
            await fulfillment(of: [initial], timeout: 5)
            let view = try XCTUnwrap(PAdESGeometryStabilizationTests().descendants(host).compactMap { $0 as? PlacementPDFView }.first)
            let draws = view.signatureOverlay.artworkView.drawCount, builds = view.signatureOverlay.artworkBuildCount, renders = renderer.started
            let hash = placement?.appearance?.sha256, identity = placement?.appearance?.approvalIdentity, priorReady = ready
            XCTAssertNotNil(view.signatureOverlay.artworkView.didDraw)
            let actualDisplayed = try XCTUnwrap(view.signatureOverlay.displayed)
            var notifications = 0
            view.signatureOverlay.displayed = { identity, error in notifications += 1; actualDisplayed(identity, error) }
            XCTAssertTrue(view.signatureOverlay.artworkView.hasPainted)
            view.signatureOverlay.artworkView.didDraw?(); view.signatureOverlay.artworkView.didDraw?()
            XCTAssertEqual(notifications, 2)
            let fence = expectation(description: "all queued display callbacks drained")
            DispatchQueue.main.async { fence.fulfill() }
            await fulfillment(of: [fence], timeout: 3)
            XCTAssertEqual(ready, priorReady)
            XCTAssertEqual(view.signatureOverlay.artworkView.drawCount, draws)
            XCTAssertEqual(view.signatureOverlay.artworkBuildCount, builds); XCTAssertEqual(renderer.started, renders)
            XCTAssertEqual(placement?.appearance?.sha256, hash); XCTAssertEqual(placement?.appearance?.approvalIdentity, identity)
            print("PHASE3_READINESS iteration=\(iteration) ready_delta=\(ready-priorReady) raster_delta=\(view.signatureOverlay.artworkView.drawCount-draws) render_delta=\(renderer.started-renders)")
            print("PHASE3_REPEAT \(#function) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-before)")
        }
    }
}
#endif
