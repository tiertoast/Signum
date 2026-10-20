import XCTest
import SwiftUI
import AppKit
@testable import SignumApp
import SignumTrustAuthentication
@testable import SignumTrustIntegration

private actor Network: TLTransport {
    let eu: Data; let it: Data
    var offline = false; var altered = false
    init(eu: Data, it: Data) { self.eu = eu; self.it = it }
    func set(offline: Bool = false, altered: Bool = false) { self.offline = offline; self.altered = altered }
    func fetch(_ url: URL) async throws -> Data {
        if offline { throw URLError(.notConnectedToInternet) }
        if url.absoluteString == EUTrustPolicy.location { return altered ? Data("<altered/>".utf8) : eu }
        return it
    }
}
private actor ServiceAtTime: TrustedListsRefreshing {
    let real: TLRefreshService; let now: Date
    init(_ real: TLRefreshService, _ now: Date) { self.real = real; self.now = now }
    func cached(now: Date?) async throws -> TLRefreshView { try await real.cached(now: self.now) }
    func refresh(now: Date?, force: Bool) async throws -> TLRefreshView { try await real.refresh(now: self.now, force: force) }
    func runAutomatically(onUpdate: @Sendable (Result<TLRefreshView, Error>) async -> Void) async {
        do { await onUpdate(.success(try await cached(now: now))) } catch { await onUpdate(.failure(error)) }
        while !Task.isCancelled { do { try await Task.sleep(nanoseconds: 100_000_000) } catch { return } }
    }
    func cancelRefresh() async { await real.cancelRefresh() }
}
final class TrustedListsIntegrationTests: XCTestCase {
    let now = ISO8601DateFormatter().date(from: "2026-10-20T12:00:00Z")!
    func fixture(_ name: String) throws -> Data { try Data(contentsOf: Bundle.module.url(forResource: name, withExtension: "xml", subdirectory: "Fixtures")!) }
    private func setup() throws -> (URL, Network, TLRefreshService) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: folder) }
        let network = Network(eu: try fixture("eu-lotl"), it: try fixture("it"))
        let url = folder.appendingPathComponent("verified.json")
        return (url, network, try TLRefreshService(cacheURL: url, transport: network))
    }
    @MainActor func settle(_ model: TrustedListsModel) async throws {
        let deadline = Date().addingTimeInterval(120)
        while model.isRefreshing, Date() < deadline { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertFalse(model.isRefreshing)
    }
    @MainActor func testManualRefreshOfflineAndUnauthenticatedResponsePreserveVerifiedView() async throws {
        let (url, network, service) = try setup()
        let model = TrustedListsModel(service: service)
        XCTAssertEqual(model.status, .unavailable)
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .current); XCTAssertEqual(model.providerCount, 56); XCTAssertEqual(model.serviceCount, 562)
        XCTAssertNotNil(model.lastVerifiedUpdate); XCTAssertNotNil(model.expiresAt)
        let original = try Data(contentsOf: url)
        await network.set(offline: true)
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .current); XCTAssertNotNil(model.message)
        XCTAssertEqual(try Data(contentsOf: url), original)
        await network.set(altered: true)
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .current); XCTAssertNotNil(model.message)
        XCTAssertEqual(try Data(contentsOf: url), original)
        let catalog: any TrustedListCatalogProviding = service
        let authenticated = try await catalog.currentCatalog()
        XCTAssertEqual(authenticated?.document.territory, "IT")
        model.stop()
    }
    @MainActor func testExpiredOfflineCacheIsVisibleButNotAvailableAsCurrentCatalog() async throws {
        let (url, network, service) = try setup()
        try TLSnapshot.save(lotl: fixture("eu-lotl"), italy: fixture("it"), to: url, now: now)
        await network.set(offline: true)
        let future = ISO8601DateFormatter().date(from: "2027-04-01T00:00:00Z")!
        let adapter = ServiceAtTime(service, future), model = TrustedListsModel(service: ServiceAtTime(service, future))
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .expired); XCTAssertEqual(model.providerCount, 56)
        let view = try await adapter.cached(now: nil)
        XCTAssertNil(view.currentItaly); XCTAssertNil(view.currentEurope)
        model.stop()
    }
    @MainActor func testStartupLifecycleReadsCacheAndStopsWithoutLateUpdates() async throws {
        let (url, _, service) = try setup()
        try TLSnapshot.save(lotl: fixture("eu-lotl"), italy: fixture("it"), to: url, now: now)
        let model = TrustedListsModel(service: ServiceAtTime(service, now))
        model.start(); model.start()
        let deadline = Date().addingTimeInterval(120)
        while model.expiresAt == nil, Date() < deadline { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertEqual(model.status, .current)
        model.stop(); let last = model.lastVerifiedUpdate
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertFalse(model.isRefreshing); XCTAssertEqual(model.lastVerifiedUpdate, last)
    }
    @MainActor func testNativeSettingsPaneRendersAuthenticatedData() async throws {
        let (url, network, service) = try setup()
        try TLSnapshot.save(lotl: fixture("eu-lotl"), italy: fixture("it"), to: url, now: now)
        await network.set(offline: true)
        let model = TrustedListsModel(service: service)
        model.checkForUpdates(); try await settle(model)
        let view = NSHostingView(rootView: TrustedListsPane(model: model).padding(20).background(Color(NSColor.windowBackgroundColor)).environment(\.locale, Locale(identifier: "it_IT")))
        view.frame = NSRect(x: 0, y: 0, width: 940, height: 340)
        let window = NSWindow(contentRect: view.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.title = "Signum — test Elenchi fiduciari"
        window.contentView = view; window.orderFront(nil)
        defer { window.close() }
        try await Task.sleep(nanoseconds: 200_000_000)
        view.layoutSubtreeIfNeeded(); view.displayIfNeeded()
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        var colors = Set<Int>()
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 4) {
                if let c = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB), c.alphaComponent > 0.5 {
                    colors.insert(Int(c.redComponent * 255) * 65536 + Int(c.greenComponent * 255) * 256 + Int(c.blueComponent * 255))
                }
            }
        }
        XCTAssertGreaterThan(colors.count, 20, "Settings must render visible content, not an empty bitmap")
        XCTAssertEqual(model.status, .current); XCTAssertEqual(model.providerCount, 56)
        if let root = ProcessInfo.processInfo.environment["SIGNUM_TEST_EVIDENCE_ROOT"] {
            let folder = URL(fileURLWithPath: root)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: folder.appendingPathComponent("trusted-lists-settings.png"))
        }
        model.stop()
    }
    @MainActor func testNetworkAbsentWithoutCacheReportsErrorAndNoCatalog() async throws {
        let (_, network, service) = try setup(); await network.set(offline: true)
        let model = TrustedListsModel(service: service)
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .error); XCTAssertEqual(model.providerCount, 0); XCTAssertNil(model.lastVerifiedUpdate)
        XCTAssertTrue(model.message?.contains("connessione") == true); model.stop()
    }
}
