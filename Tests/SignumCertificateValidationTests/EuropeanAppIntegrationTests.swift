import XCTest
import SwiftUI
import AppKit
import SignumCore
@testable import SignumTrustAuthentication
import SignumTrustIntegration
@testable import SignumCertificateValidation
@testable import SignumApp

final class EuropeanAppIntegrationTests: XCTestCase {
    func data(_ name: String, _ ext: String = "xml", folder: String = "E2") throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures/" + folder)))
    }
    func clock() throws -> Date {
        let value = try JSONDecoder().decode([String:String].self, from: data("clock", "json", folder: "E1R"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from: value["evaluatedAt"]!))
    }
    func setup() throws -> (URL, E2Transport, EuropeanTrustCatalogService) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("signum-e4-" + UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let net = E2Transport([EUTrustPolicy.location: try data("europe"), EUTrustPolicy.italyLocation: try data("IT"),
                               "https://tl.example.test/AT.xml": try data("AT")])
        let service = EuropeanTrustCatalogService(directory: directory, transport: net, anchors: [TLAuthenticator.sha256(try data("signer0", "der"))])
        return (directory, net, service)
    }
    @MainActor func settle(_ model: TrustedListsModel) async throws {
        let end = Date().addingTimeInterval(90)
        while model.isRefreshing && Date() < end { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertFalse(model.isRefreshing)
    }
    @MainActor func testSelectiveSettingsAndFailedRefreshRetainItalianCache() async throws {
        let (directory, net, service) = try setup(), at = try clock()
        let model = TrustedListsModel(europeanService: service, directory: directory, clock: { at })
        model.checkForUpdates(); try await settle(model)
        XCTAssertTrue(model.isEuropean); XCTAssertEqual(model.acquiredCountries, ["IT"])
        XCTAssertTrue(model.availableCountries.contains("DE")); XCTAssertEqual(model.status, .current)
        XCTAssertNotNil(model.countryExpiries["IT"])
        model.selectedCountry = "AT"; model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.acquiredCountries, ["AT", "IT"])
        let requests = await net.requests
        XCTAssertFalse(requests.contains { $0.contains("DE.xml") || $0.contains("BE.xml") })
        let original = try Data(contentsOf: directory.appendingPathComponent("AT.json"))
        await net.set("https://tl.example.test/AT.xml", Data("<altered/>".utf8))
        model.checkForUpdates(); try await settle(model)
        XCTAssertEqual(model.status, .current); XCTAssertNotNil(model.message)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("AT.json")), original)
        XCTAssertNotNil(model.countryExpiries["IT"]); model.stop()
    }
    @MainActor func testOfflineRestartExpiryAndUnavailableAreExplicit() async throws {
        let (directory, net, service) = try setup(), at = try clock()
        _ = try await service.refresh(countries: ["IT"], now: at)
        await net.configure(offline: true)
        let requests = await net.requests
        let restarted = EuropeanTrustCatalogService(directory: directory, transport: net, anchors: [TLAuthenticator.sha256(try data("signer0", "der"))])
        let model = TrustedListsModel(europeanService: restarted, directory: directory, offline: true, clock: { at })
        model.start()
        let end = Date().addingTimeInterval(30)
        while model.lastVerifiedUpdate == nil && Date() < end { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertEqual(model.status, .current); XCTAssertEqual(model.acquiredCountries, ["IT"])
        XCTAssertNotNil(model.catalogProvider as? any EuropeanCatalogProviding)
        model.stop()
        let future = at.addingTimeInterval(400 * 86400)
        let expired = TrustedListsModel(europeanService: restarted, directory: directory, offline: true, clock: { future })
        expired.checkForUpdates(); try await settle(expired)
        XCTAssertEqual(expired.status, .expired); XCTAssertEqual(expired.acquiredCountries, ["IT"])
        XCTAssertTrue(expired.countryExpiries.isEmpty); expired.stop()
        let missing = TrustedListsModel(europeanService: try EuropeanTrustCatalogService(directory: directory.appendingPathComponent("absent")), offline: true)
        missing.checkForUpdates(); try await settle(missing)
        XCTAssertEqual(missing.status, .error); XCTAssertNil(missing.lastVerifiedUpdate); missing.stop()
        let after = await net.requests; XCTAssertEqual(requests, after)
    }
    @MainActor func testWorkspaceUsesEuropeanProviderAndKeepsFiveResultsOffline() async throws {
        let (directory, net, service) = try setup(), at = try clock()
        _ = try await service.refresh(countries: ["IT"], now: at)
        await net.configure(offline: true)
        let model = TrustedListsModel(europeanService: service, directory: directory, offline: true, clock: { at })
        let workspace = VerificationWorkspace(catalog: model.catalogProvider, validationClock: { at })
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        for ext in ["cms", "pdf"] {
            let document = try data("multi", ext, folder: "E1R")
            let report = try SignumVerificationService.verify(data: document, name: "multi." + ext, helper: URL(fileURLWithPath: helper))
            await workspace.verify([directory.appendingPathComponent("multi." + ext)], using: { _, _ in report })
            let row = try XCTUnwrap(workspace.rows.first)
            XCTAssertEqual(row.report?.integrity, .verified)
            XCTAssertEqual(row.paths.count, 2); XCTAssertEqual(row.validations.count, 2)
            let q = try XCTUnwrap(row.validations.values.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(q.path.state, .verified); XCTAssertEqual(q.evidence.revocation.state, .good)
            XCTAssertEqual(q.evidence.time.state, .proven); XCTAssertEqual(q.qualification.state, .qualified, q.qualification.reason)
            XCTAssertEqual(q.qualification.service?.country, "IT")
            XCTAssertTrue(row.validations.values.contains { $0.qualification.state == .electronic })
        }
        XCTAssertEqual(model.acquiredCountries, ["IT"]); model.stop()
    }
    @MainActor func testEuropeanSettingsPaneRendersExistingNativeLayout() async throws {
        let (directory, _, service) = try setup(), at = try clock()
        let model = TrustedListsModel(europeanService: service, directory: directory, clock: { at })
        model.checkForUpdates(); try await settle(model)
        let view = NSHostingView(rootView: TrustedListsPane(model: model).padding(20).background(Color(NSColor.windowBackgroundColor)).environment(\.locale, Locale(identifier: "it_IT")))
        view.frame = NSRect(x: 0, y: 0, width: 1000, height: 600)
        let window = NSWindow(contentRect: view.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.title = "Signum — test pannello europeo"
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
        XCTAssertGreaterThan(colors.count, 20, "Settings must contain visible rendered content")
        if let path = ProcessInfo.processInfo.environment["SIGNUM_TEST_EVIDENCE_ROOT"] {
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
            try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: URL(fileURLWithPath: path).appendingPathComponent("european-settings.png"))
        }
        model.stop()
    }
}
