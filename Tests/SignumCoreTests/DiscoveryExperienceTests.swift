#if os(macOS)
import XCTest
@testable import SignumApp
@testable import SignumCore

final class DiscoveryExperienceTests: XCTestCase {
    func testRememberedManualPathsRemainBoundedValidatedAndRequireExplicitLoad() throws {
        let name = "Signum.synthetic.discovery." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let preferences = MiddlewarePreferences(defaults: defaults)
        preferences.remember("/synthetic/a.dylib"); preferences.remember("relative"); preferences.remember("/bad/../module")
        preferences.remember("/bad\0module"); preferences.remember("/synthetic/a.dylib")
        XCTAssertEqual(preferences.paths, ["/synthetic/a.dylib"])
        for index in 0..<10 { preferences.remember("/synthetic/\(index).so") }
        XCTAssertEqual(preferences.paths.count, 8)
        preferences.prefer("/synthetic/9.so"); XCTAssertEqual(preferences.preferredPath, "/synthetic/9.so")
        preferences.remove("/synthetic/9.so"); XCTAssertNil(preferences.preferredPath)
        XCTAssertFalse(preferences.paths.contains("/synthetic/9.so"))
        // New selection cannot acquire a route from stored configuration alone.
        XCTAssertNil(DeviceSelection().selectedRoute)
        XCTAssertEqual(Set(defaults.persistentDomain(forName: name)?.keys.map { $0 } ?? []), ["signum.discovery.manualPaths.v1"])
    }
    func testExplicitRouteSelectionClearsOldPinAndBindsProviderSlotAndDER() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let first = DeviceSelectionTests().provider(der: der)
        let second = DeviceSelectionTests().provider("opensc", der: der, slot: 23)
        let routes = DeviceCertificate.collect([first, second])[0].routes
        var selection = ProviderSelection()
        selection.select(route: routes[0]); selection.pin = "synthetic-not-a-personal-pin"
        selection.select(route: routes[1])
        XCTAssertEqual(selection.signingProvider, routes[1].providerPath)
        XCTAssertEqual(selection.selectedSlot, 23); XCTAssertEqual(selection.certificateDERs["01"], der)
        XCTAssertEqual(selection.selectedCertificateID, "01"); XCTAssertTrue(selection.pin.isEmpty)
    }
    func testShortSourceLabelsDistinguishNamesakesWithIdenticalImmediateParents() {
        let a = URL(fileURLWithPath: "/synthetic/clientA/attachments/report.txt")
        let b = URL(fileURLWithPath: "/synthetic/clientB/attachments/report.txt")
        XCTAssertEqual(BatchDisplay.sourceLabel(a, among: [a,b]), "clientA / attachments")
        XCTAssertEqual(BatchDisplay.sourceLabel(b, among: [a,b]), "clientB / attachments")
        XCTAssertEqual(BatchDisplay.sourceLabel(a, among: [a]), "attachments")
        XCTAssertEqual(BatchDisplay.destinationLabel(URL(fileURLWithPath: "/synthetic/output/report.p7m")), "output / report.p7m")
    }
    func testIneligibleRouteCanBeInspectedButCannotPermitApproval() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("authentication")
        let route = try XCTUnwrap(DeviceCertificate.collect([DeviceSelectionTests().provider(der: der)]).first?.routes.first)
        var provider = ProviderSelection(); provider.select(route: route)
        XCTAssertNotNil(provider.selectedCertificateID)
        XCTAssertFalse(try XCTUnwrap(provider.certificateAssessments["01"]).permitsSigning)
    }
}
#endif
