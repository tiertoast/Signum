#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

final class CertificateVisibilityTests: XCTestCase {
    func certificates() throws -> [DeviceCertificate] {
        let fixtures = try CertificateEligibilityTests.fixtures.get()
        return DeviceCertificate.collect(["valid", "authentication", "expired", "missingKU"].enumerated().map {
            DeviceSelectionTests().provider("synthetic\($0.offset)", der: fixtures.der($0.element))
        })
    }
    func testDefaultFilterOnlyContainsLocallyEligibleCertificates() throws {
        let filter = CertificateVisibility(try certificates())
        XCTAssertEqual(filter.visible(showExcluded: false).count, 1)
        XCTAssertTrue(filter.visible(showExcluded: false).allSatisfy { $0.routes[0].assessment.permitsSigning })
        XCTAssertEqual(filter.ineligible.count, 2); XCTAssertEqual(filter.indeterminate.count, 1)
    }
    func testExpandedFilterKeepsIneligibleAndIndeterminateDistinctWithReasons() throws {
        let filter = CertificateVisibility(try certificates())
        XCTAssertEqual(filter.visible(showExcluded: true).count, 4)
        XCTAssertTrue(filter.ineligible.allSatisfy { $0.routes[0].assessment.status == .ineligible && !$0.routes[0].assessment.reasons.isEmpty })
        XCTAssertTrue(filter.indeterminate.allSatisfy { $0.routes[0].assessment.status == .indeterminate && !$0.routes[0].assessment.permitsSigning })
    }
    func testPreferenceStartsOffAndPersistsWithoutCredentials() throws {
        let name = "Signum.synthetic.visibility." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let store = SigningExperiencePreferences(defaults: defaults)
        XCTAssertFalse(store.showExcluded); store.showExcluded = true
        XCTAssertTrue(SigningExperiencePreferences(defaults: defaults).showExcluded)
        XCTAssertEqual(defaults.persistentDomain(forName: name)?.count, 1)
    }
    func testExcludedSelectionCannotPermitSigningEvenWhenVisible() throws {
        let filter = CertificateVisibility(try certificates())
        for group in filter.ineligible + filter.indeterminate {
            let route = try XCTUnwrap(group.routes.first)
            XCTAssertFalse(filter.includes(route: route, showExcluded: false))
            XCTAssertTrue(filter.includes(route: route, showExcluded: true))
            var selection = ProviderSelection(); selection.select(route: route)
            XCTAssertFalse(try XCTUnwrap(selection.certificateAssessments[route.certificate.id]).permitsSigning)
            XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: route.der))
        }
    }
    func testRefreshNeverPreselectsAnExcludedCertificateOrChangesPolicy() throws {
        let fixture = try CertificateEligibilityTests.fixtures.get()
        var selection = DeviceSelection(); let request = selection.beginDiscovery()
        selection.acceptCompleteFixture([DeviceSelectionTests().provider(der: fixture.der("authentication"))], request: request)
        XCTAssertTrue(CertificateVisibility(selection.certificates).visible(showExcluded: false).isEmpty)
        XCTAssertNil(selection.selectedRoute)
        let refreshed = selection.beginDiscovery()
        selection.acceptCompleteFixture([DeviceSelectionTests().provider(der: fixture.der("valid"))], request: refreshed)
        XCTAssertEqual(CertificateVisibility(selection.certificates).visible(showExcluded: false).count, 1)
        XCTAssertEqual(selection.selectionOrigin,.automatic)
        XCTAssertTrue(selection.selectedRoute?.assessment.permitsSigning == true)
    }
}
#endif
