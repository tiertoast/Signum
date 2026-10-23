#if os(macOS)
import XCTest
@testable import SignumApp
@testable import SignumCore

final class DeviceRefreshLifecycleTests: XCTestCase {
    func testRefreshKeepsAutomaticOriginForAnUnchangedEligibleRoute() throws {
        let fixture = DeviceSelectionTests(), der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let provider = fixture.provider(der: der)
        var selection = DeviceSelection(); let first = selection.beginDiscovery()
        selection.acceptCompleteFixture([provider], request: first)
        let id = try XCTUnwrap(selection.selectedRouteID)
        XCTAssertEqual(selection.selectionOrigin, .automatic)
        var refresh = DeviceRefreshLifecycle()
        let request = try XCTUnwrap(refresh.begin(selection: &selection, blocked: false))
        XCTAssertTrue(refresh.accept(.init(providers: [provider], expectedPaths: [provider.candidatePath]), request: request, selection: &selection))
        XCTAssertEqual(selection.selectedRouteID, id)
        XCTAssertEqual(selection.selectionOrigin, .automatic)
        XCTAssertTrue(selection.selectionWasPreserved)
    }

    func testPublicRefreshPreservesValidSelectionAndRejectsOverlappingAndStaleResults() throws {
        let provider = DeviceSelectionTests().provider(der: try CertificateEligibilityTests.fixtures.get().der("valid"))
        var selection = DeviceSelection(); let initial = selection.beginDiscovery()
        selection.accept([provider], request: initial)
        let route = try XCTUnwrap(selection.certificates.first?.routes.first)
        selection.select(routeID: route.id)
        var refresh = DeviceRefreshLifecycle()
        XCTAssertNil(refresh.begin(selection: &selection, blocked: true))
        XCTAssertEqual(selection.selectedRouteID, route.id)
        let request = try XCTUnwrap(refresh.begin(selection: &selection, blocked: false))
        XCTAssertNil(refresh.begin(selection: &selection, blocked: false))
        let result = DeviceDiscoveryResult(providers: [provider])
        XCTAssertFalse(refresh.accept(result, request: initial, selection: &selection))
        XCTAssertTrue(refresh.accept(result, request: request, selection: &selection))
        XCTAssertEqual(selection.selectedRouteID, route.id)
        XCTAssertNil(refresh.requestID)
        let next = try XCTUnwrap(refresh.begin(selection: &selection, blocked: false))
        XCTAssertFalse(refresh.accept(result, request: request, selection: &selection))
        XCTAssertTrue(refresh.accept(DeviceDiscoveryResult(providers: []), request: next, selection: &selection))
        XCTAssertNil(selection.selectedRoute)
    }
}
#endif
