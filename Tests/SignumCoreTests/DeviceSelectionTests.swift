#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class DeviceSelectionTests: XCTestCase {
    func provider(_ id: String = "bit4id", der: Data, slot: UInt = 7, serial: String = "SAME", certificateID: UInt8 = 1) -> DiscoveredMiddleware {
        var stat = stat(); stat.st_dev = 1; stat.st_ino = id == "bit4id" ? 1 : 2
        let path = "/synthetic/\(id).dylib"
        let token = SignumToken(slot: slot, label: "Same label", manufacturer: "Synthetic", model: "Mock", reader: "Reader", serial: serial)
        return .init(id: id, definition: .init(id: id, name: id, manufacturer: "Test", candidatePaths: [path]), origin: .known,
            candidatePath: path, inspection: .init(canonicalPath: path, identity: .init(stat)), status: .ready,
            tokens: [.init(token: token, certificates: [.init(certificate: .init(label: "DS3 same label", identifier: Data([certificateID])), der: der)], certificateState: .readable)], version: "1.0", unavailableSlots: 0)
    }
    func testSameDERHasDistinctExplicitRoutesAcrossProvidersAndSlots() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let groups = DeviceCertificate.collect([provider(der: der), provider("opensc", der: der), provider(der: der, slot: 99)])
        XCTAssertEqual(groups.count, 1); XCTAssertEqual(groups[0].routes.count, 3)
        XCTAssertEqual(Set(groups[0].routes.map(\.id)).count, 3)
        XCTAssertEqual(groups[0].routes.map(\.providerPath), ["/synthetic/bit4id.dylib", "/synthetic/opensc.dylib", "/synthetic/bit4id.dylib"])
    }
    func testNamesakesLabelsAndSerialsDoNotMergeDifferentCertificates() throws {
        let fixture = try CertificateEligibilityTests.fixtures.get()
        let groups = DeviceCertificate.collect([provider(der: fixture.der("valid")), provider("opensc", der: fixture.der("replaced"))])
        XCTAssertEqual(groups.count, 2)
        XCTAssertEqual(groups[0].routes[0].title, groups[1].routes[0].title)
        XCTAssertNotEqual(groups[0].id, groups[1].id)
    }
    func testEligibleAuthenticationExpiredAmbiguousRemainDistinctAndNeverPreselected() throws {
        let fixture = try CertificateEligibilityTests.fixtures.get()
        let names = ["valid", "authentication", "expired", "wrongKU", "missingKU"]
        let providers = try names.enumerated().map { provider("test\($0.offset)", der: try fixture.der($0.element)) }
        var state = DeviceSelection(); let request = state.beginDiscovery()
        XCTAssertTrue(state.accept(providers, request: request)); XCTAssertNil(state.selectedRoute)
        let routes = state.certificates.flatMap(\.routes)
        XCTAssertEqual(routes.filter { $0.assessment.permitsSigning }.count, 1)
        XCTAssertTrue(routes.contains { $0.purpose.contains("autenticazione") })
        XCTAssertTrue(routes.contains { $0.assessment.status == .indeterminate })
        XCTAssertTrue(state.select(routeID: routes.first?.id)); XCTAssertNotNil(state.selectedRoute)
    }
    func testRemovalReinsertChangedSlotAndProviderNeverRestoreOldSelection() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        var selection = DeviceSelection(); let first = selection.beginDiscovery()
        selection.accept([provider(der: der)], request: first)
        let old = try XCTUnwrap(selection.certificates.first?.routes.first?.id)
        selection.select(routeID: old); XCTAssertNotNil(selection.selectedRoute)
        let removed = selection.beginDiscovery(); XCTAssertNil(selection.selectedRoute)
        selection.accept([], request: removed); XCTAssertTrue(selection.certificates.isEmpty)
        let reinsert = selection.beginDiscovery()
        XCTAssertFalse(selection.accept([provider(der: der)], request: first))
        selection.accept([provider("opensc", der: der, slot: 99)], request: reinsert)
        XCTAssertNil(selection.selectedRoute); XCTAssertFalse(selection.select(routeID: old))
        XCTAssertTrue(selection.select(routeID: selection.certificates[0].routes[0].id))
        XCTAssertEqual(selection.selectedRoute?.providerPath, "/synthetic/opensc.dylib")
        XCTAssertEqual(selection.selectedRoute?.token.slot, 99)
    }
    func testModuleChangedAfterChoiceRequiresFreshDiscovery() throws {
        let mock = try MockModule(), der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let inspection = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let original = provider(der: der)
        let manual = DiscoveredMiddleware(id: "manual", definition: original.definition, origin: .manual, candidatePath: mock.path.path,
            inspection: inspection, status: .ready, tokens: original.tokens, version: nil, unavailableSlots: 0)
        let route = try XCTUnwrap(DeviceCertificate.collect([manual]).first?.routes.first)
        try route.requireCurrentModule()
        let replacement = mock.folder.appendingPathComponent("replacement")
        try Data("replacement".utf8).write(to: replacement)
        XCTAssertEqual(rename(replacement.path, mock.path.path), 0)
        XCTAssertThrowsError(try route.requireCurrentModule())
    }
    func testWorkerReadsSerialThroughPublicScan() throws {
        let mock = try MockModule()
        let executable = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
        let scan = try IsolatedPKCS11Client(executable: executable).scan(provider: mock.path.path)
        XCTAssertEqual(scan.tokens.first?.serial, "SYNTHETIC-0001")
        XCTAssertNil(scan.version) // synthetic module deliberately has no C_GetInfo
    }
}
#endif
