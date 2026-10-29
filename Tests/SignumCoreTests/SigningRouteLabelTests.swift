#if os(macOS)
import XCTest
@testable import SignumApp
@testable import SignumCore

final class SigningRouteLabelTests: XCTestCase {
    func token(label: String = "", model: String = "", reader: String = "") -> SignumToken {
        .init(slot: 7, label: label, manufacturer: "Test", model: model, reader: reader)
    }
    func testObservedDeviceMetadataAndUnknownFallback() {
        XCTAssertEqual(SigningRouteLabel.device(token: token(model: "Digital-DNA")), "DigitalDNA")
        XCTAssertEqual(SigningRouteLabel.device(token: token(label: "CNS")), "Smart card CNS")
        XCTAssertEqual(SigningRouteLabel.device(token: token(reader: "Smart Card Reader")), "Smart card")
        XCTAssertEqual(SigningRouteLabel.device(token: token(model: "USB Token")), "Token USB")
        XCTAssertEqual(SigningRouteLabel.device(token: token(model: "Observed model")), "Observed model")
        XCTAssertEqual(SigningRouteLabel.device(token: token()), "Dispositivo PKCS#11")
    }
    func testSameCertificateUsesSelectedRouteAndPresentationCannotChangeBinding() throws {
        let fixture = DeviceSelectionTests()
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let a = fixture.provider("A", der: der), b = fixture.provider("B", der: der, slot: 99)
        func device(_ source: DiscoveredMiddleware, _ token: SignumToken) -> DiscoveredMiddleware {
            .init(id: source.id, definition: source.definition, origin: source.origin, candidatePath: source.candidatePath,
                  inspection: source.inspection, status: source.status,
                  tokens: [.init(token: token, certificates: source.tokens[0].certificates, certificateState: .readable)], version: nil, unavailableSlots: 0)
        }
        let digitalDNA = device(a, token(model: "DigitalDNA"))
        let cns = device(b, .init(slot: 99, label: "CNS", manufacturer: "Test", model: "Card", reader: "Reader"))
        var selection = DeviceSelection(); let request = selection.beginDiscovery()
        selection.acceptCompleteFixture([digitalDNA, cns], request: request)
        XCTAssertNil(selection.selectedRoute)
        let routes = selection.certificates[0].routes
        XCTAssertEqual(routes.count, 2); XCTAssertEqual(routes[0].certificateFingerprint, routes[1].certificateFingerprint)
        for route in routes {
            XCTAssertTrue(selection.select(routeID: route.id))
            let before = selection.selectedRouteID
            let title = SigningRouteLabel.title(try XCTUnwrap(selection.selectedRoute))
            XCTAssertTrue(title.hasPrefix(route.title + " — "))
            XCTAssertTrue(title.hasSuffix(route.token.slot == 7 ? "DigitalDNA" : "Smart card CNS"))
            XCTAssertTrue(SigningRouteLabel.tooltip(route).contains("slot \(route.token.slot)"))
            XCTAssertEqual(before, selection.selectedRouteID)
        }
        // The certificate label says DS3; it never supplies the hardware type.
        XCTAssertEqual(SigningRouteLabel.device(token: routes[0].token), "DigitalDNA")
    }
}
#endif
