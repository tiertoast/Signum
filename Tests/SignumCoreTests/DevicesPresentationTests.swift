#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

final class DevicesPresentationTests: XCTestCase {
    func observed(_ id: String, model: String, certificates: [String] = ["valid"], state: DiscoveredToken.CertificateState = .readable, serial: String = "OBSERVED") throws -> DiscoveredMiddleware {
        let fixture = try CertificateEligibilityTests.fixtures.get()
        let source = DeviceSelectionTests().provider(id,der:try fixture.der(certificates[0]))
        let token = SignumToken(slot:7,label:model,manufacturer:"Synthetic",model:model,reader:"Synthetic reader",serial:serial)
        let certs = try certificates.enumerated().map { index,name in IsolatedPKCS11Client.Certificate(certificate:.init(label:"Same label",identifier:Data([UInt8(index+1)])),der:try fixture.der(name)) }
        return .init(id:source.id,definition:source.definition,origin:source.origin,candidatePath:source.candidatePath,inspection:source.inspection,status:state == .readable ? .ready:.partial,tokens:[.init(token:token,certificates:state == .readable ? certs:[],certificateState:state)],version:"synthetic",unavailableSlots:0)
    }
    func selection(_ providers: [DiscoveredMiddleware]) -> DeviceSelection {
        var value=DeviceSelection();let request=value.beginDiscovery();value.acceptCompleteFixture(providers,request:request);return value
    }
    func testDigitalDNAAndCNSIndividuallyAndTogetherUseOnlyObservedMetadata() throws {
        let dna=try observed("dna",model:"DigitalDNA"),cns=try observed("cns",model:"CNS",certificates:["replaced"],serial:"OTHER")
        for provider in [dna,cns] {
            let value=selection([provider]),groups=DevicePresentation.collect(value)
            XCTAssertEqual(groups.count,1);XCTAssertTrue(groups[0].readable);XCTAssertEqual(groups[0].certificateGroups.count,1)
            XCTAssertNotNil(value.selectedRoute)
        }
        let both=selection([dna,cns]),groups=DevicePresentation.collect(both)
        XCTAssertEqual(Set(groups.map(\.name)),["DigitalDNA","Smart card CNS"])
        XCTAssertNil(both.selectedRoute)
    }
    func testCorrelatedProvidersAreOnePresentationGroupButAllRoutesRemainAmbiguous() throws {
        var value=selection([try observed("A",model:"DigitalDNA"),try observed("B",model:"DigitalDNA")])
        let groups=DevicePresentation.collect(value)
        XCTAssertEqual(groups.count,1);XCTAssertEqual(groups[0].accesses.count,2)
        XCTAssertEqual(groups[0].routes.count,2);XCTAssertNil(value.selectedRoute)
        let before=Set(value.certificates.flatMap(\.routes).map(\.id))
        for route in groups[0].routes {
            XCTAssertTrue(value.select(routeID:route.id))
            var provider=ProviderSelection();provider.select(route:route)
            XCTAssertEqual(provider.signingProvider,route.providerPath)
            XCTAssertEqual(value.selectedRouteID,route.id)
            XCTAssertEqual(SigningRouteLabel.title(try XCTUnwrap(value.selectedRoute)),route.title+" — DigitalDNA")
        }
        XCTAssertEqual(Set(value.certificates.flatMap(\.routes).map(\.id)),before)
    }
    func testNamesakesAndUnreadableCertificatesDoNotGainIdentityOrEligibility() throws {
        let provider=try observed("A",model:"CNS",certificates:["valid","replaced","authentication","expired","missingKU"])
        let value=selection([provider]),group=try XCTUnwrap(DevicePresentation.collect(value).first)
        XCTAssertEqual(group.certificateGroups.count,5)
        let routes=group.routes
        XCTAssertGreaterThan(Set(routes.map(\.certificateFingerprint)).count,1)
        XCTAssertTrue(routes.contains { DevicePresentation.purpose($0)=="Autenticazione" })
        XCTAssertTrue(routes.contains { DevicePresentation.certificateState($0)=="Scaduto" })
        XCTAssertTrue(routes.contains { $0.assessment.status == .indeterminate })
        XCTAssertNil(value.selectedRoute)
        let unreadable=selection([try observed("B",model:"DigitalDNA",state:.authenticationRequired)])
        let unknown=try XCTUnwrap(DevicePresentation.collect(unreadable).first)
        XCTAssertFalse(unknown.readable);XCTAssertTrue(unknown.routes.isEmpty)
        XCTAssertTrue(unknown.countLabel.contains("non determinabile"));XCTAssertFalse(unreadable.discoveryComplete)
    }
    func testNoDevicesAndRefreshKeepExistingSecureSelectionPolicy() throws {
        XCTAssertTrue(DevicePresentation.collect(selection([])).isEmpty)
        let provider=try observed("A",model:"DigitalDNA")
        var value=selection([provider]);let id=try XCTUnwrap(value.selectedRouteID)
        _=DevicePresentation.collect(value)
        let request=value.beginDiscovery();XCTAssertNil(value.selectedRoute)
        value.acceptCompleteFixture([provider],request:request)
        XCTAssertEqual(value.selectedRouteID,id);XCTAssertTrue(value.selectionWasPreserved)
        XCTAssertEqual(DevicePresentation.collect(value).first?.routes.first?.id,id)
    }
    func testTechnicalExtensionPresentationIsBoundedAndNeverUsedAsEligibility() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("authentication")
        let text=DevicePresentation.extensionDetails(der)
        XCTAssertTrue(text.contains("2.5.29.15"));XCTAssertTrue(text.contains("2.5.29.37"))
        XCTAssertEqual(DevicePresentation.extensionDetails(Data([0])),"Estensioni non disponibili.")
        XCTAssertFalse(CertificateEligibility.evaluate(certificateDER:der).permitsSigning)
    }
}
#endif
