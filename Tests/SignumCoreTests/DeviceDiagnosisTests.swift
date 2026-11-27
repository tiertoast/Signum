#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

final class DeviceDiagnosisTests: XCTestCase {
    let fixture = DeviceSelectionTests()
    func der(_ name: String) throws -> Data { try CertificateEligibilityTests.fixtures.get().der(name) }
    func provider(_ status: MiddlewareDetectionStatus, name: String = "OpenSC",
                  tokens: [DiscoveredToken] = []) -> DiscoveredMiddleware {
        let path = "/synthetic/\(name).so"
        return .init(id: name, definition: .init(id: name, name: name, manufacturer: "Test", candidatePaths: [path]), origin: .known,
                     candidatePath: path, inspection: nil, status: status, tokens: tokens, version: nil, unavailableSlots: 0)
    }
    func token(_ state: DiscoveredToken.CertificateState) -> DiscoveredToken {
        .init(token: SignumToken(slot: 1, label: "Card", manufacturer: "M", model: "X", reader: "R", serial: "1"),
              certificates: [], certificateState: state)
    }
    func readers(_ list: [(String, SmartCardReaderObservation.CardState)]) -> SmartCardReaderObservation {
        .init(availability: .observed, readers: list.map { .init(name: $0.0, card: $0.1) })
    }
    func diagnose(_ providers: [DiscoveredMiddleware], _ readers: SmartCardReaderObservation? = nil) -> [DeviceFinding] {
        DeviceDiagnosis.findings(providers: providers, certificates: DeviceCertificate.collect(providers, at: Date()), readers: readers)
    }
    func first(_ providers: [DiscoveredMiddleware], _ readers: SmartCardReaderObservation? = nil) -> DeviceFinding? {
        diagnose(providers, readers).first
    }

    func testNoReaderAtAll() {
        let finding = first([provider(.noToken)], readers([]))
        XCTAssertEqual(finding?.title, "Nessun lettore o chiavetta collegati"); XCTAssertEqual(finding?.action, .refresh)
    }
    func testReaderWithoutCard() {
        let finding = first([provider(.noToken)], readers([("ACS ACR39U", .empty)]))
        XCTAssertEqual(finding?.title, "Lettore senza tessera")
        XCTAssertTrue(finding?.detail.hasPrefix("«ACS ACR39U» è collegato") == true, finding?.detail ?? "")
    }
    func testCardPresentButNoSoftwareOffersOpenSC() {
        for readers in [readers([("ACS ACR39U", .present)]), nil] {
            let finding = first([provider(.missing), provider(.missing, name: "Bit4id")], readers)
            XCTAssertEqual(finding?.title, "Manca il software per leggere la tessera"); XCTAssertEqual(finding?.action, .installSoftware)
            XCTAssertEqual(finding?.detail.contains("«ACS ACR39U» è collegato e pronto"), readers != nil)
        }
    }
    func testCardPresentButSoftwareDoesNotSeeIt() {
        let finding = first([provider(.noToken), provider(.missing, name: "Bit4id")], readers([("Lettore", .present)]))
        XCTAssertEqual(finding?.title, "Dispositivo non riconosciuto"); XCTAssertEqual(finding?.action, .configure)
        XCTAssertTrue(finding?.detail.contains("«OpenSC» non lo riconosce") == true)
    }
    func testUnsafeAndUnresponsiveSoftware() {
        XCTAssertEqual(first([provider(.unsafe)], readers([("L", .present)]))?.title, "Software del dispositivo non caricato")
        XCTAssertEqual(first([provider(.communicationError)])?.title, "Il software del dispositivo non risponde")
    }
    func testMuteCardIsReportedEvenWithOtherFindings() {
        let findings = diagnose([provider(.noToken)], readers([("L", .mute)]))
        XCTAssertTrue(findings.contains { $0.title == "La tessera non risponde" })
    }
    func testUnknownReadersFallBackToSoftwareView() {
        let unavailable = SmartCardReaderObservation(availability: .serviceUnavailable, readers: [])
        XCTAssertEqual(first([provider(.noToken)], unavailable)?.title, "Nessun dispositivo di firma rilevato")
    }
    func testTokenWithoutReadableCertificates() {
        XCTAssertEqual(first([provider(.ready, tokens: [token(.authenticationRequired)])])?.title, "I certificati si leggono solo con il PIN")
        XCTAssertEqual(first([provider(.ready, tokens: [token(.empty)])])?.title, "Nessun certificato sul dispositivo")
        XCTAssertEqual(first([provider(.partial, tokens: [token(.communicationError)])])?.title, "Certificati non letti")
    }
    func testIneligibleCertificatesAreExplained() throws {
        XCTAssertEqual(first([fixture.provider(der: try der("authentication"))])?.title, "Il dispositivo ha solo un certificato di autenticazione")
        let expired = first([fixture.provider(der: try der("expired"))])
        XCTAssertEqual(expired?.title, "Certificato di firma scaduto"); XCTAssertTrue(expired?.detail.contains("2001") == true)
        XCTAssertEqual(first([fixture.provider(der: try der("future"))])?.title, "Certificato non ancora valido")
        XCTAssertEqual(first([fixture.provider(der: try der("wrongKU"))])?.title, "Nessun certificato idoneo alla firma")
        // Expired signing certificate next to a CNS-style one: the expiry is the reason.
        let mixed = [fixture.provider("a", der: try der("expired")), fixture.provider("b", der: try der("authentication"))]
        XCTAssertEqual(first(mixed)?.title, "Certificato di firma scaduto")
    }
    func testAnEligibleCertificateMeansNoFinding() throws {
        XCTAssertTrue(diagnose([fixture.provider(der: try der("valid"))], readers([("L", .present)])).isEmpty)
        XCTAssertTrue(diagnose([fixture.provider("a", der: try der("valid")), fixture.provider("b", der: try der("expired"))]).isEmpty)
    }
    func testSelectionCarriesReadersAndHidesFindingsWhileSearching() {
        var selection = DeviceSelection(); let request = selection.beginDiscovery()
        XCTAssertTrue(DeviceDiagnosis.findings(for: selection).isEmpty)
        let rows = [provider(.missing)]
        selection.accept(.init(providers: rows, expectedPaths: Set(rows.map(\.candidatePath)), readers: readers([])), request: request)
        XCTAssertEqual(selection.readers?.readers, [])
        XCTAssertEqual(DeviceDiagnosis.findings(for: selection).first?.title, "Nessun lettore o chiavetta collegati")
    }
    func testNameListAndLiveObservationShape() {
        XCTAssertEqual(DeviceDiagnosis.list(["A"]), "«A»")
        XCTAssertEqual(DeviceDiagnosis.list(["A", "B", "C"]), "«A», «B» e «C»")
        let live = SmartCardReaderObservation.current()  // public PC/SC listing only
        if live.availability == .observed { XCTAssertTrue(live.readers.allSatisfy { !$0.name.isEmpty }) }
    }
}
#endif
