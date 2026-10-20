import Foundation
import XCTest
@testable import SignumTrustCore

final class TrustedListParserTests: XCTestCase {
    private func xml(version: Int = 6, rootNamespace: String = "http://uri.etsi.org/02231/v2#", extra: String = "") -> Data {
        Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <TrustServiceStatusList xmlns="\(rootNamespace)" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <SchemeInformation>
            <TSLVersionIdentifier>\(version)</TSLVersionIdentifier>
            <TSLSequenceNumber>224</TSLSequenceNumber>
            <SchemeTerritory>IT</SchemeTerritory>
            <ListIssueDateTime>2026-09-24T07:16:56Z</ListIssueDateTime>
            <NextUpdate><dateTime>2027-03-24T08:16:56Z</dateTime></NextUpdate>
            <PointersToOtherTSL>
              <OtherTSLPointer><TSLLocation>https://tl.example.invalid/eu.xml</TSLLocation>
              <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId>
                <X509Certificate>AAECAw==</X509Certificate>
              </DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
              </OtherTSLPointer>
            </PointersToOtherTSL>
          </SchemeInformation>
          <TrustServiceProviderList><TrustServiceProvider>
            <TSPInformation><TSPName><Name xml:lang="it">Prestatore di prova</Name></TSPName></TSPInformation>
            <TSPServices><TSPService>
              <ServiceInformation>
                <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                <ServiceName><Name xml:lang="it">Firma prova</Name></ServiceName>
                <ServiceDigitalIdentity><DigitalId><X509Certificate>AAECAw==</X509Certificate></DigitalId></ServiceDigitalIdentity>
                <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                <StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime>
              </ServiceInformation>
              <ServiceHistory><ServiceHistoryInstance>
                <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
                <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
              </ServiceHistoryInstance></ServiceHistory>
            </TSPService></TSPServices>
          </TrustServiceProvider></TrustServiceProviderList>
          \(extra)
          <ds:Signature><ds:SignedInfo/></ds:Signature>
        </TrustServiceStatusList>
        """.utf8)
    }

    func testTLv6DoesNotImplyTrust() throws {
        let doc = try UntrustedTLParser.parse(xml())
        XCTAssertEqual(doc.version, 6)
        XCTAssertEqual(doc.sequenceNumber, 224)
        XCTAssertEqual(doc.territory, "IT")
        XCTAssertEqual(doc.providers.first?.name, "Prestatore di prova")
        XCTAssertEqual(doc.providers.first?.services.first?.history.count, 1)
        XCTAssertEqual(doc.providers.first?.services.first?.certificateDERs.first, Data([0, 1, 2, 3]))
        XCTAssertEqual(doc.pointers.first?.signingCertificateDERs.first, Data([0, 1, 2, 3]))
        XCTAssertTrue(doc.containsSignatureElement) // presence, not validation
    }

    func testTLv5Compatible() throws {
        XCTAssertEqual(try UntrustedTLParser.parse(xml(version: 5)).version, 5)
    }

    func testWrongNamespaceIsRejected() {
        XCTAssertThrowsError(try UntrustedTLParser.parse(xml(rootNamespace: "https://attacker.invalid/")))
    }

    func testDTDAndExternalEntityAreRejected() {
        var bad = String(decoding: xml(), as: UTF8.self)
        bad = bad.replacingOccurrences(of: "<TrustServiceStatusList", with: "<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><TrustServiceStatusList")
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data(bad.utf8))) { error in
            XCTAssertEqual(error as? TLParseError, .forbiddenDTD)
        }
    }

    func testInvalidUTF8Rejected() {
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data([0xFF, 0xFE])))
    }

    func testInputLimitRejected() {
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data(repeating: 32, count: UntrustedTLParser.maximumInputBytes + 1))) {
            XCTAssertEqual($0 as? TLParseError, .tooLarge)
        }
    }

    func testMalformedAndUnexpectedVersionRejected() {
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data("<hello/>".utf8)))
        XCTAssertThrowsError(try UntrustedTLParser.parse(xml(version: 8))) {
            XCTAssertEqual($0 as? TLParseError, .unsupportedVersion)
        }
    }
    func testAbsentSignatureRemainsUntrustedInput() throws {
        let withoutSignature = String(decoding: xml(), as: UTF8.self)
            .replacingOccurrences(of: "<ds:Signature><ds:SignedInfo/></ds:Signature>", with: "")
        XCTAssertFalse(try UntrustedTLParser.parse(Data(withoutSignature.utf8)).containsSignatureElement)
    }

    func testForeignNamespaceCannotInjectServiceStatus() throws {
        let altered = String(decoding: xml(), as: UTF8.self)
            .replacingOccurrences(of: "<ServiceStatus>", with:
                "<evil:ServiceStatus xmlns:evil=\"https://attacker.invalid/\">")
            .replacingOccurrences(of: "</ServiceStatus>", with: "</evil:ServiceStatus>")
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data(altered.utf8))) {
            XCTAssertEqual($0 as? TLParseError, .invalidStructure)
        }
    }

    func testMalformedCertificateIdentityRejected() throws {
        let altered = String(decoding: xml(), as: UTF8.self)
            .replacingOccurrences(of: "AAECAw==", with: "***not-base64***")
        XCTAssertThrowsError(try UntrustedTLParser.parse(Data(altered.utf8))) {
            XCTAssertEqual($0 as? TLParseError, .invalidStructure)
        }
    }

}
