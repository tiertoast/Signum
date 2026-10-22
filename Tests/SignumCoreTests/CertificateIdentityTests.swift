import Foundation
import XCTest
@testable import SignumCore

final class CertificateIdentityTests: XCTestCase {
    private func field(_ oid: [UInt8], _ text: String) -> Data {
        DER.set([DER.sequence([
            DER.wrap(0x06, Data(oid)),
            DER.wrap(0x0C, Data(text.utf8))
        ])])
    }

    private func certificate(subject: [Data]) -> Data {
        let issuer = DER.sequence([field([0x55, 0x04, 0x03], "CA di test")])
        let validity = DER.sequence([
            DER.wrap(0x17, Data("251001000000Z".utf8)),
            DER.wrap(0x17, Data("281001000000Z".utf8))
        ])
        let tbs = DER.sequence([
            DER.wrap(0xA0, DER.wrap(0x02, Data([0x02]))),
            DER.wrap(0x02, Data([0x01])),
            DER.sequence([DER.rsaEncryptionOID, DER.null]),
            issuer,
            validity,
            DER.sequence(subject),
            DER.sequence([])
        ])
        return DER.sequence([
            tbs,
            DER.sequence([DER.rsaEncryptionOID, DER.null]),
            DER.wrap(0x03, Data([0x00]))
        ])
    }

    func testExtractsHolderAndFiscalCodeFromSubjectSerialNumber() throws {
        let fixture = certificate(subject: [
            field([0x55, 0x04, 0x04], "Rossi"),
            field([0x55, 0x04, 0x2A], "Mario"),
            field([0x55, 0x04, 0x05], "TINIT-RSSMRA80A01H501U"),
            field([0x55, 0x04, 0x03], "Rossi Mario")
        ])
        let identity = try SignumCertificateIdentity(certificateDER: fixture)
        XCTAssertEqual(identity.fullName, "Mario Rossi")
        XCTAssertEqual(identity.fiscalCode, "RSSMRA80A01H501U")
        XCTAssertEqual(identity.title, "Mario Rossi (RSSMRA80A01H501U)")
        XCTAssertEqual(identity.issuer, "CA di test")
    }

    func testExtractsCNSFiscalCodeFromCommonName() throws {
        let fixture = certificate(subject: [
            field([0x55, 0x04, 0x04], "Verdi"),
            field([0x55, 0x04, 0x2A], "Anna"),
            field([0x55, 0x04, 0x03], "VRDNNA85B42F205Z/DEVICE-ID")
        ])
        let identity = try SignumCertificateIdentity(certificateDER: fixture)
        XCTAssertEqual(identity.fullName, "Anna Verdi")
        XCTAssertEqual(identity.fiscalCode, "VRDNNA85B42F205Z")
    }

    func testUnknownFiscalCodeIsNotInvented() throws {
        let fixture = certificate(subject: [
            field([0x55, 0x04, 0x03], "Mario Rossi"),
            field([0x55, 0x04, 0x05], "SERIAL-1234")
        ])
        let identity = try SignumCertificateIdentity(certificateDER: fixture)
        XCTAssertEqual(identity.title, "Mario Rossi")
        XCTAssertNil(identity.fiscalCode)
    }

    func testMalformedCertificateIsRejected() {
        XCTAssertThrowsError(try SignumCertificateIdentity(certificateDER: Data([0x30, 0x82, 0x01])))
    }

    func testPersonalNameAndStructuredIdentifiersDoNotConfuseCompaniesOrForeignSerials() throws {
        let personal=[field([0x55,0x04,0x2A],"Élodie"),field([0x55,0x04,0x04],"Müller")]
        let foreign=try SignumCertificateIdentity(certificateDER:certificate(subject:personal+[
            field([0x55,0x04,0x06],"FR"),field([0x55,0x04,0x05],"RSSMRA80A01H501U")]))
        XCTAssertEqual(foreign.personalName,"Élodie Müller");XCTAssertNil(foreign.fiscalCode)
        for serial in ["VATIT-12345678901","NTRIT-RSSMRA80A01H501U","VATIT-RSSMRA80A01H501U","TINIT-12345678901","prefix RSSMRA80A01H501U suffix"] {
            let identity=try SignumCertificateIdentity(certificateDER:certificate(subject:personal+[
                field([0x55,0x04,0x06],"IT"),field([0x55,0x04,0x05],serial)]))
            XCTAssertNil(identity.fiscalCode,serial)
        }
        let company=try SignumCertificateIdentity(certificateDER:certificate(subject:[
            field([0x55,0x04,0x03],"Impresa Test"),field([0x55,0x04,0x0A],"Impresa Test"),
            field([0x55,0x04,0x05],"VATIT-12345678901")]))
        XCTAssertNil(company.personalName);XCTAssertNil(company.fiscalCode)
        XCTAssertEqual(company.organization,"Impresa Test")
    }
    func testIncompleteAmbiguousAndOmocodiaSubjectFieldsAreExplicit() throws {
        let incomplete=try SignumCertificateIdentity(certificateDER:certificate(subject:[field([0x55,0x04,0x2A],"Mario")]))
        XCTAssertNil(incomplete.personalName)
        let duplicate=try SignumCertificateIdentity(certificateDER:certificate(subject:[
            field([0x55,0x04,0x2A],"Mario"),field([0x55,0x04,0x2A],"Altro"),field([0x55,0x04,0x04],"Rossi")]))
        XCTAssertNil(duplicate.personalName)
        let identity=try SignumCertificateIdentity(certificateDER:certificate(subject:[
            field([0x55,0x04,0x2A],"Mario"),field([0x55,0x04,0x04],"Rossi"),
            field([0x55,0x04,0x05],"tinit-rssmraULALMHRLmu")]))
        XCTAssertEqual(identity.personalName,"Mario Rossi");XCTAssertEqual(identity.fiscalCode,"RSSMRAULALMHRLMU")
    }
    func testVerificationIdentityUsesOnlyTheBoundSignerCertificate() throws {
        let der=certificate(subject:[field([0x55,0x04,0x2A],"Mario"),field([0x55,0x04,0x04],"Rossi"),field([0x55,0x04,0x05],"TINIT-RSSMRA80A01H501U")])
        var signature=SignatureVerificationResult(id:0,integrity:.invalid,certificate:.init(subject:"Untrusted display text",issuer:"CA",sha256:DocumentSnapshot.digest(der)),algorithm:"test",declaredTime:"",reason:"invalid",signedRevisionEnd:nil,laterChanges:false,cmsLayer:1)
        signature.signerDER=der
        XCTAssertEqual(signature.signerIdentity?.personalName,"Mario Rossi")
        XCTAssertEqual(signature.integrity,.invalid) // identity never promotes a verdict
        signature.signerDER=nil;signature.embeddedCertificateDERs=[der]
        XCTAssertNil(signature.signerIdentity) // never pick an arbitrary embedded certificate
        signature.signerDER=certificate(subject:[field([0x55,0x04,0x03],"Another certificate")])
        XCTAssertNil(signature.signerIdentity) // digest mismatch
    }

    func testDeviceTypeIsConservativeForUnknownHardware() {
        let usbToken = SignumToken(slot: 1, label: "DigitalDNA",
                                   manufacturer: "NXP", model: "SecID P71",
                                   reader: "Bit4id Digital-DNA Key")
        let cns = SignumToken(slot: 2, label: "CNS", manufacturer: "NXP",
                              model: "JCOP-4", reader: "Hamlet HUSCR-NFC")
        let unknown = SignumToken(slot: 3, label: "Cert", manufacturer: "X",
                                  model: "Y")
        XCTAssertEqual(usbToken.deviceKind, "Token USB")
        XCTAssertEqual(cns.deviceKind, "Smart card")
        XCTAssertEqual(unknown.deviceKind, "Dispositivo PKCS#11")
        XCTAssertEqual(cns.readerDescription, "Lettore: Hamlet HUSCR-NFC")
    }
}
