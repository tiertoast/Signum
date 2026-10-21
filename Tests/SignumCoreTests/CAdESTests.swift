import XCTest
@testable import SignumCore

final class CAdESTests: XCTestCase {
    /// ASN.1 test fixture only, deliberately NOT a valid X.509 certificate.
    private func syntheticCertificate() -> Data {
        let tbs = DER.sequence([
            DER.wrap(0xA0, DER.wrap(0x02, Data([0x02]))),
            DER.wrap(0x02, Data([0x01])),
            DER.sequence([DER.rsaEncryptionOID, DER.null]),
            DER.sequence([DER.sequence([DER.wrap(0x31, Data())])]),
            DER.sequence([]),
            DER.sequence([])
        ])
        return DER.sequence([
            tbs,
            DER.sequence([DER.rsaEncryptionOID, DER.null]),
            DER.wrap(0x03, Data([0x00]))
        ])
    }

    func testX509IssuerAndSerialExtraction() throws {
        let certificate = syntheticCertificate()
        let identity = try DER.certificateIdentity(certificate)
        XCTAssertEqual(identity.serial, Data([0x02, 0x01, 0x01]))
        XCTAssertEqual(identity.issuer.first, 0x30)
    }

    func testDERLongFormLengthRoundtrip() throws {
        let data = DER.octets(Data(repeating: 0xAB, count: 512))
        let bytes = [UInt8](data)
        var position = 0
        let node = try DER.read(bytes, at: &position, limit: bytes.count)
        XCTAssertEqual(node.tag, 0x04)
        XCTAssertEqual(node.contents.count, 512)
        XCTAssertEqual(position, bytes.count)
    }

    func testCAdESAttributesAndAttachedCMSContainer() throws {
        let original = Data("Hello, Signum".utf8)
        let prepared = try CAdES.Prepared(document: original,
                                           certificateDER: syntheticCertificate())
        let attrBytes = [UInt8](prepared.attributesToSign)
        var offset = 0
        let root = try DER.read(attrBytes, at: &offset, limit: attrBytes.count)
        XCTAssertEqual(root.tag, 0x31)
        XCTAssertEqual(offset, attrBytes.count)
        var cursor = root.contents.lowerBound
        var attributeCount = 0
        while cursor < root.contents.upperBound {
            let attr = try DER.read(attrBytes, at: &cursor, limit: root.contents.upperBound)
            XCTAssertEqual(attr.tag, 0x30)
            attributeCount += 1
        }
        XCTAssertEqual(attributeCount, 4)

        let wrapped = try prepared.finish(signature: Data(repeating: 0xBC, count: 256))
        let bytes = [UInt8](wrapped)
        var position = 0
        let contentInfo = try DER.read(bytes, at: &position, limit: bytes.count)
        XCTAssertEqual(contentInfo.tag, 0x30)
        XCTAssertEqual(position, bytes.count)
    }

    func testDeclaredSigningTimeDERBoundariesAndSignedAttribute() throws {
        let parse = ISO8601DateFormatter()
        for (iso, tag, text) in [
            ("1949-12-31T23:59:59Z", UInt8(0x18), "19491231235959Z"),
            ("1950-01-01T00:00:00Z", 0x17, "500101000000Z"),
            ("2026-10-20T07:22:23Z", 0x17, "261020072223Z"),
            ("2049-12-31T23:59:59Z", 0x17, "491231235959Z"),
            ("2050-01-01T00:00:00Z", 0x18, "20500101000000Z")
        ] {
            let date = try XCTUnwrap(parse.date(from: iso))
            let encoded = try DER.signingTime(date)
            XCTAssertEqual(encoded.first, tag)
            XCTAssertEqual(String(decoding: encoded.dropFirst(2), as: UTF8.self), text)
            let prepared = try CAdES.Prepared(document: Data([1]), certificateDER: syntheticCertificate(), declaredSigningTime: date)
            let attribute = DER.attribute(oid: DER.signingTimeAttributeOID, value: encoded)
            XCTAssertNotNil(prepared.attributesToSign.range(of: attribute))
        }
        XCTAssertThrowsError(try DER.signingTime(Date(timeIntervalSince1970: .nan)))
    }

    func testRejectMalformedCertificateAndEmptyDocument() {
        XCTAssertThrowsError(try DER.certificateIdentity(Data([0x30, 0x82, 0x01])))
        XCTAssertThrowsError(try CAdES.Prepared(document: Data(), certificateDER: syntheticCertificate()))
    }
}
