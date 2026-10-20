import XCTest
import SignumTrustCore
@testable import SignumTrustAuthentication

final class AuthenticationTests: XCTestCase {
    let now = ISO8601DateFormatter().date(from: "2026-10-20T12:00:00Z")!
    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")))
    }
    func eu(_ xml: Data? = nil, anchors: Set<Data>? = nil) throws -> AuthenticatedTL {
        try TLAuthenticator.authenticate(xml ?? fixture("eu-lotl.xml"), authorizedCertificateSHA256: anchors ?? EUTrustPolicy.journalAnchors, territory: "EU", now: now)
    }
    func changed(_ data: Data, _ from: String, _ to: String) throws -> Data {
        let s = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertTrue(s.contains(from), "mutation must affect fixture")
        return Data(s.replacingOccurrences(of: from, with: to).utf8)
    }
    func testOfficialEuropeAndItaly() throws {
        let e = try LOTLPivotChain.authenticate(current: fixture("eu-lotl.xml"), pivotsOldestFirst: [], now: now)
        let i = try TLAuthenticator.authenticateItaly(fixture("it.xml"), lotl: e, now: now)
        XCTAssertEqual(e.document.sequenceNumber, 397)
        XCTAssertEqual(i.document.sequenceNumber, 224)
        XCTAssertEqual(i.document.providers.count, 56)
        XCTAssertEqual(i.document.providers.reduce(0) { $0 + $1.services.count }, 562)
        XCTAssertEqual(e.signerSHA256.map { String(format: "%02x", $0) }.joined(), "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1")
        XCTAssertEqual(i.signerSHA256.map { String(format: "%02x", $0) }.joined(), "ddf02ac377a55fbda3709158a15fe1a10330743413ff1de72a91edb6ee285661")
    }
    func testAlteredRootContent() throws {
        XCTAssertThrowsError(try eu(changed(fixture("eu-lotl.xml"), "<TSLSequenceNumber>397", "<TSLSequenceNumber>398")))
    }
    func testUnauthorizedCertificateEvenWhenSelfContained() throws {
        XCTAssertThrowsError(try eu(anchors: []))
        XCTAssertThrowsError(try eu(fixture("synthetic-a.xml")))
    }
    func testExternalReferenceRejected() throws {
        let original = try fixture("eu-lotl.xml")
        for uri in ["file:///etc/passwd", "https://example.invalid/evil", "#xpointer(/)"] {
            XCTAssertThrowsError(try eu(changed(original, "URI=\"\"", "URI=\"\(uri)\"")))
        }
    }
    func testDuplicateIDsAndXMLWrapping() throws {
        let original = try fixture("eu-lotl.xml")
        XCTAssertThrowsError(try eu(changed(original, "<SchemeInformation>", "<SchemeInformation Id=\"ID0001\">")))
        XCTAssertThrowsError(try eu(changed(original, "<SchemeInformation>", "<SchemeInformation><TrustServiceStatusList Id=\"evil\"/>")))
        let text = String(data: original, encoding: .utf8)!
        XCTAssertThrowsError(try eu(Data(("<wrapper>" + text.replacingOccurrences(of: "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", with: "") + "</wrapper>").utf8)))
    }
    func testUnsignedSignatureObjectCannotInjectTLMetadata() throws {
        let original = try fixture("eu-lotl.xml")
        // The enveloped transform excludes Signature entirely. This injection
        // leaves the signed root and SignedProperties cryptographically intact.
        let text = String(data: original, encoding: .utf8)!
        let start = try XCTUnwrap(text.range(of: "<SchemeInformation>"))
        let end = try XCTUnwrap(text.range(of: "</SchemeInformation>"))
        let payload = String(text[start.lowerBound..<end.upperBound])
            .replacingOccurrences(of: "<TSLSequenceNumber>397", with: "<TSLSequenceNumber>999")
            .replacingOccurrences(of: "<SchemeTerritory>EU", with: "<SchemeTerritory>IT")
        let attack = try changed(original, "<ds:Object>", "<ds:Object>" + payload)
        let raw = try UntrustedTLParser.parse(attack)
        XCTAssertEqual(raw.sequenceNumber, 397)
        XCTAssertEqual(raw.territory, "EU")
        XCTAssertThrowsError(try eu(attack)) { error in
            XCTAssertTrue(String(describing: error).contains("unsigned signature objects"))
        }
    }
    func testSignedPropertiesBindingAndAlgorithmDowngrade() throws {
        let original = try fixture("eu-lotl.xml")
        for pair in [
            ("#SignedProperties", "#SomethingElse"),
            ("#rsa-sha512", "#rsa-sha1"),
            ("#sha512", "#sha1"),
            ("#enveloped-signature", "#base64"),
            ("Target=\"#id-", "Target=\"#wrong-"),
            ("<xades:SigningTime>2026-10-15T15:30:36Z", "<xades:SigningTime>2026-10-14T15:30:36Z")
        ] { XCTAssertThrowsError(try eu(changed(original, pair.0, pair.1))) }
    }
    func testSignatureValueTamperAndMissingSignature() throws {
        let original = try fixture("eu-lotl.xml")
        XCTAssertThrowsError(try eu(changed(original, ">j/hbIyjG", ">k/hbIyjG")))
        XCTAssertThrowsError(try eu(changed(original, "ds:Signature ", "ds:NotSignature ")))
    }
    func testDTDAndCriticalExtensionFailClosed() throws {
        let original = try fixture("eu-lotl.xml")
        XCTAssertThrowsError(try eu(changed(original, "<SchemeInformation>", "<SchemeInformation><Extension Critical=\"true\"><Unknown/></Extension>")))
        XCTAssertThrowsError(try eu(Data(("<!DOCTYPE x [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>" + String(data: original, encoding: .utf8)!).utf8)))
    }
    func testExpiryFutureWrongTerritory() throws {
        let xml = try fixture("eu-lotl.xml")
        XCTAssertThrowsError(try TLAuthenticator.authenticate(xml, authorizedCertificateSHA256: EUTrustPolicy.journalAnchors, territory: "EU", now: now.addingTimeInterval(365*86400)))
        XCTAssertThrowsError(try TLAuthenticator.authenticate(xml, authorizedCertificateSHA256: EUTrustPolicy.journalAnchors, territory: "EU", now: now.addingTimeInterval(-30*86400)))
        XCTAssertThrowsError(try TLAuthenticator.authenticate(xml, authorizedCertificateSHA256: EUTrustPolicy.journalAnchors, territory: "IT", now: now))
        let e = try eu()
        XCTAssertThrowsError(try TLAuthenticator.authenticateItaly(fixture("it.xml"), lotl: e, now: now.addingTimeInterval(365*86400)))
    }
    func testSyntheticAuthorizedRotationAndRetiredKey() throws {
        let a = TLAuthenticator.sha256(try fixture("test-a.der"))
        let b = TLAuthenticator.sha256(try fixture("test-b.der"))
        XCTAssertNoThrow(try eu(fixture("synthetic-a.xml"), anchors: [a]))
        let pivot = LOTLPivotChain.Pivot(location: "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-401.xml", xml: try fixture("synthetic-pivot.xml"))
        XCTAssertThrowsError(try eu(fixture("synthetic-pivot.xml"), anchors: [a])) // expired as a current LOTL
        let result = try LOTLPivotChain.validate(current: fixture("synthetic-b.xml"), pivotsOldestFirst: [pivot], now: now, initialAnchors: [a])
        XCTAssertEqual(result.signerSHA256, b)
        XCTAssertThrowsError(try LOTLPivotChain.validate(current: fixture("synthetic-b.xml"), pivotsOldestFirst: [], now: now, initialAnchors: [a]))
        XCTAssertThrowsError(try LOTLPivotChain.validate(current: fixture("synthetic-a.xml"), pivotsOldestFirst: [pivot], now: now, initialAnchors: [a]))
        XCTAssertThrowsError(try LOTLPivotChain.validate(current: fixture("synthetic-b.xml"), pivotsOldestFirst: [pivot], now: now, initialAnchors: [b]))
        XCTAssertThrowsError(try LOTLPivotChain.validate(current: fixture("synthetic-b.xml"), pivotsOldestFirst: [pivot, pivot], now: now, initialAnchors: [a]))
    }
    func testCryptographicallySignedButInvalidBaselineProperties() throws {
        let a = TLAuthenticator.sha256(try fixture("test-a.der"))
        for name in ["synthetic-wrong-cert-binding.xml", "synthetic-wrong-format.xml"] {
            XCTAssertThrowsError(try eu(fixture(name), anchors: [a]))
        }
    }
    func testSequenceRollbackAfterAuthenticatedRevision() throws {
        let a = TLAuthenticator.sha256(try fixture("test-a.der"))
        let old = try eu(fixture("synthetic-a.xml"), anchors: [a])
        let newer = try TLAuthenticator.authenticate(fixture("synthetic-pivot.xml"), authorizedCertificateSHA256: [a], territory: "EU", now: ISO8601DateFormatter().date(from: "2026-10-11T10:30:00Z")!, previous: old)
        XCTAssertThrowsError(try TLAuthenticator.authenticate(fixture("synthetic-a.xml"), authorizedCertificateSHA256: [a], territory: "EU", now: now, previous: newer))
    }
    func testAtomicSnapshotReauthenticationAndStaleRejection() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        try TLSnapshot.save(lotl: fixture("eu-lotl.xml"), italy: fixture("it.xml"), to: file, now: now)
        XCTAssertEqual(try TLSnapshot.load(from: file, now: now).1.document.sequenceNumber, 224)
        try TLSnapshot.save(lotl: fixture("eu-lotl.xml"), italy: fixture("it.xml"), to: file, now: now)
        let before = try Data(contentsOf: file)
        XCTAssertThrowsError(try TLSnapshot.save(lotl: fixture("eu-lotl.xml"), italy: Data("bad".utf8), to: file, now: now))
        XCTAssertEqual(try Data(contentsOf: file), before)
        XCTAssertThrowsError(try TLSnapshot.load(from: file, now: now.addingTimeInterval(365*86400)))
    }
}
