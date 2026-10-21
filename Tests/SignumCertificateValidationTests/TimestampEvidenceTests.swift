import XCTest
import SignumCertificateValidation

final class TimestampEvidenceTests: XCTestCase {
    func data(_ name: String, _ ext: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures/Revocation")))
    }
    func now() throws -> Date {
        let clock = try JSONDecoder().decode([String:String].self, from: data("clock", "json"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from: XCTUnwrap(clock["evaluatedAt"])))
    }
    func testRFC3161ImprintSignatureESSAndExplicitTSAPath() throws {
        let result = TimestampEvidenceVerifier.verify(token: try data("valid", "tst"), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("issuer", "der"), observedAt: try now())
        XCTAssertEqual(result.state, .authenticatedToken, result.reason)
        XCTAssertNotNil(result.tokenTime)
        XCTAssertLessThanOrEqual(try XCTUnwrap(result.tokenTime), try now())
        // An authenticated token is deliberately not called a proved signature
        // time: TSA revocation/TL authorization must also be established.
    }
    func testDirectTSAIdentityAndWrongAnchor() throws {
        let direct = TimestampEvidenceVerifier.verify(token: try data("valid", "tst"), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("tsa", "der"), observedAt: try now())
        XCTAssertEqual(direct.state, .authenticatedToken, direct.reason)
        let unknown = TimestampEvidenceVerifier.verify(token: try data("valid", "tst"), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("other", "der"), observedAt: try now())
        XCTAssertEqual(unknown.state, .invalid)
    }
    func testForgedTimestampWrongImprintAndMalformedToken() throws {
        let value = try data("signature", "bin"), anchor = try data("issuer", "der"), date = try now()
        for token in [try data("altered", "tst"), Data([0,1]), try data("valid", "tst") + Data([0])] {
            XCTAssertEqual(TimestampEvidenceVerifier.verify(token: token, signatureValue: value, explicitTSAIdentity: anchor, observedAt: date).state, .invalid)
        }
        let mismatch = TimestampEvidenceVerifier.verify(token: try data("valid", "tst"), signatureValue: value + Data([0]), explicitTSAIdentity: anchor, observedAt: date)
        XCTAssertEqual(mismatch.state, .invalid)
    }
    func testMathematicallySignedTokensWithoutTSAUsageOrESSRejected() throws {
        for name in ["wrong-eku", "missing-ess"] {
            let result = TimestampEvidenceVerifier.verify(token: try data(name, "tst"), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("issuer", "der"), observedAt: try now())
            XCTAssertEqual(result.state, .invalid, name + ": " + result.reason)
            XCTAssertNil(result.tokenTime)
        }
    }
    func testAbsentAndFutureTimestampCannotEstablishTime() throws {
        let missing = TimestampEvidenceVerifier.verify(token: Data(), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("issuer", "der"), observedAt: try now())
        XCTAssertEqual(missing.state, .unsupported);XCTAssertNil(missing.tokenTime)
        let future = TimestampEvidenceVerifier.verify(token: try data("valid", "tst"), signatureValue: try data("signature", "bin"), explicitTSAIdentity: try data("issuer", "der"), observedAt: try now().addingTimeInterval(-86400))
        XCTAssertEqual(future.state, .unsupported);XCTAssertNil(future.tokenTime)
    }
}
