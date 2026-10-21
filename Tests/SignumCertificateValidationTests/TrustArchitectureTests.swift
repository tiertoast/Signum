import XCTest
import SignumCore
import SignumTrustCore
@testable import SignumTrustAuthentication
@testable import SignumCertificateValidation

final class TrustArchitectureTests: XCTestCase {
    func data(_ name: String, _ ext: String = "xml") throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures/E1R")))
    }
    func now() throws -> Date {
        let json = try JSONSerialization.jsonObject(with: data("clock","json")) as! [String:String]
        return try XCTUnwrap(ISO8601DateFormatter().date(from: json["evaluatedAt"]!))
    }
    func source(_ name: String) throws -> AuthenticatedTLDocument {
        try TLAuthenticator.authenticateDocument(data(name), authorizedCertificateSHA256: [TLAuthenticator.sha256(data("issuer","der"))], territory: "IT", now: now())
    }
    func catalog(_ name: String) throws -> InterpretedTrustCatalog { TLInterpreter.interpret(try source(name)) }
    func report() throws -> VerificationReport {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        return try SignumVerificationService.verify(data:data("multi","cms"),name:"multi.cms",helper:URL(fileURLWithPath:helper))
    }
    func testAuthenticatedBytesAreDistinctFromServiceCapabilities() throws {
        let raw = try source("excluded-ca"), catalog = TLInterpreter.interpret(raw)
        XCTAssertEqual(raw.xml,try data("excluded-ca")); XCTAssertEqual(raw.xmlSHA256,TLAuthenticator.sha256(raw.xml))
        XCTAssertEqual(raw.signerSHA256,TLAuthenticator.sha256(try data("issuer","der")))
        XCTAssertEqual(raw.cryptographicPolicy,"Signum-TLv6-XAdES-BB-RFC9231-v1")
        XCTAssertFalse((raw as Any) is InterpretedTrustCatalog)
        XCTAssertEqual(catalog.interpretationState,.partial); XCTAssertEqual(catalog.usableServiceCount,2)
        XCTAssertEqual(catalog.excludedServices.count,1)
        XCTAssertEqual(catalog.excludedServices[0].service,"SYNTHETIC issuer")
        XCTAssertFalse(catalog.usableProviders.flatMap(\.services).contains { $0.name == "SYNTHETIC issuer" })
    }
    func testExcludedServiceCannotBuildPathOrProduceQESButSiblingStillWorks() async throws {
        let report = try report(), clock = try now()
        let baseline = await SignatureQualificationService().validate(report,authenticatedLists:[try catalog("authorized")],mode:.online,observedAt:clock)
        XCTAssertTrue(baseline.contains { $0.qualification.state == .qualified }) // existing D profile only
        let excluded = await SignatureQualificationService().validate(report,authenticatedLists:[try catalog("excluded-ca")],mode:.online,observedAt:clock)
        let first = try XCTUnwrap(report.signatures.first { $0.signerDER == (try? data("leaf","der")) })
        let failed = try XCTUnwrap(excluded.first { $0.signatureID == first.id })
        XCTAssertNotEqual(failed.path.state,.verified); XCTAssertNotEqual(failed.qualification.state,.qualified)
        let sibling = try XCTUnwrap(excluded.first { $0.signatureID != first.id })
        XCTAssertEqual(sibling.path.state,.verified); XCTAssertEqual(sibling.qualification.state,.electronic)
        XCTAssertEqual(failed.evidence.signatureID,first.id)
    }
    func testExcludedTSACannotAuthorizeOrProveTimeOrQES() async throws {
        let report = try report(), list = try catalog("excluded-tsa"), clock = try now()
        let signature = try XCTUnwrap(report.signatures.first), envelope = try XCTUnwrap(signature.evidence)
        let token = try XCTUnwrap(envelope.timestampTokens.first)
        let tsa = TSAAuthorization.evaluate(token:token,signatureValue:envelope.signatureValue,authenticatedLists:[list],observedAt:clock)
        XCTAssertEqual(tsa.state,.notAuthorized)
        let results = await SignatureQualificationService().validate(report,authenticatedLists:[list],mode:.online,observedAt:clock)
        XCTAssertEqual(results.count,2)
        XCTAssertTrue(results.allSatisfy { $0.path.state == .verified && $0.evidence.time.state != .proven && $0.qualification.state != .qualified })
    }
    func testUnknownCriterionIsNotFalseAndKnownNonMatchingCriterionIsPreserved() throws {
        let unknown = try catalog("unsupported")
        XCTAssertEqual(unknown.usableServiceCount,1); XCTAssertEqual(unknown.excludedServices.count,2)
        let knownFalse = try catalog("wrong-policy")
        XCTAssertEqual(knownFalse.usableServiceCount,3); XCTAssertTrue(knownFalse.excludedServices.isEmpty)
    }
    func testUnscopedCriticalContentBlocksWholeCatalog() throws {
        let list = try catalog("global-critical")
        XCTAssertEqual(list.interpretationState,.blocked); XCTAssertEqual(list.usableServiceCount,0)
        XCTAssertEqual(list.excludedServices.count,3); XCTAssertNotNil(list.interpretationReason)
    }
    func testCacheAndLegacyAdapterReinterpretRawBytesAndIgnoreSerializedCapabilities() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true);defer { try? FileManager.default.removeItem(at:dir) }
        let file = dir.appendingPathComponent("verified.json"), anchors: Set<Data> = [TLAuthenticator.sha256(try data("issuer","der"))]
        for name in ["excluded-ca","global-critical"] {
            try? FileManager.default.removeItem(at:file)
            try TLSnapshot.save(TLBundle(lotl:data("e1r-lotl"),italy:data(name),refreshedAt:now()),to:file,now:now(),anchors:anchors)
            var object = try JSONSerialization.jsonObject(with:Data(contentsOf:file)) as! [String:Any]
            object["interpretationState"] = "complete";object["excludedServices"] = [];object["usableProviders"] = ["forged"]
            try JSONSerialization.data(withJSONObject:object).write(to:file)
            let verified = try TLSnapshot.readVerified(file,now:now(),anchors:anchors).italy
            XCTAssertEqual(verified.usableServiceCount,name == "excluded-ca" ? 2 : 0)
            XCTAssertEqual(verified.interpretationState,name == "excluded-ca" ? .partial : .blocked)
        }
    }
    func testFixedParameterPSS256384512() throws {
        for bits in [256,384,512] {
            let value = try source("pss-\(bits)")
            XCTAssertEqual(value.xmlSHA256,TLAuthenticator.sha256(try data("pss-\(bits)")))
            XCTAssertEqual(TLInterpreter.interpret(value).usableServiceCount,3)
        }
    }
    func testRestrictedPSSKeyCannotOverrideFixedXMLParameters() throws {
        XCTAssertThrowsError(try TLAuthenticator.authenticateDocument(data("pss-constrained-key"),
            authorizedCertificateSHA256:[TLAuthenticator.sha256(data("constrained-pss","der"))],territory:"IT",now:now()))
    }
    func testPSSRejectsWrongActualSaltMGFAndTrailer() throws {
        for name in ["pss-wrong-salt","pss-wrong-mgf","pss-wrong-trailer"] { XCTAssertThrowsError(try source(name),name) }
    }
    func testPSSRejectsAlterationsUnknownURIsParametersAndUnauthorizedSigner() throws {
        let valid = try data("pss-256"), text = String(decoding:valid,as:UTF8.self)
        func reject(_ xml: Data) {
            XCTAssertThrowsError(try TLAuthenticator.authenticateDocument(xml,authorizedCertificateSHA256:[TLAuthenticator.sha256(data("issuer","der"))],territory:"IT",now:now()))
        }
        for uri in ["sha1-rsa-MGF1","rsa-pss","sha256-rsa-MGF1-fake"] { reject(Data(text.replacingOccurrences(of:"sha256-rsa-MGF1",with:uri).utf8)) }
        let end = "</ds:SignatureMethod>"
        let marker = "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1\"/>"
        XCTAssertTrue(text.contains(marker))
        for child in ["<p:RSAPSSParams xmlns:p=\"http://www.w3.org/2007/05/xmldsig-more#\"><p:SaltLength>20</p:SaltLength></p:RSAPSSParams>","<p:TrailerField xmlns:p=\"http://www.w3.org/2007/05/xmldsig-more#\">2</p:TrailerField>","<ds:Unexpected/>"] {
            reject(Data(text.replacingOccurrences(of:marker,with:marker.replacingOccurrences(of:"/>",with:">")+child+end).utf8))
        }
        let tag = try XCTUnwrap(text.range(of:"<ds:SignatureValue[^>]*>",options:.regularExpression))
        let endValue = try XCTUnwrap(text.range(of:"</ds:SignatureValue>"))
        let original = String(text[tag.upperBound..<endValue.lowerBound])
        var signatureBytes = try XCTUnwrap(Data(base64Encoded:original.filter { !$0.isWhitespace }))
        signatureBytes[0] ^= 1
        let signedTime = try XCTUnwrap(text.range(of:"(?<=<xades:SigningTime>)[^<]+",options:.regularExpression))
        let oldTime = String(text[signedTime]), date = try XCTUnwrap(ISO8601DateFormatter().date(from:oldTime))
        let edits = [(oldTime,date.addingTimeInterval(-3600).ISO8601Format()),("URI=\"\"","URI=\"#missing\""),(original,signatureBytes.base64EncodedString())]
        for (before,after) in edits { XCTAssertTrue(text.contains(before));reject(Data(text.replacingOccurrences(of:before,with:after).utf8)) }
        XCTAssertThrowsError(try TLAuthenticator.authenticateDocument(valid,authorizedCertificateSHA256:[],territory:"IT",now:now()))
        XCTAssertThrowsError(try TLAuthenticator.authenticateDocument(data("pss-wrong-key"),authorizedCertificateSHA256:[TLAuthenticator.sha256(data("wrong-key","der"))],territory:"IT",now:now()))
    }
}
