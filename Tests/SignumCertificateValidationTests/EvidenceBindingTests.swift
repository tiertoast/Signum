import XCTest
@testable import SignumCore
@testable import SignumCertificateValidation
import SignumTrustAuthentication

final class EvidenceBindingTests: XCTestCase {
    func data(_ name: String,_ ext: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name,withExtension: ext,subdirectory: "Fixtures/Binding")))
    }
    func now() throws -> Date {
        let clock = try JSONDecoder().decode([String:String].self,from: data("clock","json"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from: XCTUnwrap(clock["evaluatedAt"])))
    }
    func list(_ name: String = "authorized") throws -> AuthenticatedTL {
        try TLAuthenticator.authenticate(data(name,"xml"),authorizedCertificateSHA256: [TLAuthenticator.sha256(data("issuer","der"))],territory: "IT",now: now())
    }
    func report(_ name: String = "multi",_ ext: String = "cms") throws -> VerificationReport {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        return try SignumVerificationService.verify(data: data(name,ext),name: name,helper: URL(fileURLWithPath: helper))
    }
    func replace(_ report: VerificationReport,_ signatures: [SignatureVerificationResult]) -> VerificationReport {
        var copy = VerificationReport(id: report.id,documentName: report.documentName,sha256: report.sha256,format: report.format,
            signatures: signatures,documentState: report.documentState,issue: report.issue,previewPDF: nil,originalContent: nil)
        copy.unassociatedEvidence = report.unassociatedEvidence;return copy
    }
    func envelope(_ old: SignatureEvidenceEnvelope,evidence: [EmbeddedValidationEvidence]? = nil,tokens: [Data]? = nil) -> SignatureEvidenceEnvelope {
        .init(signatureValue: old.signatureValue,signatureKey: old.signatureKey,signerIndex: old.signerIndex,
            signedAttributes: old.signedAttributes,unsignedAttributes: old.unsignedAttributes,timestampTokens: tokens ?? old.timestampTokens,
            embedded: evidence ?? old.embedded,issue: old.issue)
    }
    func testMultisignerCAdESAndPAdESDoNotExchangeEvidence() async throws {
        for ext in ["cms","pdf"] {
            let report = try report("multi",ext)
            XCTAssertEqual(report.integrity,.verified);XCTAssertEqual(report.signatures.count,2)
            let values = await SignatureEvidenceValidationService().validate(report,authenticatedLists: [try list()],observedAt: try now())
            XCTAssertEqual(values.count,2)
            for signature in report.signatures {
                let result = try XCTUnwrap(values.first { $0.signatureID == signature.id })
                let leafOne = signature.signerDER == (try data("leaf","der"))
                XCTAssertEqual(result.revocation.state,leafOne ? .good : .revoked,result.revocation.reason)
                XCTAssertEqual(result.time.state,.proven,result.time.reason)
                XCTAssertNotEqual(result.time.declaredSigningTime,"")
                XCTAssertEqual(signature.evidence?.timestampTokens.count,1)
                XCTAssertTrue(result.associations.contains { $0.source == "signatureTimeStamp" && $0.state == .associated })
            }
            if ext == "pdf" {
                XCTAssertNotEqual(report.signatures[0].signedRevisionEnd,report.signatures[1].signedRevisionEnd)
                for signature in report.signatures {
                    XCTAssertTrue(signature.evidence?.embedded.contains { $0.source == "pdfVRI" && $0.signatureRevisionEnd == signature.signedRevisionEnd && $0.sourceRevisionEnd > $0.signatureRevisionEnd } == true)
                }
                XCTAssertFalse(report.unassociatedEvidence.isEmpty)
                XCTAssertTrue(values.allSatisfy { $0.associations.contains { $0.source == "pdfDSS" && $0.state == .unassociated } })
            }
        }
    }
    func testWrongImprintAndEvidenceOfOtherSignerAreNotAssociated() async throws {
        let wrong = try report("wrong-imprint")
        let values = await SignatureEvidenceValidationService().validate(wrong,authenticatedLists: [try list()],observedAt: try now())
        XCTAssertTrue(values.contains { $0.time.state == .invalid && $0.associations.contains { $0.source == "signatureTimeStamp" && $0.state == .unassociated } })
        let original = try report();var signatures = original.signatures
        let a = try XCTUnwrap(signatures[0].evidence),b = try XCTUnwrap(signatures[1].evidence)
        signatures[0].evidence = envelope(a,evidence: b.embedded,tokens: b.timestampTokens)
        let swapped = await SignatureEvidenceValidationService().validate(replace(original,signatures),authenticatedLists: [try list()],observedAt: try now())
        XCTAssertEqual(swapped[0].revocation.state,.indeterminate)
        XCTAssertEqual(swapped[0].time.state,.invalid)
        XCTAssertTrue(swapped[0].associations.allSatisfy { $0.state == .unassociated })
        let otherCert = try XCTUnwrap(original.signatures[1].signerDER)
        let issuer = try data(CertificateEvidenceMaterial.issued(otherCert,by: data("issuer","der")) ? "issuer" : "other","der")
        let foreign = try XCTUnwrap(b.embedded.first { $0.kind == .ocsp && CertificateEvidenceMaterial.applies(.init(kind: .ocsp,der: $0.der),to: otherCert,issuer: issuer) })
        let relabelled = EmbeddedValidationEvidence(kind: .ocsp,source: foreign.source,association: .signerInfo,der: foreign.der,
            signatureKey: a.signatureKey,signatureRevisionEnd: 0,sourceRevisionEnd: 0)
        signatures[0].evidence = envelope(a,evidence: [relabelled],tokens: [])
        let recipient = await SignatureEvidenceValidationService().validate(replace(original,signatures),authenticatedLists: [try list()],observedAt: try now())
        XCTAssertEqual(recipient[0].revocation.state,.indeterminate)
        XCTAssertTrue(recipient[0].associations.allSatisfy { $0.state == .unassociated })
    }
    func testUnauthorizedTSANeverProvesTime() async throws {
        let values = await SignatureEvidenceValidationService().validate(try report(),authenticatedLists: [try list("no-tsa")],observedAt: try now())
        XCTAssertTrue(values.allSatisfy { $0.time.state == .indeterminate && $0.time.provenTime == nil })
        XCTAssertTrue(values.allSatisfy { $0.time.authorities.allSatisfy { $0.state == .notAuthorized } })
    }
    func testValidCRLAndAlteredStaleOrRevokedOCSP() async throws {
        let original = try report();var signature = try XCTUnwrap(original.signatures.first { $0.signerDER == (try? data("leaf","der")) })
        let old = try XCTUnwrap(signature.evidence)
        signature.evidence = envelope(old,evidence: old.embedded.filter { $0.kind == .crl })
        let crl = await SignatureEvidenceValidationService().validate(replace(original,[signature]),authenticatedLists: [try list()],observedAt: try now())
        XCTAssertEqual(crl.first?.revocation.state,.good)
        for kind in [EmbeddedValidationEvidence.Kind.ocsp,.crl] {
        for (name,expected) in [("altered",SignatureRevocationState.indeterminate),("stale",.indeterminate),("revoked",.revoked)] {
            let raw = EmbeddedValidationEvidence(kind: kind,source: "cmsRevocationValues",association: .signerInfo,der: try data(name,kind.rawValue),
                signatureKey: old.signatureKey,signatureRevisionEnd: 0,sourceRevisionEnd: 0)
            signature.evidence = envelope(old,evidence: [raw],tokens: [])
            let result = await SignatureEvidenceValidationService().validate(replace(original,[signature]),authenticatedLists: [try list()],observedAt: try now())
            XCTAssertEqual(result.first?.revocation.state,expected,name)
            XCTAssertEqual(result.first?.time.state,.notProven)
        }
        }
    }
    actor Transport: RevocationTransport {
        let responses: [Data:Data]
        var calls = 0
        init(responses: [Data:Data] = [:]) { self.responses = responses }
        func fetch(_ location: RevocationLocation,body: Data?,isCancelled: @escaping @Sendable () -> Bool) async throws -> Data {
            calls += 1
            if let body, let value = responses[body] { return value }
            throw ClientError.response
        }
    }
    func testCertificateEndpointsOnlineCacheAndNetworkAbsentIndeterminate() async throws {
        let original = try report();var signature = try XCTUnwrap(original.signatures.first { $0.signerDER == (try? data("leaf","der")) })
        let old = try XCTUnwrap(signature.evidence);signature.evidence = envelope(old,evidence: [])
        let one = replace(original,[signature]),issuer = try data("issuer","der")
        let leafRequest = try XCTUnwrap(CertificateEvidenceMaterial.request(data("leaf","der"),issuer: issuer))
        let tsaRequest = try XCTUnwrap(CertificateEvidenceMaterial.request(data("tsa","der"),issuer: issuer))
        let transport = Transport(responses: [leafRequest: try data("leaf-good","ocsp"),tsaRequest: try data("tsa-good","ocsp")])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let cache = RevocationEvidenceCache(directory: directory)
        let service = SignatureEvidenceValidationService(cache: cache,transport: transport)
        let online = await service.validate(one,authenticatedLists: [try list()],mode: .online,observedAt: try now())
        XCTAssertEqual(online.first?.revocation.state,.good);XCTAssertEqual(online.first?.time.state,.proven)
        let latest = try now().addingTimeInterval(30)
        XCTAssertTrue(online.flatMap { $0.revocation.certificates }.allSatisfy { $0.evaluatedAt < latest })
        let offline = await service.validate(one,authenticatedLists: [try list()],mode: .offline,observedAt: try now())
        XCTAssertEqual(offline.first?.revocation.state,.good);XCTAssertEqual(offline.first?.time.state,.proven)
        let revoked = try await cache.store(.init(kind: .ocsp,der: data("revoked","ocsp")),certificate: data("leaf","der"),issuer: issuer,now: now())
        XCTAssertEqual(revoked.state,.revoked)
        let cachedRevoked = await service.validate(one,authenticatedLists: [try list()],mode: .offline,observedAt: try now())
        XCTAssertEqual(cachedRevoked.first?.revocation.state,.revoked,"Observed revocation must persist for offline checks")
        let absentTransport = Transport()
        let absent = await SignatureEvidenceValidationService(transport: absentTransport).validate(one,authenticatedLists: [try list()],mode: .online,observedAt: try now())
        XCTAssertEqual(absent.first?.revocation.state,.indeterminate);XCTAssertEqual(absent.first?.time.state,.indeterminate)
        let count = await absentTransport.calls;XCTAssertLessThanOrEqual(count,8)
        XCTAssertEqual(CertificateEvidenceMaterial.locations(try data("leaf","der")).map(\.url.scheme),["http","https"])
    }
    func testNoTimestampStillChecksBothSignersRevocationAndNeverPromotesQES() async throws {
        let original = try report()
        let signatures = original.signatures.map { value in
            var s = value
            if let old = value.evidence { s.evidence = envelope(old, tokens: []) }
            return s
        }
        let current = replace(original, signatures), at = try now(), tl = try list()
        let values = await SignatureEvidenceValidationService().validate(current, authenticatedLists: [tl], mode: .offline, observedAt: at)
        XCTAssertEqual(values.count, 2)
        for s in signatures {
            let value = try XCTUnwrap(values.first { $0.signatureID == s.id })
            XCTAssertEqual(value.revocation.state, s.signerDER == (try data("leaf", "der")) ? .good : .revoked)
            XCTAssertEqual(value.time.state, .notProven)
            let qualification = SignatureQualificationService.assess(s, evidence: value, lists: [tl], mode: .offline, observedAt: at)
            XCTAssertEqual(qualification.state, .indeterminate)
            XCTAssertEqual(qualification.qscd, .indeterminate)
            XCTAssertNotNil(qualification.statements)
        }

    }

    func testEndpointPolicyRejectsArbitrarySchemesPrivateAddressesAndCancellation() async throws {
        for value in ["file:///etc/passwd","ftp://example.org/a","http://127.0.0.1/a","http://user@example.org/a","https://example.org:8443/a","http://x.local/a"] {
            XCTAssertFalse(EndpointPolicy.valid(try XCTUnwrap(URL(string: value))))
        }
        for ip in ["127.0.0.1","10.1.2.3","169.254.169.254","::1","::ffff:127.0.0.1","fc00::1","2002:7f00:1::"] { XCTAssertFalse(EndpointPolicy.publicAddress(ip),ip) }
        XCTAssertTrue(EndpointPolicy.publicAddress("8.8.8.8"));XCTAssertTrue(EndpointPolicy.publicAddress("2606:4700::1111"))
        let transport = Transport()
        let result = await SignatureEvidenceValidationService(transport: transport).validate(try report(),authenticatedLists: [try list()],mode: .online,observedAt: try now(),isCancelled: { true })
        XCTAssertTrue(result.isEmpty);let count = await transport.calls;XCTAssertEqual(count,0)
    }
}
