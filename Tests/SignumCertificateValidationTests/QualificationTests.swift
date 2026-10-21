import XCTest
@testable import SignumCore
@testable import SignumCertificateValidation
import SignumTrustCore
import SignumTrustAuthentication

final class QualificationTests: XCTestCase {
    func data(_ name: String,_ ext: String) throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:ext,subdirectory:"Fixtures/Qualification")))
    }
    func now() throws -> Date {
        let clock = try JSONDecoder().decode([String:String].self,from:data("clock","json"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from:XCTUnwrap(clock["evaluatedAt"])))
    }
    func list(_ name: String = "authorized") throws -> AuthenticatedTL {
        try TLAuthenticator.authenticate(data(name,"xml"),authorizedCertificateSHA256:[TLAuthenticator.sha256(data("issuer","der"))],territory:"IT",now:now())
    }
    func report(_ name: String = "multi",_ ext: String = "cms") throws -> VerificationReport {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        return try SignumVerificationService.verify(data:data(name,ext),name:name,helper:URL(fileURLWithPath:helper))
    }
    func testSixQCStatementsStrictDERAndMetadata() throws {
        let qc = QCStatements.parse(certificate:try data("leaf","der"))
        XCTAssertEqual(qc.issue,""); XCTAssertTrue(qc.compliance); XCTAssertTrue(qc.sscd)
        XCTAssertEqual(qc.types,["0.4.0.1862.1.6.1"])
        XCTAssertEqual(qc.limitValue?.currency,"EUR"); XCTAssertEqual(qc.limitValue?.amount,100)
        XCTAssertEqual(qc.limitValue?.exponent,0); XCTAssertEqual(qc.retentionPeriod,10)
        XCTAssertEqual(qc.pds.first?.language,"it"); XCTAssertEqual(qc.pds.first?.url,"https://pds.example/")
        XCTAssertTrue(qc.unsupported.isEmpty)
        XCTAssertFalse(QCStatements.parse(certificate:try data("leaf-two","der")).compliance)
        XCTAssertFalse(QCStatements.parse(certificate:Data([48,128,0,0])).issue.isEmpty)
        XCTAssertThrowsError(try QualificationDER(Data([48,129,1,0]))) // Non-minimal DER length.
        XCTAssertThrowsError(try CertificateQualificationMaterial(data("leaf","der") + Data([0])))
        // Duplicate QcCompliance and unexpected info must not turn into a positive.
        let oid: [UInt8] = [6,6,4,0,142,70,1,1]
        let entry: [UInt8] = [48,8] + oid
        XCTAssertThrowsError(try CertificateQualificationMaterial.statements(Data([48,20] + entry + entry)))
        XCTAssertThrowsError(try CertificateQualificationMaterial.statements(Data([48,12,48,10] + oid + [5,0])))
    }
    func testQESAndNonQualifiedRemainPerSignerCAdESAndPAdES() async throws {
        for ext in ["cms","pdf"] {
            let report = try report("multi",ext)
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[try list()],mode:.online,observedAt:try now())
            XCTAssertEqual(values.count,2); XCTAssertEqual(report.integrity,.verified)
            for signature in report.signatures {
                let result = try XCTUnwrap(values.first { $0.signatureID == signature.id })
                XCTAssertEqual(result.evidence.time.state,.proven,result.evidence.time.reason)
                XCTAssertEqual(result.evidence.revocation.state,.good,result.evidence.revocation.reason)
                let qualified = signature.signerDER == (try data("leaf","der"))
                XCTAssertEqual(result.qualification.state,qualified ? .qualified : .electronic,result.qualification.reason)
                XCTAssertEqual(result.qualification.qscd,qualified ? .demonstrated : .notDemonstrated)
                XCTAssertEqual(result.qualification.service?.country,"IT")
                XCTAssertEqual(result.qualification.evaluatedAt,result.evidence.time.provenTime)
            }
        }
    }
    func testQualifiedWithoutQSCDAndApplicableTLQualifier() async throws {
        let report = try report("noqscd")
        for (name,state) in [("authorized",SignatureQualificationState.indeterminate),("tl-qscd",.qualified),("wrong-policy",.indeterminate),("unsupported",.indeterminate)] {
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[try list(name)],mode:.online,observedAt:try now())
            let q = try XCTUnwrap(values.first?.qualification)
            XCTAssertEqual(q.state,state,q.reason)
            if name == "authorized" { XCTAssertEqual(q.qualifiedCertificate,.demonstrated); XCTAssertEqual(q.qscd,.notDemonstrated) }
        }
    }
    func testWithdrawnHistoricalAndConflictingServiceNeverQES() async throws {
        for name in ["withdrawn","historical","conflict"] {
            let list = try list(name)
            let values = await SignatureQualificationService().validate(try report(),authenticatedLists:[list],mode:.online,observedAt:try now())
            XCTAssertEqual(values.count,2)
            XCTAssertTrue(values.allSatisfy { $0.qualification.state != .qualified })
            if name == "historical" {
                XCTAssertTrue(values.allSatisfy { $0.qualification.serviceStateFromHistory })
                let time = try now().addingTimeInterval(-120)
                let identities = CertificatePathValidator.identities(list,now:time)
                XCTAssertTrue(identities.contains { $0.eligible }) // Own history identity is actually parsed.
                XCTAssertFalse(CertificatePathValidator.identities(list,now:try now()).contains { $0.eligible })
            }
        }
    }
    func testNoProvenTimeNoCoverageRevokedAndOfflineNeverQES() async throws {
        let report = try report()
        let c = await SignatureEvidenceValidationService().validate(report,authenticatedLists:[try list()],observedAt:try now())
        let signature = try XCTUnwrap(report.signatures.first { $0.signerDER == (try? data("leaf","der")) })
        let evidence = try XCTUnwrap(c.first { $0.signatureID == signature.id })
        let noCoverage = SignatureQualificationService.assess(signature,evidence:evidence,lists:[],mode:.online,observedAt:try now())
        XCTAssertEqual(noCoverage.state,.indeterminate); XCTAssertTrue(noCoverage.reason.contains("Copertura"))
        let noTime = SignatureEvidenceValidationResult(signatureID:signature.id,revocation:evidence.revocation,
            time:.init(state:.notProven,declaredSigningTime:"2000-01-01T00:00:00Z",provenTime:nil,reason:"test",authorities:[]),associations:[])
        XCTAssertEqual(SignatureQualificationService.assess(signature,evidence:noTime,lists:[try list()],mode:.online,observedAt:try now()).state,.indeterminate)
        let revoked = SignatureEvidenceValidationResult(signatureID:signature.id,revocation:.init(state:.revoked,reason:"test",certificates:[]),time:evidence.time,associations:[])
        XCTAssertEqual(SignatureQualificationService.assess(signature,evidence:revoked,lists:[try list()],mode:.online,observedAt:try now()).state,.indeterminate)
        let offline = await SignatureQualificationService().validate(report,authenticatedLists:[try list()],mode:.offline,observedAt:try now())
        XCTAssertTrue(offline.allSatisfy { $0.qualification.state == .indeterminate && $0.qualification.reason.contains("offline") })
        XCTAssertTrue(offline.allSatisfy { $0.evidence.time.state == .proven }) // Independent local results retained.
    }
    func testExtensionNamespacesAndHistoryCannotBorrowQualifiers() throws {
        let list = try list("tl-qscd")
        XCTAssertTrue(list.document.providers.flatMap(\.services).contains { !$0.extensions.isEmpty })
        let data = try data("tl-qscd","xml")
        let raw = try XCTUnwrap(String(data:data,encoding:.utf8))
        // A signed document with a foreign namespace is raw input, never authenticated here.
        let foreign = raw.replacingOccurrences(of:TLQualificationRules.sie,with:"urn:foreign")
        let parsed = try UntrustedTLParser.parse(Data(foreign.utf8))
        let material = try CertificateQualificationMaterial(self.data("leaf-noqscd","der"))
        XCTAssertNil(TLQualificationRules.evaluate(try XCTUnwrap(parsed.providers.first?.services.first?.extensions),material:material))
        let conflict = raw.replacingOccurrences(of:"</ns2:Qualifiers>",with:"<ns2:Qualifier uri=\""+TLQualificationRules.prefix+"QCQSCDStatusAsInCert\"/></ns2:Qualifiers>")
        let conflictingDocument = try UntrustedTLParser.parse(Data(conflict.utf8))
        XCTAssertNil(TLQualificationRules.evaluate(try XCTUnwrap(conflictingDocument.providers.first?.services.first?.extensions),material:material))
        let history = try self.list("historical").document.providers.flatMap(\.services).flatMap(\.history)
        XCTAssertFalse(history.isEmpty); XCTAssertTrue(history.allSatisfy { $0.extensions.isEmpty })
    }
    func testPolicySetRequiresEveryPolicyAndBooleanCriteria() throws {
        let raw = try XCTUnwrap(String(data:data("tl-qscd","xml"),encoding:.utf8))
        func evaluate(_ criterion: String, assertion: String = "all", policies: Set<String> = []) throws -> Set<String>? {
            let xml = raw.replacingOccurrences(of:"<ns2:KeyUsage>.*?</ns2:KeyUsage>",with:criterion,options:.regularExpression)
                .replacingOccurrences(of:"assert=\"all\"",with:"assert=\"\(assertion)\"")
            let parsed = try UntrustedTLParser.parse(Data(xml.utf8))
            var material = try CertificateQualificationMaterial(data("leaf-noqscd","der")); material.policies = policies
            return TLQualificationRules.evaluate(try XCTUnwrap(parsed.providers.first?.services.first?.extensions),material:material)
        }
        func policy(_ oid: String) -> String { "<ns2:PolicyIdentifier><xades:Identifier Qualifier=\"OIDAsURI\">urn:oid:\(oid)</xades:Identifier></ns2:PolicyIdentifier>" }
        let criterion = "<ns2:PolicySet>" + policy("1.2.3.1") + policy("1.2.3.2") + "</ns2:PolicySet>"
        XCTAssertEqual(try evaluate(criterion,policies:["1.2.3.1"]),[])
        XCTAssertTrue(try XCTUnwrap(evaluate(criterion,policies:["1.2.3.1","1.2.3.2"])).contains(TLQualificationRules.prefix+"QCWithQSCD"))
        let a = "<ns2:KeyUsage><ns2:KeyUsageBit name=\"nonRepudiation\">true</ns2:KeyUsageBit></ns2:KeyUsage>"
        let b = "<ns2:KeyUsage><ns2:KeyUsageBit name=\"nonRepudiation\">false</ns2:KeyUsageBit></ns2:KeyUsage>"
        XCTAssertEqual(try evaluate(a+b),[])
        XCTAssertFalse(try XCTUnwrap(evaluate(a+b,assertion:"atLeastOne")).isEmpty)
        XCTAssertEqual(try evaluate(a+b,assertion:"none"),[])
    }
    func testCancellationCannotPublishQualification() async throws {
        let results = await SignatureQualificationService().validate(try report(),authenticatedLists:[try list()],mode:.online,observedAt:try now(),isCancelled:{ true })
        XCTAssertTrue(results.isEmpty)
    }
}
