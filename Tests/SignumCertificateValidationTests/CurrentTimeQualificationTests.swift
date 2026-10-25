import XCTest
@testable import SignumCore
@testable import SignumCertificateValidation
import SignumTrustCore
import SignumTrustAuthentication
import SignumTrustIntegration
@testable import SignumApp

final class CurrentTimeQualificationTests: XCTestCase {
    func data(_ name: String, _ ext: String) throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:ext,subdirectory:"Fixtures/Qualification")))
    }
    func now() throws -> Date {
        let c = try JSONDecoder().decode([String:String].self,from:data("clock","json"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from:XCTUnwrap(c["evaluatedAt"])))
    }
    func list(_ name: String = "authorized") throws -> AuthenticatedTL {
        try TLAuthenticator.authenticate(data(name,"xml"),authorizedCertificateSHA256:[TLAuthenticator.sha256(data("issuer","der"))],territory:"IT",now:now())
    }
    func verify(_ bytes: Data, ext: String = "cms") throws -> VerificationReport {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        return try SignumVerificationService.verify(data:bytes,name:"fixture."+ext,helper:URL(fileURLWithPath:helper))
    }
    // Remove ONLY the unsigned signatureTimeStamp from the frozen public CMS.
    // Signed attributes and SignatureValue remain byte-identical and are reverified natively.
    func withoutTimestamp() throws -> VerificationReport {
        func encode(_ tag: UInt8, _ bytes: [UInt8]) -> [UInt8] {
            var n = bytes.count, size = [UInt8]()
            if n < 128 { size = [UInt8(n)] } else {
                while n > 0 { size.insert(UInt8(n & 255),at:0); n >>= 8 }
                size.insert(0x80 | UInt8(size.count),at:0)
            }
            return [tag]+size+bytes
        }
        func raw(_ d: QualificationDER) -> [UInt8] { encode(d.tag,d.bytes) }
        let root = try QualificationDER(data("multi","cms")).children()
        let sd = try root[1].children(0xa0)[0].children()
        let signers = try sd.last!.children(0x31).map { signer -> [UInt8] in
            var fields = try signer.children()
            if fields.last?.tag == 0xa1 {
                let attrs = try fields.removeLast().children(0xa1).filter {
                    try $0.children()[0].oid() != "1.2.840.113549.1.9.16.2.14"
                }
                return encode(0x30,fields.flatMap(raw)+(attrs.isEmpty ? [] : encode(0xa1,attrs.flatMap(raw))))
            }
            return raw(signer)
        }.sorted { $0.lexicographicallyPrecedes($1) }
        let bytes = encode(0x30,raw(root[0])+encode(0xa0,encode(0x30,sd.dropLast().flatMap(raw)+encode(0x31,signers.flatMap { $0 }))))
        let report = try verify(Data(bytes))
        XCTAssertEqual(report.integrity,.verified)
        XCTAssertTrue(report.signatures.allSatisfy { $0.evidence?.timestampTokens.isEmpty == true })
        return report
    }
    // Component-level missing-evidence cases for both CMS and PDF revision records.
    func stripped(_ report: VerificationReport, revocation: Bool = false) -> VerificationReport {
        let signatures = report.signatures.map { s -> SignatureVerificationResult in
            var s = s
            if let e = s.evidence {
                s.evidence = .init(signatureValue:e.signatureValue,signatureKey:e.signatureKey,signerIndex:e.signerIndex,
                    signedAttributes:e.signedAttributes,unsignedAttributes:[],timestampTokens:[],embedded:revocation ? [] : e.embedded,issue:"")
            }
            return s
        }
        return .init(id:report.id,documentName:report.documentName,sha256:report.sha256,format:report.format,signatures:signatures,
                     documentState:report.documentState,issue:report.issue,previewPDF:nil,originalContent:nil)
    }
    final class ReplayClock: @unchecked Sendable {
        private let lock = NSLock()
        private var seconds: TimeInterval = 0
        func read() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return seconds }
        func advance() { lock.lock(); seconds += 2; lock.unlock() }
    }
    actor ReplayTransport: RevocationTransport {
        let clock: ReplayClock, ocsp: Data
        let crl: Data?
        private(set) var calls = 0
        init(clock: ReplayClock, ocsp: Data, crl: Data? = nil) { self.clock = clock; self.ocsp = ocsp; self.crl = crl }
        func fetch(_ location: RevocationLocation, body: Data?, isCancelled: @escaping @Sendable () -> Bool) async throws -> Data {
            calls += 1
            if location.kind == .ocsp { clock.advance(); return ocsp }
            if let crl { return crl }
            throw ClientError.response
        }
    }
    func singleSignerWithoutValidationData() throws -> VerificationReport {
        let report = try withoutTimestamp()
        var s = try XCTUnwrap(report.signatures.first { $0.signerDER == (try? data("leaf", "der")) })
        let e = try XCTUnwrap(s.evidence)
        s.evidence = .init(signatureValue:e.signatureValue,signatureKey:e.signatureKey,signerIndex:e.signerIndex,
            signedAttributes:e.signedAttributes,unsignedAttributes:[],timestampTokens:[],embedded:[],issue:"")
        return .init(id:report.id,documentName:report.documentName,sha256:report.sha256,format:report.format,
            signatures:[s],documentState:report.documentState,issue:report.issue,previewPDF:nil,originalContent:nil)
    }
    func testOnlineAcquisitionIsReauthenticatedAtCompletionWithoutCacheOrExtraRequests() async throws {
        // Frozen fixture producedAt is clock-120. The acquisition advances a fake
        // monotonic clock; no sleep or network is needed to cross that boundary.
        let start = try now().addingTimeInterval(-121), report = try singleSignerWithoutValidationData()
        let clock = ReplayClock(), transport = ReplayTransport(clock:clock,ocsp:try data("good","ocsp"))
        let service = SignatureQualificationService(transport:transport,monotonicClock:{clock.read()})
        let values = await service.validate(report,authenticatedLists:[try list()],mode:.online,
            observedAt:start,evaluationMode:.bestAvailable)
        let value = try XCTUnwrap(values.first)
        XCTAssertEqual(value.qualification.state,.qualified,value.qualification.reason)
        XCTAssertEqual(value.evidence.revocation.state,.good,value.evidence.revocation.reason)
        XCTAssertEqual(value.evidence.time.state,.notProven); XCTAssertNil(value.evidence.time.provenTime)
        XCTAssertEqual(value.qualification.verificationDate,start.addingTimeInterval(2))
        XCTAssertEqual(value.path.evaluatedAt,value.qualification.evaluatedAt)
        XCTAssertEqual(value.evidence.revocationPath?.evaluatedAt,value.qualification.evaluatedAt)
        let calls = await transport.calls; XCTAssertEqual(calls,2,"One OCSP + one CRL attempt; offline reassessment must not fetch")
    }
    func testEvidenceExpiringDuringAcquisitionCannotProduceCurrentQES() async throws {
        let response = RevocationEvidence(kind:.ocsp,der:try data("good","ocsp"))
        let checked = RevocationEvidenceVerifier.verify(response,certificate:try data("leaf","der"),issuer:try data("issuer","der"),now:try now())
        let end = try XCTUnwrap(checked.nextUpdate), start = end.addingTimeInterval(-1)
        let clock = ReplayClock(), transport = ReplayTransport(clock:clock,ocsp:response.der)
        let values = await SignatureQualificationService(transport:transport,monotonicClock:{clock.read()})
            .validate(try singleSignerWithoutValidationData(),authenticatedLists:[try list()],mode:.online,observedAt:start,evaluationMode:.currentTime)
        let value = try XCTUnwrap(values.first)
        XCTAssertEqual(value.qualification.state,.indeterminate)
        XCTAssertEqual(value.evidence.revocation.state,.indeterminate)
        XCTAssertEqual(value.qualification.verificationDate,end.addingTimeInterval(1))
    }

    func testUnusableAlternateEvidenceDoesNotMaskGoodButAuthenticatedRevocationWins() async throws {
        let report = try singleSignerWithoutValidationData(), start = try now()
        for (crl, expected) in [("restricted",SignatureRevocationState.good),("revoked",.revoked)] {
            let clock = ReplayClock(), transport = ReplayTransport(clock:clock,ocsp:try data("good","ocsp"),crl:try data(crl,"crl"))
            let values = await SignatureQualificationService(transport:transport,monotonicClock:{clock.read()})
                .validate(report,authenticatedLists:[try list()],mode:.online,observedAt:start,evaluationMode:.currentTime)
            let value = try XCTUnwrap(values.first)
            XCTAssertEqual(value.evidence.revocation.state,expected,value.evidence.revocation.reason)
            XCTAssertEqual(value.qualification.state,expected == .good ? .qualified : .indeterminate,value.qualification.reason)
            if expected == .good { XCTAssertEqual(value.evidence.revocation.certificates.count,1,"One selected authenticated witness per certificate") }
        }
    }
    func testReassessmentCannotPromoteFutureExpiredAlteredOrRevokedEvidence() async throws {
        let report = try singleSignerWithoutValidationData()
        for (name, offset) in [("good",-130.0),("good",172800.0),("altered",0.0),("revoked",0.0)] {
            let clock = ReplayClock(), transport = ReplayTransport(clock:clock,ocsp:try data(name,"ocsp"))
            let values = await SignatureQualificationService(transport:transport,monotonicClock:{clock.read()})
                .validate(report,authenticatedLists:[try list()],mode:.online,observedAt:try now().addingTimeInterval(offset),evaluationMode:.currentTime)
            XCTAssertTrue(values.allSatisfy { $0.qualification.state != .qualified },name)
        }
        let clock = ReplayClock(), transport = ReplayTransport(clock:clock,ocsp:try data("good","ocsp"))
        let cancelled = await SignatureQualificationService(transport:transport,monotonicClock:{clock.read()})
            .validate(report,authenticatedLists:[try list()],mode:.online,observedAt:try now(),evaluationMode:.currentTime,isCancelled:{true})
        XCTAssertTrue(cancelled.isEmpty)
        let calls = await transport.calls; XCTAssertEqual(calls,0)
    }

    func testUntimestampedCMSCurrentAndAutomaticPositiveButHistoricalIndeterminate() async throws {
        let report = try withoutTimestamp(), at = try now(), tl = try list()
        for mode in [SignatureEvaluationMode.currentTime,.bestAvailable,.historical] {
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[tl],mode:.offline,observedAt:at,evaluationMode:mode)
            XCTAssertEqual(values.count,2)
            for v in values {
                XCTAssertEqual(v.evidence.time.state,.notProven); XCTAssertNil(v.evidence.time.provenTime)
                XCTAssertEqual(v.evidence.revocation.state,.good,v.evidence.revocation.reason)
                let qualified = v.qualification.statements?.compliance == true
                XCTAssertEqual(v.qualification.state,mode == .historical ? .indeterminate : qualified ? .qualified : .electronic,v.qualification.reason)
                XCTAssertEqual(v.qualification.verificationDate,at)
                if mode != .historical {
                    XCTAssertEqual(v.qualification.evaluatedAt,at); XCTAssertEqual(v.qualification.evaluationMode,.currentTime)
                    XCTAssertEqual(v.evidence.revocationPath?.evaluatedAt,at)
                    XCTAssertEqual(v.path.evaluatedAt,at)
                }
            }
        }
    }
    func testPDFWithoutTemporalEvidenceAndMissingRevocationRemainIndependent() async throws {
        let original = try verify(data("multi","pdf"),ext:"pdf"), at = try now(), tl = try list()
        for missing in [false,true] {
            let report = stripped(original,revocation:missing)
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[tl],mode:.offline,observedAt:at,evaluationMode:.bestAvailable)
            XCTAssertEqual(values.count,2)
            XCTAssertTrue(values.allSatisfy { $0.evidence.time.state == .notProven && $0.evidence.time.provenTime == nil })
            let q = try XCTUnwrap(values.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(q.qualification.state,missing ? .indeterminate : .qualified,q.qualification.reason)
            XCTAssertEqual(q.evidence.revocation.state,missing ? .indeterminate : .good)
        }
    }
    func testNoTimestampRevokedMissingStaleAndUnboundPathNeverPositive() async throws {
        let report = try withoutTimestamp(), at = try now(), tl = try list()
        let values = await SignatureQualificationService().validate(report,authenticatedLists:[tl],observedAt:at,evaluationMode:.currentTime)
        let value = try XCTUnwrap(values.first { $0.qualification.state == .qualified })
        let s = try XCTUnwrap(report.signatures.first { $0.id == value.signatureID })
        for state in [SignatureRevocationState.revoked,.indeterminate,.good] {
            let e = SignatureEvidenceValidationResult(signatureID:s.id,revocation:.init(state:state,reason:"synthetic missing data",certificates:[]),time:value.evidence.time,associations:[],revocationPath:value.evidence.revocationPath)
            XCTAssertEqual(SignatureQualificationService.assess(s,evidence:e,lists:[tl],mode:.offline,observedAt:at,evaluationMode:.currentTime).state,.indeterminate)
        }
        for delta in [-1.0, 1.0] {
            let records = value.evidence.revocation.certificates.map { r in
                RevocationEvidenceResult(state:.good,kind:r.kind,evaluatedAt:at,thisUpdate:delta > 0 ? at.addingTimeInterval(delta) : r.thisUpdate,nextUpdate:delta < 0 ? at.addingTimeInterval(delta) : r.nextUpdate,revokedAt:nil,reason:"synthetic stale/future")
            }
            let e = SignatureEvidenceValidationResult(signatureID:s.id,revocation:.init(state:.good,reason:"synthetic",certificates:records),time:value.evidence.time,associations:[],revocationPath:value.evidence.revocationPath)
            XCTAssertEqual(SignatureQualificationService.assess(s,evidence:e,lists:[tl],mode:.offline,observedAt:at,evaluationMode:.currentTime).state,.indeterminate)
        }
        let noPath = SignatureEvidenceValidationResult(signatureID:s.id,revocation:value.evidence.revocation,time:value.evidence.time,associations:[])
        XCTAssertEqual(SignatureQualificationService.assess(s,evidence:noPath,lists:[tl],mode:.offline,observedAt:at,evaluationMode:.currentTime).state,.indeterminate)
        let late = at.addingTimeInterval(400*86400)
        let expired = await SignatureQualificationService().validate(report,authenticatedLists:[tl],observedAt:late,evaluationMode:.currentTime)
        XCTAssertTrue(expired.allSatisfy { $0.qualification.state == .indeterminate && $0.path.state != .verified })
    }
    func testCurrentServiceQSCDAndCoverageGuards() async throws {
        let at = try now()
        for (name,expected) in [("authorized",SignatureQualificationState.indeterminate),("tl-qscd",.qualified),("withdrawn",.indeterminate),("historical",.indeterminate),("conflict",.indeterminate),("unsupported",.indeterminate)] {
            let report = stripped(try verify(data("noqscd","cms")))
            let v = await SignatureQualificationService().validate(report,authenticatedLists:[try list(name)],observedAt:at,evaluationMode:.currentTime)
            XCTAssertEqual(v.first?.qualification.state,expected,v.first?.qualification.reason ?? "absent")
        }
        let absent = await SignatureQualificationService().validate(try withoutTimestamp(),authenticatedLists:[],observedAt:at,evaluationMode:.currentTime)
        XCTAssertTrue(absent.allSatisfy { $0.qualification.state == .indeterminate })
    }
    func testTimestampHistoricalPreservedAndExplicitCurrentDoesNotReuseHistoricalRevocationPath() async throws {
        let report = try verify(data("multi","cms")), at = try now(), tl = try list()
        for mode in [SignatureEvaluationMode.bestAvailable,.currentTime] {
            let v = await SignatureQualificationService().validate(report,authenticatedLists:[tl],observedAt:at,evaluationMode:mode)
            let q = try XCTUnwrap(v.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(q.qualification.state,.qualified,q.qualification.reason)
            XCTAssertEqual(q.evidence.time.state,.proven)
            XCTAssertEqual(q.qualification.evaluatedAt,mode == .currentTime ? at : q.evidence.time.provenTime)
            XCTAssertEqual(q.evidence.revocationPath?.evaluatedAt,q.qualification.evaluatedAt)
        }
        let bad = await SignatureQualificationService().validate(try verify(data("wrong-imprint","cms")),authenticatedLists:[tl],observedAt:at,evaluationMode:.currentTime)
        XCTAssertTrue(bad.allSatisfy { $0.qualification.state != .qualified })
    }
    func testDeclaredTimeAndInvalidIntegrityCannotSupplyHistoricalProof() async throws {
        let report = try withoutTimestamp(), at = try now(), tl = try list()
        let values = await SignatureQualificationService().validate(report,authenticatedLists:[tl],observedAt:at,evaluationMode:.currentTime)
        let v = try XCTUnwrap(values.first { $0.qualification.state == .qualified })
        let original = try XCTUnwrap(report.signatures.first { $0.id == v.signatureID })
        for integrity in [CryptographicIntegrity.verified,.invalid] {
            var s = SignatureVerificationResult(id:original.id,integrity:integrity,certificate:original.certificate,
                algorithm:original.algorithm,declaredTime:"2000-01-01T00:00:00Z",reason:original.reason,
                signedRevisionEnd:original.signedRevisionEnd,laterChanges:original.laterChanges,cmsLayer:original.cmsLayer)
            s.signerDER = original.signerDER; s.embeddedCertificateDERs = original.embeddedCertificateDERs; s.evidence = original.evidence
            let q = SignatureQualificationService.assess(s,evidence:v.evidence,lists:[tl],mode:.offline,observedAt:at,evaluationMode:.currentTime)
            XCTAssertEqual(q.state,integrity == .verified ? .qualified : .indeterminate,q.reason)
            XCTAssertEqual(SignatureQualificationService.assess(s,evidence:v.evidence,lists:[tl],mode:.offline,observedAt:at).state,.indeterminate)
        }
    }
    private struct Catalog: TrustedListCatalogProviding {
        let value: InterpretedTrustCatalog
        func currentCatalog() async throws -> InterpretedTrustCatalog? { value }
    }
    @MainActor func testWorkspaceSelectsCurrentWithoutTimestamp() async throws {
        let at = try now(), report = try withoutTimestamp()
        let workspace = VerificationWorkspace(catalog:Catalog(value:try list()),validationClock:{ at })
        await workspace.verify([URL(fileURLWithPath:"/synthetic/multi.cms")],using:{ _,_ in report })
        let values = try XCTUnwrap(workspace.rows.first).validations.values
        XCTAssertEqual(values.count,2)
        XCTAssertTrue(values.contains { $0.qualification.state == .qualified && $0.qualification.evaluationMode == .currentTime && $0.evidence.time.state == .notProven })
    }
}
