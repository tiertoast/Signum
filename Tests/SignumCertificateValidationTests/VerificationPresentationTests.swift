import XCTest
@testable import SignumCore
@testable import SignumApp
@testable import SignumCertificateValidation
import SignumVerificationReports

final class VerificationPresentationTests: XCTestCase {
    func signature(_ integrity: CryptographicIntegrity = .verified) -> SignatureVerificationResult {
        .init(id: 0, integrity: integrity, certificate: nil, algorithm: "RSA-SHA256", declaredTime: "", reason: "", signedRevisionEnd: nil, laterChanges: false, cmsLayer: 0)
    }
    func qualification(_ state: SignatureQualificationState, mode: SignatureEvaluationMode) -> SignatureQualificationResult {
        .init(signatureID: 0, state: state, qualifiedCertificate: .indeterminate, qscd: .indeterminate, evaluatedAt: Date(), service: nil, reason: "", statements: nil, evaluationMode: mode)
    }
    func time(_ state: SignatureTimeState) -> SignatureTimeResult {
        .init(state: state, declaredSigningTime: "", provenTime: nil, reason: "", authorities: [])
    }
    func testCurrentQESIsExplicitlyCurrentAndHistoricalIndeterminateIsNotGreen() {
        let current = VerificationPresentation.qualification(qualification(.qualified, mode: .currentTime))
        XCTAssertEqual(current.tone, .positive)
        XCTAssertTrue(current.value.contains("alla data di verifica"))
        let historical = VerificationPresentation.qualification(qualification(.indeterminate, mode: .historical))
        XCTAssertEqual(historical.tone, .uncertain)
        XCTAssertFalse(historical.symbol.contains("checkmark"))
        XCTAssertTrue(VerificationPresentation.qualification(qualification(.qualified, mode: .historical)).value.contains("all’istante comprovato"))
    }
    func testAlteredRevokedUnknownAndMissingHaveDistinctNonGreenStates() {
        XCTAssertEqual(VerificationPresentation.integrity(.invalid).tone, .negative)
        XCTAssertEqual(VerificationPresentation.revocation(.revoked).tone, .negative)
        XCTAssertEqual(VerificationPresentation.provider(.unavailable("unknown")).tone, .uncertain)
        XCTAssertEqual(VerificationPresentation.provider(nil).tone, .uncertain)
        XCTAssertEqual(VerificationPresentation.revocation(.indeterminate).tone, .uncertain)
        XCTAssertEqual(VerificationPresentation.qualification(nil).tone, .uncertain)
    }
    func testTimestampValidAbsentInvalidAndUnresolved() {
        var s = signature()
        XCTAssertEqual(VerificationPresentation.timestamp(s, time: nil).value, "Non determinabile")
        s.evidence = .init(signatureValue: Data(), signatureKey: "", signerIndex: 0, signedAttributes: [], unsignedAttributes: [], timestampTokens: [], embedded: [], issue: "")
        XCTAssertEqual(VerificationPresentation.timestamp(s, time: time(.notProven)).value, "Assente")
        XCTAssertEqual(VerificationPresentation.timestamp(s, time: time(.proven)).tone, .positive)
        XCTAssertEqual(VerificationPresentation.timestamp(s, time: time(.invalid)).tone, .negative)
        XCTAssertEqual(VerificationPresentation.timestamp(s, time: time(.indeterminate)).tone, .uncertain)
    }
    func testMixedSignaturesDoNotShareAnOutcome() {
        let values = [CryptographicIntegrity.verified, .invalid, .notVerifiable].map(VerificationPresentation.integrity)
        XCTAssertEqual(values.map(\.tone), [.positive, .negative, .uncertain])
    }
    @MainActor func testFinderRequestsCoalesceAndReachVerificationWorkspace() async throws {
        let inbox = SystemDocuments()
        let first = URL(fileURLWithPath: "/synthetic/first.p7m")
        let second = URL(fileURLWithPath: "/synthetic/second.pdf")
        inbox.receive([first])
        inbox.receive([second, URL(string: "https://example.invalid/not-local")!])
        let request = try XCTUnwrap(inbox.next())
        XCTAssertEqual(request.urls, [first, second])
        XCTAssertNil(inbox.next())
        let workspace = VerificationWorkspace()
        await workspace.verify(request.urls, using: { url, _ in
            .init(id: UUID(), documentName: url.lastPathComponent, sha256: String(repeating: "a", count: 64),
                  format: url.pathExtension == "pdf" ? .pades : .cades, signatures: [], documentState: "unsigned",
                  issue: "", previewPDF: nil, originalContent: nil)
        })
        XCTAssertEqual(workspace.rows.map(\.name), ["first.p7m", "second.pdf"])
        XCTAssertEqual(workspace.rows.compactMap(\.report).map(\.format), [.cades, .pades])
        XCTAssertFalse(workspace.busy)
    }
    func testExplicitTimeZonesAcrossItalianDSTBoundary() throws {
        let before = try XCTUnwrap(VerificationPresentation.declaredInstant("Oct 24 12:41:52 2026 GMT"))
        let after = try XCTUnwrap(VerificationPresentation.declaredInstant("2026-10-25T16:23:11Z"))
        XCTAssertEqual(before, ISO8601DateFormatter().date(from: "2026-10-24T12:41:52Z"))
        let zone = try XCTUnwrap(TimeZone(identifier: "Europe/Rome"))
        XCTAssertEqual(zone.secondsFromGMT(for: before), 7200)
        XCTAssertEqual(zone.secondsFromGMT(for: after), 3600)
        XCTAssertEqual(VerificationPresentation.declaredInstant("2026-10-24T14:41:52+02:00"), before)
        XCTAssertNil(VerificationPresentation.declaredInstant("24/10/2026 12:41"))
        XCTAssertNil(VerificationPresentation.declaredInstant("Feb 30 12:00:00 2026 GMT"))
    }
    func testCommercialNameIsOnlyAShortPresentationOfAuthenticatedProvider() {
        XCTAssertEqual(VerificationPresentation.providerName("InfoCamere S.C.p.A."), "InfoCamere")
        XCTAssertEqual(VerificationPresentation.providerName("Unknown InfoCamere issuer"), "Unknown InfoCamere issuer")
    }
    // Minimal DER envelopes exercise the informational reader only, not X.509 trust.
    func node(_ tag: UInt8, _ content: Data) -> Data {
        let n = content.count
        let size: [UInt8] = n < 128 ? [UInt8(n)] : n < 256 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 255)]
        return Data([tag] + size) + content
    }
    func policyCertificate(notice: String?, oid: [UInt8] = [0x2b, 0x4c, 0x10, 0x06], cps: Bool = false) -> Data {
        func seq(_ d: Data) -> Data { node(0x30, d) }
        var policy = node(6, Data(oid))
        if let notice {
            let qualifier = node(6, Data([0x2b,6,1,5,5,7,2,cps ? 1 : 2]))
            let text = node(cps ? 0x16 : 12, Data(notice.utf8))
            policy += seq(seq(qualifier + (cps ? text : seq(text))))
        }
        let ext = seq(node(6, Data([0x55,0x1d,0x20])) + node(4, seq(seq(policy))))
        return seq(seq(node(0xa3, seq(ext))) + seq(Data()) + node(3, Data([0])))
    }
    let notice = "Questo certificato rispetta le raccomandazioni previste dalla Determinazione Agid N. 121/2019"
    func testAgIDNoticeAndOriginalProvenanceArePreserved() {
        let p = CertificatePolicyPresentation(certificate: policyCertificate(notice: notice))
        XCTAssertTrue(p.available); XCTAssertTrue(p.agidDeclared)
        XCTAssertEqual(p.policies.first?.oid, "1.3.76.16.6")
        XCTAssertEqual(p.policies.first?.notices, [notice])
        XCTAssertEqual(p.summary, "Raccomandazioni AgID: dichiarate dal certificatore")
        XCTAssertTrue(CertificatePolicyPresentation.reference.contains("147/2019"))
        XCTAssertTrue(CertificatePolicyPresentation.reference.contains("189/2017"))
    }
    func testOIDAloneUnrelatedNoticeNegationAndCPSCannotDeclareAgID() {
        for p in [
            policyCertificate(notice: nil),
            policyCertificate(notice: "Determinazione AgID 189/2017"),
            policyCertificate(notice: "Questo certificato non rispetta le raccomandazioni previste dalla Determinazione Agid N. 121/2019"),
            policyCertificate(notice: notice, oid: [0x2a,3]),
            policyCertificate(notice: notice, cps: true)
        ] { XCTAssertFalse(CertificatePolicyPresentation(certificate: p).agidDeclared) }
    }
    func testUnavailableAndMalformedPoliciesCannotDeclareAgID() {
        for d in [nil, Data(), Data([0x30,0x80,0,0]), Data(repeating: 0, count: 65537)] {
            let p = CertificatePolicyPresentation(certificate: d)
            XCTAssertFalse(p.available); XCTAssertFalse(p.agidDeclared)
        }
    }
}
