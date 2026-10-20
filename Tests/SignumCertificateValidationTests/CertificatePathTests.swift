import XCTest
@testable import SignumApp
import SignumTrustIntegration
import SignumCore
import SignumTrustCore
import SignumTrustAuthentication
@testable import SignumCertificateValidation

final class CertificatePathTests: XCTestCase {
    let now = ISO8601DateFormatter().date(from: "2026-10-21T12:00:00Z")!
    func data(_ name: String, _ ext: String = "der") throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")))
    }
    func identity(_ name: String, label: String = "Synthetic Service", eligible: Bool = true) throws -> CertificatePathValidator.Identity {
        let der = try data(name)
        return .init(match: .init(provider: "Synthetic Provider", service: label, country: "IT", status: eligible ? CertificatePathValidator.granted : "withdrawn", statusSince: now.addingTimeInterval(-86400), listSequence: 999, historical: false, identitySHA256: CertificatePathValidator.hash(der)), der: der, eligible: eligible)
    }
    func evaluate(_ leaf: String = "leaf", _ chain: [String] = ["intermediate"], anchors: [String] = ["root-a"]) throws -> CertificatePathResult {
        CertificatePathValidator.evaluate(signer: try data(leaf), intermediates: try chain.map { try data($0) }, identities: try anchors.map { try identity($0) }, now: now)
    }
    func testCorrectChainAndDuplicateIntermediates() throws {
        let result = try evaluate("leaf", ["intermediate", "intermediate", "root-a"])
        XCTAssertEqual(result.state, .verified, result.reason);XCTAssertEqual(result.path.count, 3)
        XCTAssertEqual(result.path.first?.sha256, CertificatePathValidator.hash(try data("leaf")))
        XCTAssertEqual(result.path.last?.sha256, CertificatePathValidator.hash(try data("root-a")))
        XCTAssertEqual(result.service?.country, "IT")
        let extraneous = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [Data([0,1]), try data("intermediate")], identities: [try identity("root-a")], now: now)
        XCTAssertEqual(extraneous.state, .verified, extraneous.reason)
    }
    func testMissingIntermediateUnknownAuthorityAndWrongIntermediate() throws {
        for result in [try evaluate("leaf", []), try evaluate(anchors: ["root-b"]), try evaluate("leaf", ["wrong-intermediate"])] {
            XCTAssertEqual(result.state, .notVerifiable, result.reason)
        }
    }
    func testAlteredIntermediateAndLeafValidity() throws {
        XCTAssertEqual(try evaluate("leaf", ["altered-intermediate"]).state, .invalid)
        var altered = try data("leaf");altered[altered.count - 1] ^= 1
        let tampered = CertificatePathValidator.evaluate(signer: altered, intermediates: [try data("intermediate")], identities: [try identity("root-a")], now: now)
        XCTAssertEqual(tampered.state, .invalid);XCTAssertFalse(tampered.path.isEmpty)
        for name in ["expired", "future"] { let result = try evaluate(name);XCTAssertEqual(result.state, .invalid, result.reason) }
    }
    func testCriticalBasicUsagePathLengthNameAndAlgorithmConstraints() throws {
        for (leaf, chain) in [("critical", ["intermediate"]),("bad-ku", ["intermediate"]),("bad-eku", ["intermediate"]),("bad-basic", ["not-ca"]),("bad-pathlen", ["subca", "path-zero"]),("bad-name", ["name-ca"]),("sha1", ["intermediate"])] {
            let result = try evaluate(leaf, chain)
            XCTAssertEqual(result.state, .invalid, "\(leaf): \(result.reason)")
        }
    }
    func testNonSelfSignedServiceAndAlternativeCrossSignedPaths() throws {
        XCTAssertEqual(try evaluate("leaf", ["altered-intermediate", "wrong-intermediate", "intermediate"]).state, .verified)
        let direct = try evaluate(anchors: ["intermediate"])
        XCTAssertEqual(direct.state, .verified, direct.reason);XCTAssertEqual(direct.path.count, 2)
        let cross = try evaluate("leaf", ["intermediate", "cross"], anchors: ["root-b"])
        XCTAssertEqual(cross.state, .verified, cross.reason)
        XCTAssertEqual(cross.path.last?.sha256, CertificatePathValidator.hash(try data("root-b")))
        let both = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: try ["intermediate","cross"].map { try data($0) }, identities: try [identity("root-a",label: "A"),identity("root-b",label: "B")], now: now)
        XCTAssertEqual(both.state, .verified);XCTAssertEqual(both.service?.service, "A");XCTAssertEqual(both.alternativeServices.first?.service, "B")
    }
    func authenticated(_ name: String, at date: Date? = nil) throws -> AuthenticatedTL {
        try TLAuthenticator.authenticate(data(name,"xml"), authorizedCertificateSHA256: [TLAuthenticator.sha256(data("tl-signer"))], territory: "IT", now: date ?? now)
    }
    func testOfflineAuthenticatedTLIdentityAndWithdrawnService() throws {
        let tl = try authenticated("trusted")
        let result = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [try data("intermediate")], authenticatedLists: [tl], now: now)
        XCTAssertEqual(result.state, .verified, result.reason);XCTAssertEqual(result.service?.identitySHA256, CertificatePathValidator.hash(try data("root-a")))
        let withdrawn = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [try data("intermediate")], authenticatedLists: [try authenticated("withdrawn")], now: now)
        XCTAssertEqual(withdrawn.state, .notVerifiable);XCTAssertNotNil(withdrawn.service)
    }
    func testHistoricalIdentityDoesNotAuthorizeTodayAndExpiredList() throws {
        let tl = try authenticated("history")
        XCTAssertEqual(tl.document.providers.first?.services.first?.history.first?.certificateDERs, [try data("root-a")])
        let result = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [try data("intermediate")], authenticatedLists: [tl], now: now)
        XCTAssertEqual(result.state, .notVerifiable, result.reason);XCTAssertEqual(result.service?.identitySHA256, CertificatePathValidator.hash(try data("root-a")))
        XCTAssertEqual(result.service?.historical, true)
        let later = ISO8601DateFormatter().date(from: "2027-04-02T00:00:00Z")!
        XCTAssertEqual(CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [], authenticatedLists: [tl], now: later).state, .notVerifiable)
        var altered = try data("trusted","xml");altered[100] ^= 1
        XCTAssertThrowsError(try TLAuthenticator.authenticate(altered, authorizedCertificateSHA256: [TLAuthenticator.sha256(data("tl-signer"))], territory: "IT", now: now))
    }
    func testUnsupportedCertificateSignatureAlgorithmIsNotVerifiable() throws {
        var der = try data("leaf")
        let oid = Data([6,9,42,134,72,134,247,13,1,1,11])
        var found = 0, offset = 0
        while offset < der.count, let range = der.range(of: oid, in: offset..<der.count) {
            der[range.upperBound - 1] = 99;offset = range.upperBound;found += 1
        }
        XCTAssertEqual(found, 2)
        let result = CertificatePathValidator.evaluate(signer: der, intermediates: [try data("intermediate")], identities: [try identity("root-a")], now: now)
        XCTAssertEqual(result.state, .notVerifiable, result.reason)
    }
    func testLimitsCancellationAndUntrustedNamesNeverAuthorize() throws {
        let result = CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [], identities: [try identity("root-a")], now: now, isCancelled: { true })
        XCTAssertEqual(result.state, .notVerifiable)
        XCTAssertEqual(CertificatePathValidator.evaluate(signer: try data("leaf"), intermediates: [], identities: [], now: now).state, .notVerifiable)
        XCTAssertEqual(CertificatePathValidator.evaluate(signer: Data([1,2]), intermediates: [], identities: [try identity("root-a")], now: now).state, .invalid)
    }
    private struct Catalog: TrustedListCatalogProviding {
        let list: AuthenticatedTL
        func currentCatalog() async throws -> AuthenticatedTL? { list }
    }
    @MainActor func testWorkspaceUsesAuthenticatedCatalogAndKeepsIntegrityIndependent() async throws {
        guard let path = ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Official helper required") }
        let file = try XCTUnwrap(Bundle.module.url(forResource: "valid-untrusted", withExtension: "cms", subdirectory: "Fixtures"))
        let verifier: VerificationWorkspace.Verifier = { url, control in
            try SignumVerificationService.verify(file: url, helper: URL(fileURLWithPath: path), isCancelled: { control.isCancellationRequested })
        }
        let workspace = VerificationWorkspace(catalog: Catalog(list: try authenticated("trusted")))
        let start = Date()
        await workspace.verify([file], using: verifier)
        XCTAssertEqual(workspace.rows.first?.report?.integrity, .verified)
        XCTAssertEqual(workspace.rows.first?.paths[0]?.state, .verified)
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(workspace.rows.first?.paths[0]?.evaluatedAt), start)
        XCTAssertEqual(workspace.rows.first?.report?.revocation, .notChecked)
        let unavailable = VerificationWorkspace()
        await unavailable.verify([file], using: verifier)
        XCTAssertEqual(unavailable.rows.first?.report?.integrity, .verified)
        XCTAssertEqual(unavailable.rows.first?.paths[0]?.state, .notVerifiable)
    }
    func testValidCAdESIntegrityRemainsSeparateFromTrust() throws {
        guard let helper = ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Run with the official native helper") }
        let report = try SignumVerificationService.verify(data: data("valid-untrusted","cms"), name: "synthetic", helper: URL(fileURLWithPath: helper))
        XCTAssertEqual(report.integrity, .verified)
        let signature = try XCTUnwrap(report.signatures.first)
        XCTAssertEqual(signature.signerDER, try data("leaf"));XCTAssertEqual(signature.embeddedCertificateDERs.count, 3)
        XCTAssertEqual(CertificatePathValidator.evaluate(signer: try XCTUnwrap(signature.signerDER), intermediates: signature.embeddedCertificateDERs, authenticatedLists: [], now: now).state, .notVerifiable)
        let trusted = CertificatePathValidator.evaluate(signer: try XCTUnwrap(signature.signerDER), intermediates: signature.embeddedCertificateDERs, authenticatedLists: [try authenticated("trusted")], now: now)
        XCTAssertEqual(trusted.state, .verified, trusted.reason);XCTAssertEqual(report.revocation,.notChecked);XCTAssertEqual(report.qualification,.notChecked)
    }
}
