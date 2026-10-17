#if os(macOS)
import XCTest
import Foundation
import Security
@testable import SignumCore

/// Ephemeral software CA and keys; no keychain, middleware, hardware or real PIN.
final class SyntheticCertificates {
    let folder: URL
    private let openssl = "/usr/bin/openssl"
    private(set) var certificates: [String: Data] = [:]
    init() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("signum-eligibility-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        // Keep only public DER in the shared fixture cache. Remove the ephemeral
        // CA/private keys immediately; static fixtures may live until process exit.
        defer { try? FileManager.default.removeItem(at: folder) }
        try generate()
    }
    deinit { try? FileManager.default.removeItem(at: folder) }
    private func run(_ args: [String]) throws {
        let p = Process(); p.executableURL = URL(fileURLWithPath: openssl); p.arguments = args
        p.currentDirectoryURL = folder
        p.standardOutput = FileHandle.nullDevice
        let error = Pipe(); p.standardError = error
        try p.run()
        let diagnostics = error.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw SignumError.module("Synthetic certificate generation: " + String(decoding: diagnostics, as: UTF8.self))
        }
    }
    private func generate() throws {
        try run(["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rsa.key", "-out", "ca.pem",
                 "-days", "1", "-subj", "/CN=Synthetic Signum CA"])
        try run(["req", "-new", "-key", "rsa.key", "-out", "rsa.csr", "-subj", "/CN=DS3 CNL0 Synthetic Signer"])
        try run(["req", "-new", "-key", "rsa.key", "-out", "other.csr", "-subj", "/CN=Signum Synthetic Signer B"])
        try run(["ecparam", "-name", "prime256v1", "-genkey", "-out", "ec.key"])
        try run(["req", "-new", "-key", "ec.key", "-out", "ec.csr", "-subj", "/CN=Synthetic EC Signer"])
        try run(["genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "pss.key"])
        try run(["req", "-new", "-key", "pss.key", "-out", "pss.csr", "-subj", "/CN=Synthetic PSS Signer"])
        try run(["genrsa", "-out", "small.key", "1024"])
        try run(["req", "-new", "-key", "small.key", "-out", "small.csr", "-subj", "/CN=Synthetic Small Key"])
        try Data().write(to: folder.appendingPathComponent("index"))
        try Data("01\n".utf8).write(to: folder.appendingPathComponent("serial"))
        func make(_ name: String, ku: String? = "digitalSignature,nonRepudiation", eku: String? = nil,
                  start: String = "200101000000Z", end: String = "400101000000Z",
                  csr: String = "rsa.csr", other: String = "", ca: Bool = false) throws {
            let config = """
            [ca]
            default_ca=issuer
            [issuer]
            dir=.
            database=./index
            serial=./serial
            new_certs_dir=.
            certificate=./ca.pem
            private_key=./rsa.key
            default_md=sha256
            policy=names
            unique_subject=no
            x509_extensions=extensions
            [names]
            commonName=supplied
            [extensions]
            basicConstraints=critical,CA:\(ca ? "TRUE" : "FALSE")
            \(ku.map { "keyUsage=critical," + $0 } ?? "")
            \(eku.map { "extendedKeyUsage=" + $0 } ?? "")
            \(other)
            """
            try Data(config.utf8).write(to: folder.appendingPathComponent("ca.cnf"))
            try run(["ca", "-batch", "-config", "ca.cnf", "-in", csr, "-out", "leaf.pem", "-notext", "-startdate", start, "-enddate", end])
            try run(["x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der"])
            certificates[name] = try Data(contentsOf: folder.appendingPathComponent("leaf.der"))
        }
        try make("valid", eku: "1.3.6.1.5.5.7.3.36")
        try make("otherSigner", csr: "other.csr")
        try make("replaced", eku: "1.3.6.1.5.5.7.3.36") // same key/subject, distinct serial and DER
        try make("expired", start: "000101000000Z", end: "010101000000Z")
        try make("future", start: "400101000000Z", end: "410101000000Z")
        try make("generalized", start: "20500101000000Z", end: "20510101000000Z")
        try make("authentication", ku: "digitalSignature", eku: "clientAuth")
        try make("wrongKU", ku: "keyEncipherment")
        try make("wrongEKU", eku: "codeSigning,emailProtection")
        try make("absentEKU")
        try make("digitalOnly", ku: "digitalSignature")
        try make("commitmentOnly", ku: "nonRepudiation")
        try make("anyEKU", eku: "anyExtendedKeyUsage")
        try make("mixedEKU", eku: "clientAuth,1.3.6.1.5.5.7.3.36")
        try make("unknownEKU", eku: "1.2.3.4.5")
        try make("missingKU", ku: nil)
        try make("criticalUnknown", other: "1.2.3.4.5=critical,DER:05:00")
        try make("noncriticalUnknown", other: "1.2.3.4.5=DER:05:00")
        try make("noncriticalHighTag", other: "1.2.3.4.99=DER:9F:1F:01:00")
        try make("noncriticalLongTag", other: "1.2.3.4.99=DER:9F:81:80:00:01:00")
        try make("criticalHighTag", other: "1.2.3.4.99=critical,DER:9F:1F:01:00")
        try make("ec", csr: "ec.csr")
        try make("pss", csr: "pss.csr")
        try make("small", csr: "small.csr")
        try make("ca", ca: true)
        try make("badKUPadding", ku: "DER:03:02:07:81")
        try make("emptyEKU", eku: "DER:30:00")
        try make("badKUHighTag", ku: "DER:9F:1F:01:00")
        try make("badEKUHighTag", eku: "DER:9F:1F:01:00")
    }
    func der(_ name: String) -> Data { certificates[name]! }
}

final class CertificateEligibilityTests: XCTestCase {
    static let fixtures = Result { try SyntheticCertificates() }
    private func der(_ name: String) throws -> Data { try Self.fixtures.get().der(name) }
    private let date = Date(timeIntervalSince1970: 1_792_195_200) // 2026-10-17 UTC
    private func assess(_ name: String) throws -> CertificateEligibility.Assessment {
        CertificateEligibility.evaluate(certificateDER: try der(name), at: date)
    }
    func testValidDocumentSigningCertificate() throws {
        let a = try assess("valid")
        XCTAssertEqual(a.status, .eligible); XCTAssertTrue(a.permitsSigning)
        XCTAssertTrue(a.digitalSignature); XCTAssertTrue(a.contentCommitment)
        XCTAssertTrue(a.documentSigning); XCTAssertTrue(a.extendedKeyUsagePresent)
        XCTAssertEqual(a.publicKeyBits, 2048); XCTAssertTrue(a.reasons.isEmpty)
    }
    func testExpiredAndFutureCertificatesAreBlocked() throws {
        for name in ["expired", "future"] {
            XCTAssertEqual(try assess(name).status, .ineligible)
            XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: der(name), at: date))
        }
    }
    func testValidityBoundariesAreInclusiveAndRechecked() throws {
        let data = try der("valid"), a = try assess("valid")
        for boundary in [a.notBefore!, a.notAfter!] {
            XCTAssertEqual(CertificateEligibility.evaluate(certificateDER: data, at: boundary).status, .eligible)
        }
        XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: data, at: a.notAfter!.addingTimeInterval(1)))
        XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: data, at: a.notBefore!.addingTimeInterval(-1)))
    }
    func testGeneralizedTime() throws {
        let a = CertificateEligibility.evaluate(certificateDER: try der("generalized"), at: Date(timeIntervalSince1970: 2_540_000_000))
        XCTAssertEqual(a.status, .eligible)
    }
    func testAuthenticationCertificateDespiteSigningUsageAndLabel() throws {
        let a = try assess("authentication")
        XCTAssertTrue(a.digitalSignature); XCTAssertEqual(a.status, .ineligible)
        XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: der("authentication"), at: date))
    }
    func testIncompatibleKeyUsageAndEKU() throws {
        for name in ["wrongKU", "wrongEKU"] { XCTAssertEqual(try assess(name).status, .ineligible) }
    }
    func testAbsentEKUDoesNotDisqualify() throws {
        let a = try assess("absentEKU")
        XCTAssertEqual(a.status, .eligible); XCTAssertFalse(a.extendedKeyUsagePresent)
    }
    func testDigitalSignatureAndContentCommitmentAreDistinctAndBothSupported() throws {
        let ds = try assess("digitalOnly"), cc = try assess("commitmentOnly")
        XCTAssertEqual(ds.status, .eligible); XCTAssertEqual(cc.status, .eligible)
        XCTAssertTrue(ds.digitalSignature); XCTAssertFalse(ds.contentCommitment)
        XCTAssertFalse(cc.digitalSignature); XCTAssertTrue(cc.contentCommitment)
    }
    func testAnyAndMixedDocumentEKU() throws {
        XCTAssertTrue(try assess("anyEKU").anyExtendedKeyUsage)
        XCTAssertEqual(try assess("anyEKU").status, .eligible)
        XCTAssertEqual(try assess("mixedEKU").status, .eligible)
    }
    func testAmbiguityBlocksSigningWithoutInventingQualification() throws {
        for name in ["unknownEKU", "missingKU", "criticalUnknown"] {
            let a = try assess(name)
            XCTAssertEqual(a.status, .indeterminate); XCTAssertFalse(a.permitsSigning)
            XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: der(name), at: date))
        }
        XCTAssertEqual(try assess("noncriticalUnknown").status, .eligible)
    }
    func testUnknownNoncriticalHighTagValuesAreOpaqueAndEligible() throws {
        for name in ["noncriticalUnknown", "noncriticalHighTag", "noncriticalLongTag"] {
            let bytes = try der(name)
            XCTAssertNotNil(SecCertificateCreateWithData(nil, bytes as CFData), name)
            let assessment = try assess(name)
            XCTAssertEqual(assessment.status, .eligible, name)
            XCTAssertTrue(assessment.reasons.isEmpty, name)
            XCTAssertNoThrow(try CertificateEligibility.requireEligible(certificateDER: bytes, at: date))
        }
    }
    func testUnknownCriticalHighTagBlocksWithoutClaimingMalformed() throws {
        let bytes = try der("criticalHighTag")
        XCTAssertNotNil(SecCertificateCreateWithData(nil, bytes as CFData))
        let assessment = try assess("criticalHighTag")
        XCTAssertEqual(assessment.status, .indeterminate)
        XCTAssertFalse(assessment.permitsSigning)
        XCTAssertNotNil(assessment.notBefore)
        XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: bytes, at: date))
    }
    func testUnsupportedPublicKeysAndCA() throws {
        for name in ["ec", "pss", "small", "ca"] { XCTAssertEqual(try assess(name).status, .ineligible, name) }
    }
    func testMalformedCertificateAndBounds() throws {
        let valid = try der("valid")
        for bytes in [Data(), Data([0x30, 0x03, 0x02, 0x01, 0x01]), Data(valid.dropLast()), valid + Data([0]), Data(repeating: 0, count: 65537)] {
            let a = CertificateEligibility.evaluate(certificateDER: bytes, at: date)
            XCTAssertEqual(a.status, .ineligible); XCTAssertNil(a.notBefore)
        }
    }
    func testMalformedUsageExtensionsAndTimeAreBlocked() throws {
        for name in ["badKUPadding", "emptyEKU", "badKUHighTag", "badEKUHighTag"] {
            XCTAssertEqual(try assess(name).status, .ineligible)
        }
        var broken = try der("valid")
        let original = Data("200101000000Z".utf8)
        let range = try XCTUnwrap(broken.range(of: original))
        broken.replaceSubrange(range, with: Data("200230000000Z".utf8)) // February 30
        XCTAssertEqual(CertificateEligibility.evaluate(certificateDER: broken, at: date).status, .ineligible)
    }
    func testDuplicateExtensionsAreRejectedRatherThanChoosingOne() throws {
        for name in ["valid", "noncriticalHighTag", "criticalHighTag"] {
            let bytes = [UInt8](try der(name))
            func children(_ node: DER.Node) throws -> [DER.Node] {
                var result: [DER.Node] = [], offset = node.contents.lowerBound
                while offset < node.contents.upperBound { result.append(try DER.read(bytes, at: &offset, limit: node.contents.upperBound)) }
                return result
            }
            var offset = 0
            let root = try DER.read(bytes, at: &offset, limit: bytes.count)
            let outer = try children(root), fields = try children(outer[0])
            let ext = try XCTUnwrap(fields.first(where: { $0.tag == 0xa3 }))
            let sequence = try XCTUnwrap(children(ext).first)
            let values = try children(sequence)
            // Duplicate each extension, including KU and EKU, with an unchanged
            // certificate signature: these malformed encodings must fail before trust.
            for duplicate in values {
                let extensions = DER.wrap(0xa3, DER.sequence(values.map { Data(bytes[$0.full]) } + [Data(bytes[duplicate.full])]))
                let tbs = DER.sequence(fields.map { $0.full == ext.full ? extensions : Data(bytes[$0.full]) })
                let malformed = DER.sequence([tbs] + outer.dropFirst().map { Data(bytes[$0.full]) })
                XCTAssertEqual(CertificateEligibility.evaluate(certificateDER: malformed, at: date).status, .ineligible)
            }
        }
    }
    func testReplacedCertificateWithSameKeySubjectAndIDIsRejected() throws {
        let approved = try der("valid"), replaced = try der("replaced")
        XCTAssertNotEqual(approved, replaced)
        XCTAssertEqual(try assess("replaced").status, .eligible)
        XCTAssertThrowsError(try CertificateEligibility.requireEligible(certificateDER: replaced, expectedCertificateDER: approved, at: date))
        XCTAssertNoThrow(try CertificateEligibility.requireEligible(certificateDER: approved, expectedCertificateDER: approved, at: date))
    }
    func testNoTrustQualificationOrRevocationClaim() throws {
        // This leaf's synthetic issuer is never added to a keychain/trust store.
        XCTAssertEqual(try assess("valid").status, .eligible)
        XCTAssertTrue(CertificateEligibility.scope.contains("non valutate"))
    }
    func testInvalidEvaluationClockIsIndeterminate() throws {
        XCTAssertEqual(CertificateEligibility.evaluate(certificateDER: try der("valid"), at: Date(timeIntervalSince1970: .nan)).status, .indeterminate)
    }
}
#endif
