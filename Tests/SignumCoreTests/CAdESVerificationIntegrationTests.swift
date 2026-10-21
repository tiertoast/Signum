import XCTest
import Foundation
@testable import SignumCore

#if os(macOS)
final class CAdESVerificationIntegrationTests: XCTestCase {
    private func openssl(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        try FixtureProcess.wait(process)
        guard process.terminationStatus == 0 else {
            throw SignumError.module("Local OpenSSL test fixture failed: \(arguments.first ?? "")")
        }
    }

    func testNestedAttachedSignaturesAndTamperDetection() throws {
        let manager = FileManager.default
        let folder = manager.temporaryDirectory.appendingPathComponent(
            "signum-cms-tests-" + UUID().uuidString, isDirectory: true)
        try manager.createDirectory(at: folder, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: folder) }

        let document = folder.appendingPathComponent("sample.txt")
        let key = folder.appendingPathComponent("private-key.pem")
        let certificate = folder.appendingPathComponent("public-cert.pem")
        let first = folder.appendingPathComponent("sample.txt.p7m")
        let second = folder.appendingPathComponent("sample.txt.p7m.p7m")

        let expected = Data("Signum fixture for CMS verification\n".utf8)
        try expected.write(to: document)
        try openssl(["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key.path, "-out", certificate.path, "-days", "1",
                     "-subj", "/CN=Fixture Signer/O=Signum Tests"])
        func sign(_ input: URL, _ output: URL) throws {
            try openssl(["cms", "-sign", "-binary", "-nodetach", "-in", input.path,
                         "-signer", certificate.path, "-inkey", key.path,
                         "-outform", "DER", "-out", output.path])
        }
        try sign(document, first)
        try sign(first, second)

        let verified = try CAdESVerifier.verify(file: second)
        XCTAssertEqual(verified.verifiedLayerCount, 2)
        XCTAssertEqual(verified.verifiedSignatureCount, 2)
        XCTAssertEqual(verified.levels[0].signers.first, "Fixture Signer")
        XCTAssertEqual(verified.levels[1].signers.first, "Fixture Signer")
        XCTAssertEqual(verified.originalDocument, expected)
        XCTAssertEqual(verified.suggestedFilename, "sample.txt")

        // Verify the assembled Signum builder independently with a synthetic
        // software key. No PKCS#11 provider, token or PIN is involved.
        let der = folder.appendingPathComponent("certificate.der")
        let attributes = folder.appendingPathComponent("attributes")
        let signature = folder.appendingPathComponent("signature")
        try openssl(["x509", "-in", certificate.path, "-outform", "DER", "-out", der.path])
        let declared = ISO8601DateFormatter().date(from: "2026-10-20T07:22:23Z")!
        let prepared = try CAdES.Prepared(document: expected, certificateDER: Data(contentsOf: der), declaredSigningTime: declared)
        try prepared.attributesToSign.write(to: attributes)
        try openssl(["dgst", "-sha256", "-sign", key.path, "-out", signature.path, attributes.path])
        let built = try prepared.finish(signature: Data(contentsOf: signature))
        let published = folder.appendingPathComponent("verified.p7m")
        try SignumFileOutput.writeNew(built, to: published) { staged in
            XCTAssertFalse(manager.fileExists(atPath: published.path))
            try CAdESVerifier.verifyAttached(data: staged, expectedDocument: expected)
        }
        XCTAssertEqual(try Data(contentsOf: published), built)
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let current = try SignumVerificationService.verify(data: built, name: "synthetic.p7m", helper: URL(fileURLWithPath: helper))
        XCTAssertEqual(current.integrity, .verified)
        XCTAssertEqual(current.signatures.first?.declaredTime, "Oct 20 07:22:23 2026 GMT")
        XCTAssertTrue(current.signatures.first?.evidence?.timestampTokens.isEmpty == true)
        XCTAssertEqual(current.signatures.first?.evidence?.signedAttributes.filter { $0.oid == "1.2.840.113549.1.9.5" }.count, 1)
        let noTime = try CAdES.Prepared(document: expected, certificateDER: Data(contentsOf: der), declaredSigningTime: nil)
        try noTime.attributesToSign.write(to: attributes)
        try openssl(["dgst", "-sha256", "-sign", key.path, "-out", signature.path, attributes.path])
        let off = try noTime.finish(signature: Data(contentsOf: signature))
        try CAdESVerifier.verifyAttached(data: off, expectedDocument: expected)
        let offReport = try SignumVerificationService.verify(data: off, name: "off.p7m", helper: URL(fileURLWithPath: helper))
        XCTAssertEqual(offReport.integrity, .verified); XCTAssertEqual(offReport.signatures.first?.declaredTime, "")
        XCTAssertFalse(offReport.signatures.first?.evidence?.signedAttributes.contains { $0.oid == "1.2.840.113549.1.9.5" } ?? true)
        let rejected = folder.appendingPathComponent("rejected.p7m")
        XCTAssertThrowsError(try SignumFileOutput.writeNew(built, to: rejected) { staged in
            try CAdESVerifier.verifyAttached(data: staged, expectedDocument: Data("Wrong content".utf8))
        })
        XCTAssertFalse(manager.fileExists(atPath: rejected.path))
        // Signing an existing envelope compares the outer payload, not the
        // innermost document returned by the recursive presentation verifier.
        try CAdESVerifier.verifyAttached(data: Data(contentsOf: second), expectedDocument: Data(contentsOf: first))

        var corrupted = try Data(contentsOf: second)
        corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0x01
        XCTAssertThrowsError(try CAdESVerifier.verify(data: corrupted))
        XCTAssertThrowsError(try SignumFileOutput.writeNew(corrupted, to: rejected) { staged in
            try CAdESVerifier.verifyAttached(data: staged, expectedDocument: Data(contentsOf: first))
        })
        XCTAssertFalse(manager.fileExists(atPath: rejected.path))

    }
}
#endif
