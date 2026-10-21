import XCTest
import SignumCore
import SignumTrustCore
import SignumTrustAuthentication
@testable import SignumCertificateValidation

final class XAdESTrustIntegrationTests: XCTestCase {
    func signedXML() throws -> Data {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-xades-trust-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at:root) }
        func run(_ args: [String]) throws {
            let p = Process();p.executableURL = URL(fileURLWithPath:"/usr/bin/openssl");p.arguments = args;p.currentDirectoryURL = root
            p.standardOutput = FileHandle.nullDevice;p.standardError = FileHandle.nullDevice
            try p.run();p.waitUntilExit();guard p.terminationStatus == 0 else { throw SignumError.invalidCertificate }
        }
        try run(["req","-new","-x509","-newkey","rsa:2048","-nodes","-keyout","key.pem","-out","cert.pem","-days","2","-subj","/CN=Signum Synthetic XAdES"])
        try run(["x509","-in","cert.pem","-outform","DER","-out","cert.der"])
        let prepared = try XAdES.Prepared(document:Data("<document>synthetic</document>".utf8),certificateDER:Data(contentsOf:root.appendingPathComponent("cert.der")),declaredTime:Date(timeIntervalSince1970:1600000000))
        try prepared.attributesToSign.write(to:root.appendingPathComponent("message"))
        try run(["dgst","-sha256","-sign","key.pem","-out","signature","message"])
        return try prepared.finish(signature:Data(contentsOf:root.appendingPathComponent("signature")))
    }
    func testIntegrityDoesNotTrustEmbeddedCertificateOrDeclaredSigningTime() async throws {
        let xml = try signedXML(), at = Date()
        let report = try SignumVerificationService.verify(data:xml,name:"synthetic.xml")
        XCTAssertEqual(report.integrity,.verified);XCTAssertEqual(report.signatures.count,1)
        let values = await SignatureQualificationService().validate(report,authenticatedLists:[],mode:.offline,observedAt:at,evaluationMode:.bestAvailable)
        let v = try XCTUnwrap(values.first)
        XCTAssertEqual(v.path.state,.notVerifiable);XCTAssertEqual(v.evidence.revocation.state,.indeterminate)
        XCTAssertEqual(v.evidence.time.state,.notProven);XCTAssertNil(v.evidence.time.provenTime)
        XCTAssertEqual(v.qualification.evaluationMode,.currentTime);XCTAssertEqual(v.qualification.state,.indeterminate)
        XCTAssertEqual(v.qualification.evaluatedAt,at);XCTAssertEqual(v.evidence.time.declaredSigningTime,"2020-09-13T12:26:40Z")
    }
    func testConcurrentDocumentVerificationAndExistingTLAuthentication() async throws {
        let xml = try signedXML()
        func fixture(_ name: String,_ ext: String) throws -> Data {
            try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:ext,subdirectory:"Fixtures/E1R")))
        }
        let tl = try fixture("authorized","xml"), cert = try fixture("issuer","der")
        let clock = try JSONDecoder().decode([String:String].self,from:fixture("clock","json"))
        let at = try XCTUnwrap(ISO8601DateFormatter().date(from:XCTUnwrap(clock["evaluatedAt"])))
        try await withThrowingTaskGroup(of:Void.self) { group in
            for _ in 0..<8 {
                group.addTask { _ = try XAdES.verify(xml) }
                group.addTask { _ = try TLAuthenticator.authenticate(tl,authorizedCertificateSHA256:[TLAuthenticator.sha256(cert)],territory:"IT",now:at) }
            }
            try await group.waitForAll()
        }
    }
}
