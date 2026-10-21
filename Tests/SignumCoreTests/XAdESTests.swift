#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

final class XAdESTests: XCTestCase {
    let input = Data("<invoice xmlns=\"urn:signum:test\" xmlns:p=\"urn:part\" Id=\"invoice\"><p:item code=\"à\">Documento sintetico € 123</p:item></invoice>".utf8)
    func fixture(_ body: (URL,SoftwareSigner) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-xades-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at:root) }
        try body(root,SoftwareSigner(folder:root))
    }
    @discardableResult func run(_ exe: URL,_ args: [String],at root: URL) throws -> Data {
        let p = Process(), out = Pipe(); p.executableURL = exe; p.arguments = args; p.currentDirectoryURL = root
        p.standardOutput = out;p.standardError = out
        if exe.lastPathComponent == "xmlsec1" {
            var environment = ProcessInfo.processInfo.environment
            environment["DYLD_LIBRARY_PATH"] = exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("lib").path
            p.environment = environment
        }
        try p.run(); let data = out.fileHandleForReading.readDataToEndOfFile(); try FixtureProcess.wait(p)
        XCTAssertEqual(p.terminationStatus,0,"Command failed: \(exe.lastPathComponent) \(args) \(String(decoding:data,as:UTF8.self))")
        guard p.terminationStatus == 0 else { throw SignumError.invalidSignature }; return data
    }
    func sign(_ message: Data,root: URL) throws -> Data {
        try message.write(to:root.appendingPathComponent("signed-info"))
        try run(URL(fileURLWithPath:"/usr/bin/openssl"),["dgst","-sha256","-sign","key.pem","-out","signature","signed-info"],at:root)
        return try Data(contentsOf:root.appendingPathComponent("signature"))
    }
    func signed(root: URL,signer: SoftwareSigner) throws -> Data {
        let p = try XAdES.Prepared(document:input,certificateDER:signer.der)
        return try p.finish(signature:sign(p.attributesToSign,root:root))
    }
    func testGenerationVerificationAndDeclaredTime() throws {
        try fixture { root,signer in
            let time = Date(timeIntervalSince1970:1792600000)
            let p = try XAdES.Prepared(document:input,certificateDER:signer.der,declaredTime:time)
            let xml = try p.finish(signature:sign(p.attributesToSign,root:root))
            let v = try XAdES.verify(xml)
            XCTAssertEqual(v.certificateDER,signer.der); XCTAssertEqual(v.signedInfo,p.attributesToSign)
            XCTAssertEqual(ISO8601DateFormatter().date(from:v.declaredTime),time)
            let report = try SignumVerificationService.verify(data:xml,name:"signed.xml",helper:URL(fileURLWithPath:"/no-cms-helper"))
            XCTAssertEqual(report.format,.xml); XCTAssertEqual(report.integrity,.verified)
            XCTAssertEqual(report.signatures.first?.signerDER,signer.der)
            XCTAssertEqual(report.signatures.first?.evidence?.signatureValue,v.signatureValue)
            XCTAssertNil(report.originalContent)
            let text = String(decoding:xml,as:UTF8.self)
            let declaration = try XCTUnwrap(text.range(of:"?>"))
            let withBOM = Data(("\u{feff}\n"+text[declaration.upperBound...]).utf8)
            XCTAssertEqual(try SignumVerificationService.verify(data:withBOM,name:"bom.xml").integrity,.verified)
            XCTAssertThrowsError(try SignumVerificationService.verify(data:xml,name:"cancelled.xml",isCancelled:{ true }))
        }
    }
    func testIndependentXMLSecInteroperabilityInBothDirections() throws {
        try fixture { root,signer in
            let env = ProcessInfo.processInfo.environment
            let available = (env["PATH"] ?? "").split(separator:":").map { String($0)+"/xmlsec1" }.first { FileManager.default.isExecutableFile(atPath:$0) }
            let cli = URL(fileURLWithPath:try XCTUnwrap(env["SIGNUM_TEST_XMLSEC"] ?? available))
            let xml = try signed(root:root,signer:signer)
            try xml.write(to:root.appendingPathComponent("signed.xml"))
            try run(cli,["--verify","--trusted-der","certificate.der","--pubkey-cert-der","certificate.der","--id-attr:Id","SignedProperties","signed.xml"],at:root)
            let p = try XAdES.Prepared(document:input,certificateDER:signer.der)
            try p.template.write(to:root.appendingPathComponent("template.xml"))
            try run(cli,["--sign","--lax-key-search","--enabled-key-data","rsa","--trusted-der","certificate.der","--privkey-pem","key.pem,certificate.pem","--id-attr:Id","SignedProperties","--output","independent.xml","template.xml"],at:root)
            let external = try Data(contentsOf:root.appendingPathComponent("independent.xml"))
            XCTAssertEqual(try XAdES.verify(external).certificateDER,signer.der)
        }
    }
    func testTamperingPayloadPropertiesAndCertificateRejected() throws {
        try fixture { root,signer in
            let text = String(decoding:try signed(root:root,signer:signer),as:UTF8.self)
            let cases = [text.replacingOccurrences(of:"123",with:"999"),
                         text.replacingOccurrences(of:"application/xml",with:"text/plain"),
                         text.replacingOccurrences(of:"<xades:SigningTime>",with:"<xades:SigningTime>2000"),
                         text.replacingOccurrences(of:signer.der.base64EncodedString(),with:Data(repeating:1,count:256).base64EncodedString()),
                         text.replacingOccurrences(of:"<ds:DigestValue>",with:"<ds:DigestValue>AAAA")]
            for value in cases { XCTAssertNotEqual(value,text); XCTAssertThrowsError(try XAdES.verify(Data(value.utf8))) }
            let report = try SignumVerificationService.verify(data:Data(cases[0].utf8),name:"altered.xml")
            XCTAssertEqual(report.integrity,.invalid)
        }
    }
    func testWrappingDuplicateIDsAndUncoveredObjectRejected() throws {
        try fixture { root,signer in
            let text = String(decoding:try signed(root:root,signer:signer),as:UTF8.self)
            let sig = try XCTUnwrap(text.range(of:"<ds:Signature "))
            let signature = String(text[sig.lowerBound..<text.range(of:"</ds:Signature>")!.upperBound])
            let cases = [text.replacingOccurrences(of:"</invoice>",with:"<unsigned Id=\"invoice\"/></invoice>"),
                         text.replacingOccurrences(of:signature,with:"<wrapper>"+signature+"</wrapper>"),
                         text.replacingOccurrences(of:signature,with:signature+signature),
                         text.replacingOccurrences(of:"<ds:Object>",with:"<ds:Object><unsigned/>"),
                         text.replacingOccurrences(of:"</xades:SignedProperties>",with:"</xades:SignedProperties><xades:SignedProperties Id=\"invoice\"/>"),
                         text.replacingOccurrences(of:"Id=\"invoice\"",with:"Id=\"invoice\" id=\"other\"")]
            for value in cases { XCTAssertThrowsError(try XAdES.verify(Data(value.utf8))) }
        }
    }
    func testExternalURIsTransformsAndAlgorithmParametersRejected() throws {
        try fixture { root,signer in
            let text = String(decoding:try signed(root:root,signer:signer),as:UTF8.self)
            for uri in ["https://example.invalid/payload","file:///etc/passwd","#xpointer(/)","#invoice"] {
                XCTAssertThrowsError(try XAdES.verify(Data(text.replacingOccurrences(of:"URI=\"\"",with:"URI=\""+uri+"\"").utf8)))
            }
            for transform in ["http://www.w3.org/TR/1999/REC-xslt-19991116","http://www.w3.org/TR/1999/REC-xpath-19991116"] {
                XCTAssertThrowsError(try XAdES.verify(Data(text.replacingOccurrences(of:"http://www.w3.org/2000/09/xmldsig#enveloped-signature",with:transform).utf8)))
            }
            let parameter = text.replacingOccurrences(of:"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",with:"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><bad/></ds:CanonicalizationMethod>")
            XCTAssertNotEqual(parameter,text);XCTAssertThrowsError(try XAdES.verify(Data(parameter.utf8)))
        }
    }
    func testDTDXXEMalformedEncodingAndResourceLimitsRejectedBeforeSigning() throws {
        let cases = ["<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><a>&x;</a>",
                     "<!DOCTYPE a SYSTEM 'https://example.invalid/dtd'><a/>","<a><b></a>","<?instruct x?><a/>","<a><!--comment--></a>",
                     "<a xml:base='file:///tmp/'/>","<?xml version=\"1.1\"?><a/>","<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>","<a Id='same'><b ID='same'/></a>","<a><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'/></a>",
                     String(repeating:"<a>",count:70)+String(repeating:"</a>",count:70)]
        for value in cases { XCTAssertThrowsError(try XAdES.requireUnsignedInput(Data(value.utf8))) }
        XCTAssertThrowsError(try XAdES.requireUnsignedInput(Data([0xff,0xfe,60,0,97,0,47,0,62,0])))
        XCTAssertThrowsError(try XAdES.requireUnsignedInput(Data(repeating:65,count:XAdES.maximumDocumentBytes+1)))
    }
    func testExistingWorkerAndAtomicPublicationUseApprovedXML() throws {
        try fixture { root,signer in
            let source = root.appendingPathComponent("invoice.xml");try input.write(to:source)
            let snapshot = try DocumentSnapshot.capture(source:source,format:.xades,privateRoot:root)
            let mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
            let job = try SigningJob(snapshot:snapshot,providerPath:mock.path.resolvingSymlinksInPath().path,slot:7,
                certificate:.init(label:"Synthetic",identifier:Data([0x53])),certificateDER:signer.der,destination:root.appendingPathComponent("result.xml"))
            try Data("<changed/>".utf8).write(to:source)
            let worker = Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
            let op = SigningOperation()
            try job.signXAdES(using:IsolatedPKCS11Client(executable:worker),pin:"synthetic-fixture",operation:op)
            XCTAssertEqual(op.state,.completed)
            let output = try Data(contentsOf:job.destination)
            XCTAssertEqual(try XAdES.verify(output).certificateDER,signer.der)
            XCTAssertTrue(String(decoding:output,as:UTF8.self).contains("123"))
            XCTAssertFalse(String(decoding:output,as:UTF8.self).contains("<changed"))
            XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
            XCTAssertEqual(mock.count(8),0) // Parent has not loaded or logged into the PKCS#11 provider.
        }
    }
    func testInvalidSignatureAndCancellationNeverPublish() throws {
        for cancel in [false,true] {
            try fixture { root,signer in
                let source = root.appendingPathComponent("source.xml");try input.write(to:source)
                let snapshot = try DocumentSnapshot.capture(source:source,format:.xades,privateRoot:root)
                let job = try SigningJob(snapshot:snapshot,providerPath:"/synthetic/provider",slot:7,
                    certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:signer.der,destination:root.appendingPathComponent("result.xml"))
                var called = false
                XCTAssertThrowsError(try job.executeXAdES(isCancelled:{ cancel }) { _ in called = true;return Data(repeating:0,count:256) })
                XCTAssertEqual(called,!cancel);XCTAssertFalse(FileManager.default.fileExists(atPath:job.destination.path))
                XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
                XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath:root.path).contains { $0.hasPrefix(".signum-staging-") })
            }
        }
    }
    @MainActor func testFormatSelectionReviewAndPreAuthenticationXMLGuard() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-xades-review-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false)
        defer { try? FileManager.default.removeItem(at:root) }
        let signer = try SoftwareSigner(folder:root), source = root.appendingPathComponent("invoice.xml")
        try input.write(to:source)
        let batch = BatchSigningCoordinator();defer { batch.reset() }
        await batch.addDocuments([source],format:.cades)
        let id = try XCTUnwrap(batch.documents.first?.id);try batch.setFormat(.xades,for:id)
        let plan = try await batch.prepareReview(provider:"/synthetic/provider",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders)
        XCTAssertEqual(plan.jobs.first?.format,.xades);XCTAssertEqual(plan.jobs.first?.destination.lastPathComponent,"invoice-firmato.xml")
        XCTAssertEqual(plan.jobs.first?.formatDescription,"XAdES — XML firmato")
        try batch.freezeReview(plan);try batch.confirm(plan)
        XCTAssertThrowsError(try batch.setFormat(.cades,for:id))
        let bad = root.appendingPathComponent("bad.xml");try Data("<!DOCTYPE a><a/>".utf8).write(to:bad)
        let snapshot = try DocumentSnapshot.capture(source:bad,format:.xades);defer { snapshot.close() }
        XCTAssertThrowsError(try SigningJob(snapshot:snapshot,providerPath:"/synthetic/provider",slot:7,
            certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:signer.der,destination:root.appendingPathComponent("bad-result.xml")))
    }
}
#endif
