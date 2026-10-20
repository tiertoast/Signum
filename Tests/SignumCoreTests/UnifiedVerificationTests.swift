#if os(macOS)
import XCTest
import PDFKit
import Darwin
import UniformTypeIdentifiers
@testable import SignumCore
@testable import SignumApp

final class UnifiedVerificationTests: XCTestCase {
    private var helper: URL {
        get throws { try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map(URL.init(fileURLWithPath:)), "A native helper is mandatory") }
    }
    private func folder(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("verification-"+UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at: root) }; try body(root)
    }
    private func verify(_ bytes: Data, name: String = "wrong-extension.bin") throws -> VerificationReport {
        try SignumVerificationService.verify(data: bytes, name: name, helper: helper)
    }
    private func openssl(_ args: [String], root: URL) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath:"/usr/bin/openssl"); process.arguments = args; process.currentDirectoryURL = root
        process.standardError = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice
        try process.run(); try FixtureProcess.wait(process); XCTAssertEqual(process.terminationStatus,0)
    }
    private func assertUnassessed(_ report: VerificationReport, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(report.trust,.notChecked,file:file,line:line); XCTAssertEqual(report.revocation,.notChecked,file:file,line:line); XCTAssertEqual(report.qualification,.notChecked,file:file,line:line)
    }
    func testAttachedCAdESContentBasedDetectionCertificateMetadataAndIndependentReference() throws {
        try folder { root in
            let signer = try SoftwareSigner(folder:root), original = Data("Synthetic non-PDF payload".utf8)
            let cms = try signer.cms(for:original), report = try verify(cms,name:"document.pdf")
            XCTAssertEqual(report.format,.cades); XCTAssertEqual(report.integrity,.verified); XCTAssertEqual(report.signatures.count,1)
            XCTAssertNil(report.previewPDF); XCTAssertEqual(report.signatures[0].certificate?.sha256,DocumentSnapshot.digest(signer.der))
            XCTAssertEqual(report.originalContent,original)
            let exported = root.appendingPathComponent("exported")
            try SignumFileOutput.writeNew(try XCTUnwrap(report.originalContent),to:exported)
            XCTAssertEqual(try Data(contentsOf:exported),original)
            XCTAssertThrowsError(try SignumFileOutput.writeNew(try XCTUnwrap(report.originalContent),to:exported))
            XCTAssertTrue(report.signatures[0].certificate?.subject.contains("Signum Synthetic") ?? false)
            XCTAssertTrue(report.signatures[0].algorithm.contains("sha256")); assertUnassessed(report)
            XCTAssertEqual(try CAdESVerifier.verify(data:cms).originalDocument,original)
        }
    }
    func testCAdESTamperedSignatureIsInvalidNotTrustedOrQualified() throws {
        try folder { root in
            let signer = try SoftwareSigner(folder:root); var cms = try signer.cms(for:Data("Synthetic".utf8))
            cms[cms.count-1] ^= 1
            let report = try verify(cms)
            XCTAssertEqual(report.integrity,.invalid); XCTAssertNil(report.previewPDF); assertUnassessed(report)
            XCTAssertThrowsError(try CAdESVerifier.verify(data:cms))
        }
    }
    func testNestedCAdESAndEmbeddedPDFPreviewRemainInMemory() throws {
        try folder { root in
            let signer = try SoftwareSigner(folder:root), pdf = try PAdESAppearanceTests().pdf()
            let report = try verify(signer.cms(for:signer.cms(for:pdf)))
            XCTAssertEqual(report.signatures.count,2); XCTAssertEqual(report.signatures.map(\.cmsLayer),[1,2])
            XCTAssertEqual(report.integrity,.verified); XCTAssertEqual(report.previewPDF,pdf)
            XCTAssertFalse(FileManager.default.fileExists(atPath:root.appendingPathComponent("document.pdf").path))
        }
    }
    func testDetachedMissingCertificateUnsupportedAlgorithmAndDeclaredTime() throws {
        try folder { root in
            let signer = try SoftwareSigner(folder:root);try Data("Synthetic detached".utf8).write(to:root.appendingPathComponent("input"))
            for (name,flags,reason) in [("detached",[],"detached"),("missing",["-nodetach","-nocerts"],"assente"),("sha1",["-nodetach","-md","sha1"],"Algoritmo")] {
                try openssl(["cms","-sign","-binary"]+flags+["-in","input","-signer","certificate.pem","-inkey","key.pem","-outform","DER","-out",name],root:root)
                let report = try verify(Data(contentsOf:root.appendingPathComponent(name)))
                XCTAssertEqual(report.integrity,.notVerifiable); XCTAssertTrue(report.signatures[0].reason.contains(reason)); XCTAssertFalse(report.signatures[0].declaredTime.isEmpty)
                XCTAssertNil(report.previewPDF); assertUnassessed(report)
            }
            var unknownOID = try signer.cms(for:Data("Synthetic unsupported signature algorithm".utf8))
            let identifier = try XCTUnwrap(unknownOID.range(of:DER.rsaEncryptionOID,options:.backwards))
            unknownOID[identifier.upperBound-1] = 99
            let unsupported = try verify(unknownOID)
            XCTAssertEqual(unsupported.integrity,.notVerifiable)
            XCTAssertTrue(unsupported.signatures[0].reason.contains("Algoritmo"))
        }
    }
    func testMultipleCMSSignersHaveIndependentCertificatesAndCryptographicStates() throws {
        try folder { root in
            _ = try SoftwareSigner(folder:root)
            let other = root.appendingPathComponent("other");try FileManager.default.createDirectory(at:other,withIntermediateDirectories:false)
            _ = try SoftwareSigner(folder:other);try Data("Multiple synthetic signers".utf8).write(to:root.appendingPathComponent("input"))
            try openssl(["cms","-sign","-binary","-nodetach","-in","input","-signer","certificate.pem","-inkey","key.pem","-signer","other/certificate.pem","-inkey","other/key.pem","-outform","DER","-out","multi"],root:root)
            var bytes = try Data(contentsOf:root.appendingPathComponent("multi"))
            let valid = try verify(bytes);XCTAssertEqual(valid.signatures.count,2);XCTAssertEqual(valid.integrity,.verified)
            XCTAssertEqual(Set(valid.signatures.compactMap{$0.certificate?.sha256}).count,2)
            XCTAssertEqual(try CAdESVerifier.verify(data:bytes).verifiedSignatureCount,2)
            bytes[bytes.count-1] ^= 1
            let damaged = try verify(bytes)
            XCTAssertEqual(damaged.signatures.filter{$0.integrity == .verified}.count,1)
            XCTAssertEqual(damaged.signatures.filter{$0.integrity == .invalid}.count,1);XCTAssertEqual(damaged.integrity,.invalid)
        }
    }
    func testUnknownXMLMalformedCMSAndTruncatedPDFDoNotBecomeVerified() throws {
        for (bytes,format,state) in [(Data("ordinary bytes".utf8),VerifiedDocumentFormat.unknown,"unsupported"),(Data("<?xml version=\"1.0\"?><document/>".utf8),.xml,"unsupported"),(Data([0x30,0x03,0x06,0x01,0x2a]),.cades,"damaged"),(Data("%PDF-1.7\ntruncated".utf8),.pades,"damaged")] {
            let report = try verify(bytes,name:"misleading.p7m")
            XCTAssertEqual(report.format,format);XCTAssertEqual(report.documentState,state);XCTAssertEqual(report.integrity,.notVerifiable)
            XCTAssertNil(report.previewPDF)
        }
        try folder { root in
            try Data("Synthetic unsupported CMS ContentInfo".utf8).write(to:root.appendingPathComponent("input"))
            try openssl(["cms","-data_create","-binary","-in","input","-outform","DER","-out","data.cms"],root:root)
            let unsupported = try verify(Data(contentsOf:root.appendingPathComponent("data.cms")))
            XCTAssertEqual(unsupported.documentState,"unsupported");XCTAssertEqual(unsupported.integrity,.notVerifiable)
            XCTAssertTrue(unsupported.issue.contains("Tipo CMS non supportato"))
        }
    }
    func testUnsignedPDFAndInvisibleGraphicAndMultipleIncrementalSignatures() throws {
        try folder { root in
            let fixture = PAdESAppearanceTests(), signer = try SoftwareSigner(folder:root)
            let document = try XCTUnwrap(PDFDocument(data:fixture.pdf()))
            let secondPage = try XCTUnwrap(document.page(at:1))
            secondPage.setBounds(CGRect(x:20,y:30,width:900,height:400),for:.mediaBox)
            secondPage.setBounds(CGRect(x:50,y:70,width:800,height:300),for:.cropBox)
            let original = try XCTUnwrap(document.dataRepresentation())
            let unsigned = try verify(original,name:"wrong.p7m")
            XCTAssertEqual(unsigned.format,.pades);XCTAssertEqual(unsigned.integrity,.absent);XCTAssertTrue(unsigned.signatures.isEmpty)
            let mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
            var config = fixture.config();config.visible = false
            let (first,_) = try fixture.signed(original,configuration:config,root:root,signer:signer,mock:mock,name:"first")
            let single = try verify(first);XCTAssertEqual(single.integrity,.verified);XCTAssertFalse(single.signatures[0].laterChanges)
            config.visible = true;config.pageIndex = 1
            let (second,_) = try fixture.signed(first,configuration:config,root:root,signer:signer,mock:mock,name:"second")
            let multi = try verify(second);XCTAssertEqual(multi.signatures.count,2);XCTAssertEqual(multi.integrity,.verified)
            XCTAssertEqual(multi.signatures.map(\.laterChanges),[true,false]);XCTAssertEqual(multi.signatures.first?.signedRevisionEnd,first.count)
            let auditBefore = try Data(contentsOf:mock.folder.appendingPathComponent("operations"))
            _ = try verify(second)
            XCTAssertEqual(try Data(contentsOf:mock.folder.appendingPathComponent("operations")),auditBefore,"Verification must never load/authenticate the provider")
            XCTAssertEqual(multi.previewPDF,second);assertUnassessed(multi)
        }
    }
    func testPAdESLaterBytesDoNotInvalidateAnEarlierRevision() throws {
        try folder { root in
            let fixture = PAdESAppearanceTests(), signer = try SoftwareSigner(folder:root), mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
            let (signed,_) = try fixture.signed(fixture.pdf(),configuration:fixture.config(),root:root,signer:signer,mock:mock,name:"later")
            var changed = signed;changed.append(Data("\n% Synthetic later bytes, NOT a DocMDP approval\n".utf8))
            let report = try verify(changed)
            XCTAssertEqual(report.integrity,.verified);XCTAssertTrue(report.signatures[0].laterChanges)
            XCTAssertEqual(report.signatures[0].signedRevisionEnd,signed.count)
        }
    }
    func testPAdESMissingCertificateMalformedCMSAndUnsupportedDigest() throws {
        try folder { root in
            let fixture = PAdESAppearanceTests(), signer = try SoftwareSigner(folder:root), mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
            let (signed,_) = try fixture.signed(fixture.pdf(),configuration:fixture.config(),root:root,signer:signer,mock:mock,name:"cms")
            let cg = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:signed as CFData))))
            var form: CGPDFDictionaryRef?, fields: CGPDFArrayRef?, field: CGPDFDictionaryRef?, value: CGPDFDictionaryRef?, ranges: CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(cg.catalog),"AcroForm",&form))
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(form),"Fields",&fields));XCTAssertTrue(CGPDFArrayGetDictionary(try XCTUnwrap(fields),0,&field))
            XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(field),"V",&value));XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(value),"ByteRange",&ranges))
            var r = [Int](repeating:0,count:4)
            for i in 0..<4 { var n: CGPDFInteger = 0;XCTAssertTrue(CGPDFArrayGetInteger(try XCTUnwrap(ranges),i,&n));r[i] = Int(n) }
            var content = signed.prefix(r[1]);content.append(signed[r[2]..<r[2]+r[3]])
            try content.write(to:root.appendingPathComponent("content"))
            for (name,flags,expectedReason) in [("missing",["-nocerts","-md","sha256"],"assente"),("sha384",["-md","sha384"],"Unsupported")] {
                try openssl(["cms","-sign","-binary","-noattr","-in","content","-signer","certificate.pem","-inkey","key.pem","-outform","DER","-out",name]+flags,root:root)
                let cms = try Data(contentsOf:root.appendingPathComponent(name)),hex = cms.map{String(format:"%02X",$0)}.joined()
                XCTAssertLessThan(hex.utf8.count,r[2]-r[1]-2)
                guard hex.utf8.count < r[2]-r[1]-2 else { return }
                var edited = signed
                edited.replaceSubrange(r[1]+1..<r[2]-1,with:Data((hex+String(repeating:"0",count:r[2]-r[1]-2-hex.utf8.count)).utf8))
                let report = try verify(edited)
                XCTAssertEqual(report.integrity,.notVerifiable);XCTAssertTrue(report.signatures[0].reason.contains(expectedReason))
            }
            var malformed = signed;malformed[r[1]+1] = 70;malformed[r[1]+2] = 70
            XCTAssertNotEqual(try verify(malformed).integrity,.verified)
            let sourceHex = Array(signed[r[1]+1..<r[2]-1])
            var cms = Data()
            for offset in stride(from:0,to:sourceHex.count,by:2) {
                cms.append(try XCTUnwrap(UInt8(String(decoding:sourceHex[offset..<offset+2],as:UTF8.self),radix:16)))
            }
            let identifier = try XCTUnwrap(cms.range(of:DER.rsaEncryptionOID,options:.backwards));cms[identifier.upperBound-1] = 99
            var unsupportedPDF = signed
            unsupportedPDF.replaceSubrange(r[1]+1..<r[2]-1,with:Data(cms.map{String(format:"%02X",$0)}.joined().utf8))
            XCTAssertEqual(try verify(unsupportedPDF).integrity,.notVerifiable)
        }
    }
    func testLargeCAdESVerificationWithinDocumentBudget() throws {
        try folder { root in
            let signer = try SoftwareSigner(folder:root), document = Data(repeating:0x61,count:100*1024*1024)
            let cms = try signer.cms(for:document)
            let report = try verify(cms)
            XCTAssertEqual(report.integrity,.verified);XCTAssertNil(report.previewPDF)
            XCTAssertEqual(report.sha256,DocumentSnapshot.digest(cms))
        }
    }
    func testPAdESAlteredByteRangeOverlapAndContentAreNeverVerified() throws {
        try folder { root in
            let fixture = PAdESAppearanceTests(), signer = try SoftwareSigner(folder:root), mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
            let (signed,_) = try fixture.signed(fixture.pdf(),configuration:fixture.config(),root:root,signer:signer,mock:mock,name:"range")
            let text = String(decoding:signed,as:UTF8.self)
            let marker = try XCTUnwrap(signed.range(of:Data("/ByteRange[".utf8)) ?? signed.range(of:Data("/ByteRange [".utf8)))
            var overlap = signed;let bracket = try XCTUnwrap(overlap[marker.lowerBound...].firstIndex(of:91))
            let end = try XCTUnwrap(overlap[bracket...].firstIndex(of:93))
            let range = Data(("[0 1 0 1]"+String(repeating:" ",count:end-bracket+1-9)).utf8)
            overlap.replaceSubrange(bracket...end,with:range)
            XCTAssertNotEqual(try verify(overlap).integrity,.verified)
            var altered = signed
            if let creator = altered.range(of:Data("Creator".utf8)) { altered[creator.lowerBound] ^= 1 }
            else { altered[8] ^= 1 }
            XCTAssertNotEqual(try verify(altered).integrity,.verified)
            XCTAssertTrue(text.contains("ByteRange"))
        }
    }
    func testFileInputSymlinkLimitsAndOriginalUnchanged() throws {
        try folder { root in
            let bytes = try PAdESAppearanceTests().pdf(), file = root.appendingPathComponent("plain.bin")
            try bytes.write(to:file);let original = try FileManager.default.attributesOfItem(atPath:file.path)
            let report = try SignumVerificationService.verify(file:file,helper:helper)
            XCTAssertEqual(report.integrity,.absent);XCTAssertEqual(try Data(contentsOf:file),bytes)
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath:file.path)[.modificationDate] as? Date,original[.modificationDate] as? Date)
            let link = root.appendingPathComponent("link");try FileManager.default.createSymbolicLink(at:link,withDestinationURL:file)
            XCTAssertThrowsError(try SignumVerificationService.verify(file:link,helper:helper))
            let large = root.appendingPathComponent("large");FileManager.default.createFile(atPath:large.path,contents:nil)
            let handle = try FileHandle(forWritingTo:large);try handle.truncate(atOffset:UInt64(SignumVerificationService.maximumInputBytes+1));try handle.close()
            XCTAssertThrowsError(try SignumVerificationService.verify(file:large,helper:helper))
        }
    }
    func testSupervisedVerificationCrashTimeoutCancelAndRSSLimit() throws {
        try folder { root in
            let engine = root.appendingPathComponent("parser")
            func script(_ text: String) throws { try Data(("#!/bin/sh\n"+text).utf8).write(to:engine);try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:engine.path) }
            for (body,expected) in [("kill -KILL $$",SupervisedProcess.Failure.abnormalExit),("while :; do :; done",.timeout)] {
                try script(body)
                XCTAssertThrowsError(try SignumVerificationService.verify(data:Data("Synthetic".utf8),name:"parser",helper:engine,timeout:expected == .timeout ? 0.1 : 3)) { XCTAssertEqual($0 as? SupervisedProcess.Failure,expected) }
            }
            XCTAssertThrowsError(try SignumVerificationService.verify(data:Data("Synthetic".utf8),name:"parser",helper:engine,isCancelled:{true})) { XCTAssertEqual($0 as? SupervisedProcess.Failure,.cancelled) }
            let control = SigningOperation()
            DispatchQueue.global().asyncAfter(deadline:.now()+0.15) { control.requestCancellation() }
            XCTAssertThrowsError(try SignumVerificationService.verify(data:Data("Synthetic".utf8),name:"parser",helper:engine,timeout:3,isCancelled:{control.isCancellationRequested})) { XCTAssertEqual($0 as? SupervisedProcess.Failure,.cancelled) }
            var input = Data()
            XCTAssertThrowsError(try SupervisedProcess.run(executable:engine,input:&input,maximumResidentBytes:1,timeout:2)) { XCTAssertEqual($0 as? SupervisedProcess.Failure,.resourceLimit) }
        }
    }
    @MainActor func testBatchIndependentResultsDuplicatePathsAndCancellation() async throws {
        let workspace = VerificationWorkspace()
        let urls = [URL(fileURLWithPath:"/synthetic/one"),URL(fileURLWithPath:"/synthetic/two"),URL(fileURLWithPath:"/synthetic/one")]
        let bytes = try PAdESAppearanceTests().pdf(), engine = try helper
        await workspace.verify(urls) { url,_ in
            if url.lastPathComponent == "one" { throw SupervisedProcess.Failure.abnormalExit }
            return try SignumVerificationService.verify(data:bytes,name:url.lastPathComponent,helper:engine)
        }
        XCTAssertEqual(workspace.rows.count,2);XCTAssertFalse(workspace.rows[0].issue.isEmpty);XCTAssertEqual(workspace.rows[1].report?.integrity,.absent)
        let task = Task { await workspace.verify(urls) { _,control in
            let deadline = ProcessInfo.processInfo.systemUptime+5
            while !control.isCancellationRequested, ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval:0.001) }
            throw SupervisedProcess.Failure.cancelled
        } }
        let waitDeadline = ProcessInfo.processInfo.systemUptime+5
        while !workspace.busy, ProcessInfo.processInfo.systemUptime < waitDeadline { await Task.yield() }
        XCTAssertTrue(workspace.busy, "Timed out waiting for async fixture");workspace.cancel();await task.value
        XCTAssertFalse(workspace.busy);XCTAssertTrue(workspace.rows.allSatisfy{!$0.issue.isEmpty})
        await workspace.verify((0..<33).map{URL(fileURLWithPath:"/synthetic/\($0)")})
        XCTAssertFalse(workspace.issue.isEmpty)
    }
    @MainActor func testMultipleNativeDropProvidersAndBoundedPreviewRetention() async throws {
        let urls = [URL(fileURLWithPath:"/synthetic/first.pdf"),URL(fileURLWithPath:"/synthetic/second.p7m")]
        let providers = urls.map { NSItemProvider(item:$0 as NSURL,typeIdentifier:UTType.fileURL.identifier) }
        let dropped = await VerificationDropLoader.urls(from:providers)
        XCTAssertEqual(dropped,urls)
        let memory = Data(repeating:0,count:65*1024*1024), workspace = VerificationWorkspace()
        await workspace.verify(urls) { url,_ in
            VerificationReport(id:UUID(),documentName:url.lastPathComponent,sha256:"synthetic",format:.pades,signatures:[],documentState:"unsigned",issue:"",previewPDF:memory,originalContent:nil)
        }
        XCTAssertNotNil(workspace.rows[0].report?.previewPDF)
        XCTAssertNil(workspace.rows[1].report?.previewPDF);XCTAssertFalse(workspace.rows[1].issue.isEmpty)
        XCTAssertEqual(workspace.rows[1].report?.integrity,.absent)
    }
}
#endif
