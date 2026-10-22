#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

final class ASiCTests: XCTestCase {
    let payloads = [ASiC.Payload(name:"uno.txt",data:Data("Primo documento".utf8)),.init(name:"dati à.bin",data:Data([0,1,255,10,13,8]))]
    func fixture(_ body: (URL,SoftwareSigner) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-asic-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at:root) }
        try body(root,SoftwareSigner(folder:root))
    }
    @discardableResult func run(_ exe: URL,_ args: [String],root: URL) throws -> Data {
        let p = Process(), pipe = Pipe();p.executableURL=exe;p.arguments=args;p.currentDirectoryURL=root;p.standardOutput=pipe;p.standardError=pipe
        if exe.lastPathComponent == "xmlsec1" {
            var env = ProcessInfo.processInfo.environment;env["DYLD_LIBRARY_PATH"] = exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("lib").path;p.environment=env
        }
        try p.run();let output=pipe.fileHandleForReading.readDataToEndOfFile();try FixtureProcess.wait(p)
        guard p.terminationStatus==0 else { XCTFail(String(decoding:output,as:UTF8.self));throw SignumError.invalidSignature };return output
    }
    func sign(_ bytes: Data,root: URL) throws -> Data {
        try bytes.write(to:root.appendingPathComponent("signed-info"))
        try run(URL(fileURLWithPath:"/usr/bin/openssl"),["dgst","-sha256","-sign","key.pem","-out","signature","signed-info"],root:root)
        return try Data(contentsOf:root.appendingPathComponent("signature"))
    }
    func signed(_ kind: ASiC.Kind,root: URL,signer: SoftwareSigner) throws -> Data {
        let archive = try ASiC.unsignedArchive(kind:kind,payloads:kind == .simple ? [payloads[0]] : payloads)
        let p = try ASiC.Prepared(unsignedArchive:archive,certificateDER:signer.der)
        return try p.finish(signature:sign(p.attributesToSign,root:root))
    }
    func testSimpleAndExtendedCoverEveryOriginalByteAndIdentifySigner() throws {
        try fixture { root,signer in
            for kind in [ASiC.Kind.simple,.extended] {
                let archive = try signed(kind,root:root,signer:signer), v = try ASiC.verify(archive)
                XCTAssertEqual(v.kind,kind);XCTAssertEqual(v.signature.certificateDER,signer.der)
                XCTAssertEqual(Set(v.payloads.map(\.name)),Set((kind == .simple ? [payloads[0]] : payloads).map(\.name)))
                for payload in v.payloads { XCTAssertEqual(payload.data,payloads.first { $0.name == payload.name }?.data) }
                let entries = try ASiCZIP.read(archive)
                XCTAssertEqual(entries.first?.name,"mimetype");XCTAssertEqual(entries.first?.data,Data(kind.mime.utf8))
                XCTAssertEqual(entries.contains { $0.name == ASiC.manifestName },kind == .extended)
                let report = try SignumVerificationService.verify(data:archive,name:"signed."+kind.rawValue)
                XCTAssertEqual(report.format,.asic);XCTAssertEqual(report.integrity,.verified);XCTAssertNil(report.originalContent)
                XCTAssertTrue(report.signatures[0].reason.contains(kind.title))
            }
        }
    }
    func testFourDocumentsAndPercentEncodedUnicodeReferences() throws {
        try fixture { root,signer in
            let files = (0..<4).map { ASiC.Payload(name:String(repeating:"é",count:40)+"\($0).bin",data:Data([UInt8($0),255])) }
            let archive = try ASiC.unsignedArchive(kind:.extended,payloads:files)
            let prepared = try ASiC.Prepared(unsignedArchive:archive,certificateDER:signer.der)
            XCTAssertLessThanOrEqual(prepared.attributesToSign.count,4096)
            let output = try prepared.finish(signature:sign(prepared.attributesToSign,root:root))
            XCTAssertEqual(try ASiC.verify(output).payloads.count,4)
        }
    }
    func testODFManifestSemanticsAcceptPrefixesWhitespaceAndBindExactBytes() throws {
        try fixture { root,signer in
            let files=[ASiC.Payload(name:"doc (1) & '.txt",data:Data([1])),.init(name:"é.txt",data:Data([2]))]
            let archive=try ASiC.unsignedArchive(kind:.extended,payloads:files),entries=try ASiCZIP.read(archive)
            let original=String(decoding:try XCTUnwrap(entries.first { $0.name == ASiC.manifestName }).data,as:UTF8.self)
            let alternate=original.replacingOccurrences(of:"<manifest:",with:"<odf:").replacingOccurrences(of:"</manifest:",with:"</odf:")
                .replacingOccurrences(of:" manifest:",with:" odf:").replacingOccurrences(of:"xmlns:manifest=",with:"xmlns:odf=").replacingOccurrences(of:"><",with:">\n<")
            let varied=try ASiCZIP.write(entries.map { $0.name == ASiC.manifestName ? .init(name:$0.name,data:Data(alternate.utf8)) : $0 })
            let prepared=try ASiC.Prepared(unsignedArchive:varied,certificateDER:signer.der)
            let signed=try prepared.finish(signature:sign(prepared.attributesToSign,root:root))
            XCTAssertEqual(try ASiC.verify(signed).payloads.count,2)
            let modified=try ASiCZIP.read(signed).map { $0.name == ASiC.manifestName ? ASiCZIP.Entry(name:$0.name,data:Data(original.utf8)) : $0 }
            XCTAssertThrowsError(try ASiC.verify(ASiCZIP.write(modified))) // Equivalent semantics cannot replace signed bytes.
            for bad in [alternate.replacingOccurrences(of:"application/vnd.etsi.asic-e+zip",with:"application/vnd.etsi.asic-s+zip"),alternate.replacingOccurrences(of:"é.txt",with:"missing.txt")] {
                let invalid=try ASiCZIP.write(entries.map { $0.name == ASiC.manifestName ? .init(name:$0.name,data:Data(bad.utf8)) : $0 })
                XCTAssertThrowsError(try ASiC.Prepared(unsignedArchive:invalid,certificateDER:signer.der))
            }
        }
    }
    func testChangedSwappedMissingExtraOrRenamedPayloadNeverPass() throws {
        try fixture { root,signer in
            let archive = try signed(.extended,root:root,signer:signer), entries = try ASiCZIP.read(archive)
            for name in payloads.map(\.name) {
                let altered = try ASiCZIP.write(entries.map { $0.name == name ? .init(name:$0.name,data:Data("alterato".utf8)) : $0 })
                XCTAssertThrowsError(try ASiC.verify(altered))
                XCTAssertEqual(try SignumVerificationService.verify(data:altered,name:"altered.asice").integrity,.invalid)
            }
            let swapped = try ASiCZIP.write(entries.map { entry in
                if let i = payloads.firstIndex(where:{ $0.name == entry.name }) { return .init(name:entry.name,data:payloads[1-i].data) };return entry
            })
            XCTAssertThrowsError(try ASiC.verify(swapped))
            for modified in [entries.filter { $0.name != payloads[0].name },entries+[.init(name:"extra.txt",data:Data([9]))],entries.map { $0.name == payloads[0].name ? .init(name:"renamed.txt",data:$0.data) : $0 }] {
                XCTAssertThrowsError(try ASiC.verify(ASiCZIP.write(modified)))
            }
        }
    }
    func testWrongReferencesTransformsAndSignedManifestAreRejected() throws {
        try fixture { root,signer in
            let entries = try ASiCZIP.read(signed(.extended,root:root,signer:signer))
            let original = try XCTUnwrap(entries.first { $0.name == ASiC.signatureName })
            let xml = String(decoding:original.data,as:UTF8.self)
            for uri in ["https://example.invalid/uno.txt","file:///etc/passwd","../uno.txt","#invoice","META-INF/unknown.xml"] {
                let changed = xml.replacingOccurrences(of:"URI=\"uno.txt\"",with:"URI=\""+uri+"\"")
                XCTAssertNotEqual(changed,xml)
                XCTAssertThrowsError(try ASiC.verify(ASiCZIP.write(entries.map { $0.name == original.name ? .init(name:$0.name,data:Data(changed.utf8)) : $0 })))
            }
            let unsupported = xml.replacingOccurrences(of:"<ds:Reference URI=\"uno.txt\"",with:"<ds:Reference Type=\"other\" URI=\"uno.txt\"")
            XCTAssertThrowsError(try ASiC.verify(ASiCZIP.write(entries.map { $0.name == original.name ? .init(name:$0.name,data:Data(unsupported.utf8)) : $0 })))
            let changedManifest = entries.map { $0.name == ASiC.manifestName ? ASiCZIP.Entry(name:$0.name,data:$0.data+Data(" ".utf8)) : $0 }
            XCTAssertThrowsError(try ASiC.verify(ASiCZIP.write(changedManifest)))
        }
    }
    func testAmbiguousNamesAndCountsRejectedBeforeSigning() throws {
        for name in ["../file","/absolute","a\\b","a%20b","a?b","a:b","mimetype","MIMETYPE","META-INF/evil",".hidden","a..b","file.","file ","CON.txt","e\u{301}.txt","a\u{202e}txt"] {
            XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.simple,payloads:[.init(name:name,data:Data([1]))]),name)
        }
        XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.extended,payloads:[payloads[0]]))
        XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.simple,payloads:payloads))
        XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.extended,payloads:[payloads[0],.init(name:"UNO.txt",data:Data([1]))]))
        XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.simple,payloads:[.init(name:"big",data:Data(repeating:0,count:ASiCZIP.maximumFile+1))]))
        let four = (0..<4).map { ASiC.Payload(name:"file\($0)",data:Data([UInt8($0)])) }
        XCTAssertNoThrow(try ASiC.unsignedArchive(kind:.extended,payloads:four))
        XCTAssertThrowsError(try ASiC.unsignedArchive(kind:.extended,payloads:four+[.init(name:"five",data:Data([5]))]))
    }
    func value(_ d: Data,_ at: Int,_ count: Int) -> Int { (0..<count).reduce(0) { $0 | Int(d[at+$1]) << (8*$1) } }
    func set(_ d: inout Data,_ at: Int,_ value: Int,_ count: Int) { for i in 0..<count { d[at+i]=UInt8((value >> (8*i))&255) } }
    func testZIPTraversalSymlinksOverlapsEncryptionBombAndHeaderDisagreement() throws {
        let zip = try ASiC.unsignedArchive(kind:.simple,payloads:[.init(name:"abcde",data:Data([1,2,3]))])
        let central = value(zip,zip.count-6,4)
        let second = central+46+value(zip,central+28,2), local = value(zip,second+42,4)
        var cases = [Data]()
        var z=zip;z.replaceSubrange(second+46..<second+51,with:Data("../xx".utf8));z.replaceSubrange(local+30..<local+35,with:Data("../xx".utf8));cases.append(z)
        z=zip;set(&z,second+38,0xa1ff0000,4);cases.append(z)
        z=zip;set(&z,second+42,0,4);cases.append(z)
        z=zip;set(&z,second+8,0x801,2);set(&z,local+6,0x801,2);cases.append(z)
        z=zip;set(&z,second+24,ASiCZIP.maximumFile+1,4);cases.append(z)
        z=zip;set(&z,second+20,1,4);set(&z,second+24,ASiCZIP.maximumFile,4);cases.append(z)
        z=zip;set(&z,local+14,0,4);cases.append(z)
        z=zip;set(&z,local+28,2,2);cases.append(z)
        z=zip;set(&z,second+10,99,2);cases.append(z)
        z=zip;set(&z,second+10,8,2);set(&z,local+8,8,2);cases.append(z)
        z=zip;z[local+35] ^= 1;cases.append(z)
        cases.append(zip+Data([1]));cases.append(Data(zip.dropLast()))
        for data in cases { XCTAssertThrowsError(try ASiCZIP.read(data)) }
    }
    func testMetadataLimitsPreventOversizedSignatureAndManifest() throws {
        let mime = ASiCZIP.Entry(name:"mimetype",data:Data(ASiC.Kind.simple.mime.utf8))
        for (name,limit) in [(ASiC.signatureName,128*1024),(ASiC.manifestName,16*1024)] {
            XCTAssertThrowsError(try ASiCZIP.write([mime,.init(name:"doc.txt",data:Data([1])),.init(name:name,data:Data(repeating:65,count:limit+1))]))
        }
    }
    func testRawDuplicateZIPNamesRejectedBeforeInflation() throws {
        let zip = try ASiC.unsignedArchive(kind:.extended,payloads:[.init(name:"one.txt",data:Data([1])),.init(name:"two.txt",data:Data([2]))])
        let central=value(zip,zip.count-6,4),first=central+46+value(zip,central+28,2)
        let second=first+46+value(zip,first+28,2),local=value(zip,second+42,4)
        var changed=zip
        changed.replaceSubrange(second+46..<second+53,with:Data("ONE.txt".utf8))
        changed.replaceSubrange(local+30..<local+37,with:Data("ONE.txt".utf8))
        XCTAssertThrowsError(try ASiCZIP.read(changed))
    }
    func testZIPDuplicatesAndUnsupportedMetadataCannotBeHidden() throws {
        XCTAssertThrowsError(try ASiCZIP.write([.init(name:"mimetype",data:Data(ASiC.Kind.simple.mime.utf8)),.init(name:"a.txt",data:Data([1])),.init(name:"A.txt",data:Data([2]))]))
        try fixture { root,signer in
            let archive = try signed(.simple,root:root,signer:signer), entries = try ASiCZIP.read(archive)
            let extra = try ASiCZIP.write(entries+[.init(name:ASiC.manifestName,data:Data("<wrong/>".utf8))])
            XCTAssertThrowsError(try ASiC.verify(extra))
            XCTAssertThrowsError(try ASiC.Prepared(unsignedArchive:archive,certificateDER:signer.der))
        }
    }
    func testIndependentZIPAndDetachedXMLDSigInteroperability() throws {
        try fixture { root,signer in
            let binary = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_XMLSEC"])
            let cli=URL(fileURLWithPath:binary),archive=try signed(.extended,root:root,signer:signer)
            try archive.write(to:root.appendingPathComponent("input.asice"))
            try run(URL(fileURLWithPath:"/usr/bin/unzip"),["-t","input.asice"],root:root)
            let entries = try ASiCZIP.read(archive)
            try FileManager.default.createDirectory(at:root.appendingPathComponent("META-INF"),withIntermediateDirectories:false)
            for entry in entries { try entry.data.write(to:root.appendingPathComponent(entry.name == ASiC.signatureName ? "signature.xml" : entry.name)) }
            try run(cli,["--verify","--trusted-der","certificate.der","--id-attr:Id","SignedProperties","signature.xml"],root:root)
            let unsigned = try ASiC.unsignedArchive(kind:.extended,payloads:payloads),p=try ASiC.Prepared(unsignedArchive:unsigned,certificateDER:signer.der)
            try p.template.write(to:root.appendingPathComponent("template.xml"))
            try run(cli,["--sign","--lax-key-search","--enabled-key-data","rsa","--privkey-pem","key.pem,certificate.pem","--id-attr:Id","SignedProperties","--output","independent.xml","template.xml"],root:root)
            let inverse = try ASiCZIP.write(entries.map { $0.name == ASiC.signatureName ? .init(name:$0.name,data:try Data(contentsOf:root.appendingPathComponent("independent.xml"))) : $0 })
            XCTAssertNoThrow(try ASiC.verify(inverse))
            let python = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PYTHON"])
            let script = "import zipfile\na=zipfile.ZipFile('input.asice')\nb=zipfile.ZipFile('deflated.asice','w')\nfor i in a.infolist():\n b.writestr(i.filename,a.read(i.filename),compress_type=zipfile.ZIP_STORED if i.filename=='mimetype' else zipfile.ZIP_DEFLATED)\nb.close()\n"
            try run(URL(fileURLWithPath:python),["-c",script],root:root)
            XCTAssertNoThrow(try ASiC.verify(Data(contentsOf:root.appendingPathComponent("deflated.asice"))))
        }
    }
    func testWorkerAndExclusivePublicationRetainCapturedMultiDocumentSet() throws {
        try fixture { root,signer in
            var urls = [URL]()
            for p in payloads { let u=root.appendingPathComponent(p.name);try p.data.write(to:u);urls.append(u) }
            let snapshot=try ASiC.capture(sources:urls,kind:.extended)
            XCTAssertEqual(Set(snapshot.containerPayloadNames),Set(payloads.map(\.name)))
            let mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
            let job=try SigningJob(snapshot:snapshot,providerPath:mock.path.resolvingSymlinksInPath().path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([0x53])),certificateDER:signer.der,destination:root.appendingPathComponent("result.asice"))
            XCTAssertTrue(payloads.allSatisfy { job.approvalDescription.contains($0.name) && job.approvalDescription.contains(DocumentSnapshot.digest($0.data)) })
            for u in urls { try Data("changed after capture".utf8).write(to:u) }
            let worker=Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"),op=SigningOperation()
            try job.signXAdES(using:IsolatedPKCS11Client(executable:worker),pin:"synthetic-fixture",operation:op)
            XCTAssertEqual(op.state,.completed);XCTAssertEqual(mock.count(8),0)
            let verified=try ASiC.verify(Data(contentsOf:job.destination))
            for p in payloads { XCTAssertEqual(verified.payloads.first { $0.name == p.name }?.data,p.data) }
            XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
        }
    }
    func testCancellationInvalidSignatureAndOccupiedDestinationNeverPublish() throws {
        for variant in 0..<3 {
            try fixture { root,signer in
                let source=root.appendingPathComponent("doc.txt");try payloads[0].data.write(to:source)
                let snapshot=try ASiC.capture(sources:[source],kind:.simple),destination=root.appendingPathComponent("result.asics")
                let job=try SigningJob(snapshot:snapshot,providerPath:"/synthetic",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:signer.der,destination:destination)
                if variant==2 { try Data("preserved".utf8).write(to:destination) }
                var calls=0
                XCTAssertThrowsError(try job.executeXAdES(isCancelled:{ variant==0 }) { _ in calls+=1;return Data(repeating:0,count:256) })
                XCTAssertEqual(calls,variant==1 ? 1 : 0)
                if variant==2 { XCTAssertEqual(try Data(contentsOf:destination),Data("preserved".utf8)) }
                else { XCTAssertFalse(FileManager.default.fileExists(atPath:destination.path)) }
                XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
            }
        }
    }
    @MainActor func testGUIAcquisitionGroupsASiCEAndFreezesAllPayloadsInOneApproval() async throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("signum-asic-review-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false);defer { try? FileManager.default.removeItem(at:root) }
        let signer=try SoftwareSigner(folder:root);var urls=[URL]()
        for p in payloads { let u=root.appendingPathComponent(p.name);try p.data.write(to:u);urls.append(u) }
        let batch=BatchSigningCoordinator();defer { batch.reset() }
        await batch.addDocuments(urls,format:.asice)
        XCTAssertEqual(batch.documents.count,1,batch.selectionIssues.joined(separator:"; "));let s=try XCTUnwrap(batch.documents.first)
        XCTAssertEqual(s.format,.asice)
        let approval=try await batch.prepareReview(provider:"/synthetic",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders)
        XCTAssertEqual(approval.jobs.count,1);XCTAssertEqual(approval.jobs[0].destination.deletingLastPathComponent().resolvingSymlinksInPath().path,root.resolvingSymlinksInPath().path)
        XCTAssertTrue(approval.jobs[0].approvalDescription.contains("dati à.bin"))
        try batch.freezeReview(approval);try batch.confirm(approval)
        XCTAssertThrowsError(try batch.setFormat(.cades,for:s.id))
        await batch.addDocuments(urls,format:.asice);XCTAssertEqual(batch.documents.count,1)
        let simple=BatchSigningCoordinator();defer { simple.reset() }
        await simple.addDocuments(urls,format:.asics)
        XCTAssertEqual(simple.documents.count,2);XCTAssertTrue(simple.documents.allSatisfy { $0.snapshot.containerPayloadNames.count == 1 })
        let invalid=BatchSigningCoordinator();defer { invalid.reset() }
        await invalid.addDocuments([urls[0]],format:.asice);XCTAssertTrue(invalid.documents.isEmpty);XCTAssertFalse(invalid.selectionIssues.isEmpty)
    }
}
#endif
