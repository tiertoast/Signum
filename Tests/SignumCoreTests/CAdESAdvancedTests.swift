#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

final class CAdESAdvancedTests: XCTestCase {
    let content=Data([0,255,13,10])+Data("Contenuto sintetico CAdES avanzato\n".utf8)
    var helper: URL { get throws { URL(fileURLWithPath:try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])) } }
    func publicEvidence(_ name: String,_ bytes: Data) throws {
        if let path=ProcessInfo.processInfo.environment["SIGNUM_TEST_CADES_INTEROP"] {
            let root=URL(fileURLWithPath:path);try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            try bytes.write(to:root.appendingPathComponent(name),options:.atomic)
        }
    }
    func fixture(_ body: (URL,SoftwareSigner,SoftwareSigner) throws -> Void) throws {
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-cades-advanced-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer {try? FileManager.default.removeItem(at:root)}
        let second=root.appendingPathComponent("second");try FileManager.default.createDirectory(at:second,withIntermediateDirectories:false)
        try body(root,SoftwareSigner(folder:root),SoftwareSigner(folder:second))
    }
    @discardableResult func run(_ args: [String],at root: URL,executable: URL=URL(fileURLWithPath:"/usr/bin/openssl")) throws -> Data {
        let p=Process(),pipe=Pipe();p.executableURL=executable;p.arguments=args;
        if executable.path != "/usr/bin/openssl" {var env=ProcessInfo.processInfo.environment;env["DYLD_LIBRARY_PATH"]=executable.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("lib").path;p.environment=env}
p.currentDirectoryURL=root;p.standardOutput=pipe;p.standardError=pipe
        try p.run();let out=pipe.fileHandleForReading.readDataToEndOfFile();try FixtureProcess.wait(p)
        guard p.terminationStatus==0 else {XCTFail(String(decoding:out,as:UTF8.self));throw SignumError.invalidSignature};return out
    }
    func sign(_ bytes: Data,with signer: SoftwareSigner) throws -> Data {
        try bytes.write(to:signer.folder.appendingPathComponent("attributes"))
        try run(["dgst","-sha256","-sign","key.pem","-out","signature","attributes"],at:signer.folder)
        return try Data(contentsOf:signer.folder.appendingPathComponent("signature"))
    }
    func advanced(_ input: Data,format: SigningFormat,signer: SoftwareSigner,target: String?=nil) throws -> Data {
        let p=try CAdESAdvanced.Prepared(document:input,format:format,certificateDER:signer.der,counterSignatureKey:target,helper:helper)
        return try p.finish(signature:sign(p.attributesToSign,with:signer))
    }
    func report(_ data: Data,original: Data?=nil) throws -> VerificationReport {
        try SignumVerificationService.verify(data:data,name:"synthetic",detachedContent:original,helper:helper)
    }
    func testDetachedExactBinaryAssociationAndIndependentOpenSSL() throws {
        try fixture { root,a,_ in
            let cms=try advanced(content,format:.cadesDetached,signer:a)
            try publicEvidence("detached.p7s",cms);try publicEvidence("original.bin",content)
            XCTAssertNil(try CAdESAdvanced.Container(cms).document)
            let valid=try report(cms,original:content)
            XCTAssertEqual(valid.integrity,.verified);XCTAssertEqual(valid.originalContent,content)
            XCTAssertEqual(valid.detachedContentSHA256,DocumentSnapshot.digest(content))
            XCTAssertEqual(try report(cms).integrity,.notVerifiable)
            var wrong=content;wrong[wrong.startIndex]^=1
            XCTAssertEqual(try report(cms,original:wrong).integrity,.invalid)
            XCTAssertNil(try report(cms,original:wrong).originalContent)
            try cms.write(to:root.appendingPathComponent("signature.p7s"));try content.write(to:root.appendingPathComponent("document"))
            try run(["cms","-verify","-binary","-inform","DER","-in","signature.p7s","-content","document","-noverify","-out","extracted"],at:root)
            XCTAssertEqual(try Data(contentsOf:root.appendingPathComponent("extracted")),content)
            XCTAssertEqual(try SignumVerificationService.verifyDetached(signature:root.appendingPathComponent("signature.p7s"),content:root.appendingPathComponent("document"),helper:helper).integrity,.verified)
        }
    }
    func testDetachedRejectsAttachedSubstitutionUnsafeOriginalAndCancellation() throws {
        try fixture { root,a,_ in
            let attached=try a.cms(for:content)
            XCTAssertEqual(try report(attached,original:content).integrity,.notVerifiable)
            let cms=try advanced(content,format:.cadesDetached,signer:a)
            let sig=root.appendingPathComponent("signature.p7s"),doc=root.appendingPathComponent("document"),link=root.appendingPathComponent("link")
            try cms.write(to:sig);try content.write(to:doc);try FileManager.default.createSymbolicLink(at:link,withDestinationURL:doc)
            XCTAssertThrowsError(try SignumVerificationService.verifyDetached(signature:sig,content:link,helper:helper))
            XCTAssertThrowsError(try SignumVerificationService.verifyDetached(signature:sig,content:doc,helper:helper,isCancelled:{true}))
            XCTAssertThrowsError(try report(cms,original:Data()))
        }
    }
    func testCoSignaturePreservesEveryPreviousSignedByteAndUnsignedAttribute() throws {
        try fixture { root,a,b in
            let original=try a.cms(for:content),old=try CAdESAdvanced.Container(original)
            var signer=try CAdESAdvanced.Signer(old.signers[0]);var unsigned=DER.set([DER.attribute(oid:Data([6,3,42,3,4]),value:DER.octets(Data([9,8,7])))])
            unsigned[0]=0xa1;signer.parts.append(unsigned)
            var parts=old.parts;parts[parts.count-1]=DER.set([signer.encoded])
            let annotated=DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(parts))])
            let result=try advanced(annotated,format:.cadesCoSign,signer:b),updated=try CAdESAdvanced.Container(result)
            try publicEvidence("cofirmato.p7m",result)
            XCTAssertTrue(updated.signers.contains(signer.encoded));XCTAssertEqual(updated.document,content)
            XCTAssertEqual(updated.parts[2],old.parts[2]);XCTAssertEqual(try report(result).signatures.count,2)
            XCTAssertTrue(try report(result).signatures.allSatisfy{$0.counterSignatureOf==nil && $0.integrity == .verified})
            try result.write(to:root.appendingPathComponent("co.p7m"))
            try run(["cms","-verify","-binary","-inform","DER","-in","co.p7m","-noverify","-out","output"],at:root)
            XCTAssertEqual(try Data(contentsOf:root.appendingPathComponent("output")),content)
        }
    }
    func testOpenSSLCoSignIsRecognizedIndependently() throws {
        try fixture { root,a,b in
            try a.cms(for:content).write(to:root.appendingPathComponent("input.p7m"))
            let xmlsec=URL(fileURLWithPath:try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_XMLSEC"]))
            let openssl3=xmlsec.deletingLastPathComponent().appendingPathComponent("openssl")
            try run(["cms","-resign","-binary","-md","sha256","-nodetach","-inform","DER","-in","input.p7m","-signer",b.folder.appendingPathComponent("certificate.pem").path,"-inkey",b.folder.appendingPathComponent("key.pem").path,"-outform","DER","-out","co.p7m"],at:root,executable:openssl3)
            let r=try report(Data(contentsOf:root.appendingPathComponent("co.p7m")))
            XCTAssertEqual(r.integrity,.verified);XCTAssertEqual(r.signatures.count,2);XCTAssertEqual(r.originalContent,content)
        }
    }
    func testCounterSignatureBindsSignatureValueAndLeavesSignedFieldsUntouched() throws {
        try fixture { root,a,b in
            let cms=try a.cms(for:content),key=try CAdESAdvanced.targets(in:cms)[0].signatureKey
            let result=try advanced(cms,format:.cadesCounterSign,signer:b,target:key)
            try publicEvidence("controfirmato.p7m",result)
            let old=try CAdESAdvanced.Signer(CAdESAdvanced.Container(cms).signers[0]),new=try CAdESAdvanced.Signer(CAdESAdvanced.Container(result).signers[0])
            XCTAssertEqual(Array(old.parts.prefix(old.signatureIndex+1)),Array(new.parts.prefix(new.signatureIndex+1)))
            let child=try CAdESAdvanced.Signer(XCTUnwrap(new.counters().first))
            let r=try report(result);XCTAssertEqual(r.integrity,.verified);XCTAssertEqual(r.signatures.count,2)
            XCTAssertEqual(r.signatures.filter{$0.counterSignatureOf==key}.count,1)
            let counter=try XCTUnwrap(r.signatures.first{$0.counterSignatureOf != nil})
            XCTAssertEqual(counter.signerDER,b.der);XCTAssertFalse(counter.evidence!.signedAttributes.contains{$0.oid=="1.2.840.113549.1.9.3"})
            XCTAssertEqual(counter.evidence!.signatureKey,try child.key)
            var attrs=child.parts[3];attrs[0]=0x31
            try attrs.write(to:root.appendingPathComponent("counter-attrs"));try child.value.write(to:root.appendingPathComponent("counter-signature"))
            try old.value.write(to:root.appendingPathComponent("parent-value"))
            try run(["x509","-in",b.folder.appendingPathComponent("certificate.pem").path,"-pubkey","-noout"],at:root).write(to:root.appendingPathComponent("public.pem"))
            try run(["dgst","-sha256","-verify","public.pem","-signature","counter-signature","counter-attrs"],at:root)
            let digest=try run(["dgst","-sha256","-binary","parent-value"],at:root)
            let md=try CAdESAdvanced.fields(child.parts[3],tag:0xa0).first { try CAdESAdvanced.fields($0,tag:0x30)[0]==DER.messageDigestAttributeOID }
            XCTAssertEqual(try CAdESAdvanced.fields(XCTUnwrap(md),tag:0x30)[1],DER.set([DER.octets(digest)]))
        }
    }
    func testCounterSignatureCannotMoveBetweenCoSignersAndTamperIsIndividual() throws {
        try fixture { _,a,b in
            let co=try advanced(a.cms(for:content),format:.cadesCoSign,signer:b),c=try CAdESAdvanced.Container(co)
            let key=try CAdESAdvanced.Signer(c.signers[0]).key
            let signed=try advanced(co,format:.cadesCounterSign,signer:b,target:key),container=try CAdESAdvanced.Container(signed)
            let parent=try XCTUnwrap(container.signers.first { try CAdESAdvanced.Signer($0).key==key })
            let s=try CAdESAdvanced.Signer(parent),other=try XCTUnwrap(container.signers.first { try CAdESAdvanced.Signer($0).key != key })
            var moved=try CAdESAdvanced.Signer(other);moved.parts.append(s.parts.last!)
            var raw=s.parts;raw.removeLast()
            var outer=container.parts;outer[outer.count-1]=DER.set([DER.sequence(raw),moved.encoded])
            let r=try report(DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(outer))]))
            XCTAssertEqual(r.integrity,.invalid);XCTAssertEqual(r.signatures.filter{$0.counterSignatureOf==nil && $0.integrity == .verified}.count,2)
            XCTAssertEqual(r.signatures.first{$0.counterSignatureOf != nil}?.integrity,.invalid)
            var child=try CAdESAdvanced.Signer(XCTUnwrap(s.counters().first));var bytes=try child.value;bytes[0]^=1;child.parts[child.signatureIndex]=DER.octets(bytes)
            var changed=s.parts;changed[changed.count-1]=DER.wrap(0xa1,try CAdESAdvanced.content(DER.set([DER.attribute(oid:CAdESAdvanced.counterOID,value:child.encoded)]),tag:0x31))
            outer[outer.count-1]=DER.set([DER.sequence(changed),other])
            let damaged=try report(DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(outer))]))
            XCTAssertEqual(damaged.integrity,.invalid);XCTAssertEqual(damaged.signatures.filter{$0.counterSignatureOf==nil && $0.integrity == .verified}.count,2)
        }
    }
    func testParentContentFailureCannotPromoteCounterAndContentTypeIsForbidden() throws {
        try fixture { _,a,b in
            let base=try a.cms(for:content),key=try CAdESAdvanced.targets(in:base)[0].signatureKey
            let cms=try advanced(base,format:.cadesCounterSign,signer:b,target:key)
            var changed=cms;let range=try XCTUnwrap(changed.range(of:content));changed[range.lowerBound]^=1
            let r=try report(changed)
            XCTAssertEqual(r.integrity,.invalid);XCTAssertEqual(r.signatures.first{$0.counterSignatureOf != nil}?.integrity,.notVerifiable)
            XCTAssertNil(r.originalContent)
            let c=try CAdESAdvanced.Container(cms);var parent=try CAdESAdvanced.Signer(c.signers[0])
            var child=try CAdESAdvanced.Signer(XCTUnwrap(parent.counters().first))
            let attrs=try CAdESAdvanced.fields(child.parts[3],tag:0xa0)
            var newAttrs=DER.set(attrs+[DER.attribute(oid:DER.contentTypeAttributeOID,value:DER.dataOID)]);newAttrs[0]=0xa0;child.parts[3]=newAttrs
            var unsigned=DER.set([DER.attribute(oid:CAdESAdvanced.counterOID,value:child.encoded)]);unsigned[0]=0xa1;parent.parts[parent.parts.count-1]=unsigned
            var parts=c.parts;parts[parts.count-1]=DER.set([parent.encoded])
            let rejected=try report(DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(parts))]))
            XCTAssertEqual(rejected.signatures.first{$0.counterSignatureOf != nil}?.integrity,.invalid)
        }
    }
    func testNestedCountersAndCoSignRetainExistingCounter() throws {
        try fixture { _,a,b in
            let cms=try a.cms(for:content),key=try CAdESAdvanced.targets(in:cms)[0].signatureKey
            let first=try advanced(cms,format:.cadesCounterSign,signer:b,target:key)
            let counter=try XCTUnwrap(report(first).signatures.first{$0.counterSignatureOf != nil})
            let nested=try advanced(first,format:.cadesCounterSign,signer:a,target:counter.evidence!.signatureKey)
            let r=try report(nested);XCTAssertEqual(r.integrity,.verified);XCTAssertEqual(r.signatures.count,3)
            XCTAssertEqual(r.signatures.filter{$0.counterSignatureOf != nil}.count,2)
            let co=try advanced(nested,format:.cadesCoSign,signer:b)
            XCTAssertEqual(try report(co).signatures.count,4)
            XCTAssertTrue(try CAdESAdvanced.Container(co).signers.contains(CAdESAdvanced.Container(nested).signers[0]))
        }
    }
    func testInvalidCMSUnknownTargetAndMalformedDERFailBeforeSigning() throws {
        try fixture { _,a,b in
            let cms=try a.cms(for:content)
            XCTAssertThrowsError(try CAdESAdvanced.targets(in:cms+Data([0])))
            for key in [nil,String(repeating:"0",count:64)] {
                XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:cms,format:.cadesCounterSign,certificateDER:b.der,counterSignatureKey:key,helper:helper))
            }
            var bad=cms;if let r=bad.range(of:content){bad[r.lowerBound]^=1}
            XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:bad,format:.cadesCoSign,certificateDER:b.der,helper:helper))
            let detached=try advanced(content,format:.cadesDetached,signer:a)
            XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:detached,format:.cadesCoSign,certificateDER:b.der,helper:helper))
            var c=try CAdESAdvanced.Container(cms).parts;c[c.count-1]=DER.set(Array(repeating:try CAdESAdvanced.Container(cms).signers[0],count:33))
            XCTAssertThrowsError(try CAdESAdvanced.targets(in:DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(c))])))
        }
    }
    func testCounterDepthAndSignerCountLimitsAreRejectedBeforeWorker() throws {
        try fixture { _,a,b in
            var cms=try a.cms(for:content)
            var target=try CAdESAdvanced.targets(in:cms)[0].signatureKey
            for _ in 0..<4 {
                cms=try advanced(cms,format:.cadesCounterSign,signer:b,target:target)
                let signatures=try report(cms).signatures
                target=try XCTUnwrap(signatures.last?.evidence?.signatureKey)
            }
            XCTAssertEqual(try report(cms).signatures.count,5)
            XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:cms,format:.cadesCounterSign,certificateDER:a.der,counterSignatureKey:target,helper:helper)) { XCTAssertTrue($0.localizedDescription.contains("quattro livelli")) }
            let base=try CAdESAdvanced.Container(a.cms(for:content));var parts=base.parts
            let many=try (0..<32).map { i -> Data in
                var signer=try CAdESAdvanced.Signer(base.signers[0]),value=try signer.value
                value[0]=UInt8(i);signer.parts[signer.signatureIndex]=DER.octets(value);return signer.encoded
            }
            parts[parts.count-1]=DER.set(many)
            let full=DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(parts))])
            XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:full,format:.cadesCoSign,certificateDER:b.der,helper:URL(fileURLWithPath:"/never-launch"))) { XCTAssertTrue($0.localizedDescription.contains("32 firme")) }
        }
    }
    func testAmbiguousIssuerSerialCertificateNeverAuthorizesCoSigning() throws {
        try fixture { _,a,b in
            let identity=try DER.certificateIdentity(a.der)
            var certificate=try CAdESAdvanced.fields(b.der,tag:0x30),tbs=try CAdESAdvanced.fields(certificate[0],tag:0x30)
            tbs[tbs[0].first==0xa0 ? 1:0]=identity.serial
            certificate[0]=DER.sequence(tbs)
            // Deliberately untrusted synthetic certificate with a colliding CMS SID.
            let extra=DER.sequence(certificate),original=try a.cms(for:content),container=try CAdESAdvanced.Container(original)
            XCTAssertEqual(try DER.certificateIdentity(extra).serial,identity.serial)
            XCTAssertEqual(try DER.certificateIdentity(extra).issuer,identity.issuer)
            var parts=container.parts,set=DER.set(container.certificates+[extra]);set[0]=0xa0;parts[3]=set
            let ambiguous=DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(parts))])
            let r=try report(ambiguous);XCTAssertEqual(r.integrity,.notVerifiable)
            XCTAssertTrue(r.signatures[0].reason.contains("ambigua"))
            XCTAssertThrowsError(try CAdESAdvanced.Prepared(document:ambiguous,format:.cadesCoSign,certificateDER:b.der,helper:helper))
        }
    }
    func testLegacyVerifierRefusesPartialCounterVerification() throws {
        try fixture { _,a,b in
            let original=try a.cms(for:content),key=try CAdESAdvanced.targets(in:original)[0].signatureKey
            let cms=try advanced(original,format:.cadesCounterSign,signer:b,target:key)
            XCTAssertThrowsError(try CAdESVerifier.verify(data:cms)) {XCTAssertTrue($0.localizedDescription.contains("controfirme"))}
            XCTAssertThrowsError(try CAdESVerifier.verifyAttached(data:cms,expectedDocument:content))
            XCTAssertEqual(try report(cms).integrity,.verified)
        }
    }
    func testSyntheticWorkerPublishesAllAdvancedOperationsFromImmutableSnapshot() throws {
        try fixture { root,a,b in
            let attached=try a.cms(for:content),key=try CAdESAdvanced.targets(in:attached)[0].signatureKey
            let mock=try MockModule(certificate:b.der,privateKey:b.rsaPrivateDER())
            for format in [SigningFormat.cadesDetached,.cadesCoSign,.cadesCounterSign] {
                let input=format == .cadesDetached ? content:attached,source=root.appendingPathComponent(format.rawValue+".input")
                try input.write(to:source)
                let snapshot=try DocumentSnapshot.capture(source:source,format:format)
                let out=root.appendingPathComponent(format.rawValue+"."+format.outputExtension)
                let job=try SigningJob(snapshot:snapshot,format:format,providerPath:mock.path.resolvingSymlinksInPath().path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([0x53])),certificateDER:b.der,destination:out,counterSignatureKey:format == .cadesCounterSign ? key:nil)
                try Data("Changed after capture".utf8).write(to:source)
                let operation=SigningOperation()
                try job.signAdvancedCAdES(using:IsolatedPKCS11Client(executable:Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")),pin:"1234",operation:operation,helper:helper)
                XCTAssertEqual(operation.state,.completed)
                XCTAssertEqual(try report(Data(contentsOf:out),original:format == .cadesDetached ? input:nil).integrity,.verified)
                XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
            }
        }
    }
    func testCancellationInvalidWorkerAndOccupiedOutputNeverPublish() throws {
        try fixture { root,a,_ in
            for variant in 0..<4 {
                let source=root.appendingPathComponent("in\(variant)");try content.write(to:source)
                let snapshot=try DocumentSnapshot.capture(source:source,format:.cadesDetached)
                let out=root.appendingPathComponent("out\(variant).p7s")
                let job=try SigningJob(snapshot:snapshot,format:.cadesDetached,providerPath:"/synthetic",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:a.der,destination:out)
                if variant==2 {try Data("preserved".utf8).write(to:out)}
                var calls=0,cancelled=variant==0
                XCTAssertThrowsError(try job.executeXAdES(helper:helper,isCancelled:{cancelled}) { attrs in
                    calls+=1
                    if variant==3 {cancelled=true;return try sign(attrs,with:a)}
                    return Data(repeating:0,count:256)
                })
                XCTAssertEqual(calls,variant==0 || variant==2 ? 0:1)
                if variant==2 {XCTAssertEqual(try Data(contentsOf:out),Data("preserved".utf8))}
                else {XCTAssertFalse(FileManager.default.fileExists(atPath:out.path))}
            }
        }
    }
    @MainActor func testCounterTargetSelectionInvalidatesReviewAndIsFrozenInJob() async throws {
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-counter-review-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false);defer {try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),file=root.appendingPathComponent("input.p7m")
        try signer.cms(for:content).write(to:file)
        let batch=BatchSigningCoordinator();await batch.enqueueDocuments([file],format:.cadesCounterSign)?.value
        defer {batch.reset()}
        let id=try XCTUnwrap(batch.documents.first?.id),key=try XCTUnwrap(batch.documents.first?.snapshot.cmsSignatureTargets.first?.signatureKey)
        do { _=try await batch.prepareReview(provider:"/synthetic",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders);XCTFail("Missing explicit target") } catch {}
        let before=batch.revision;try batch.selectCounterSignature(key,for:id);XCTAssertNotEqual(before,batch.revision)
        let review=try await batch.prepareReview(provider:"/synthetic",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders)
        XCTAssertEqual(review.jobs[0].counterSignatureKey,key);XCTAssertTrue(review.jobs[0].approvalDescription.contains(key))
        try batch.freezeReview(review)
        XCTAssertThrowsError(try batch.selectCounterSignature(key,for:id))
    }
}
#endif
