// Fixed local performance experiment; not an application or benchmark assertion.
import Foundation
import Darwin
import Security
import PDFKit
import SwiftUI
@testable import SignumCore
@_silgen_name("signum_profile_resident") func resident() -> UInt64
@_silgen_name("signum_profile_disk") func disk(_ write: Int32) -> UInt64
let started = ProcessInfo.processInfo.systemUptime
func mark(_ phase: String, _ bytes: Int = 0, facts: [String: Any] = [:]) {
    var r = rusage(); getrusage(RUSAGE_SELF, &r)
    let cpu = Double(r.ru_utime.tv_sec + r.ru_stime.tv_sec) + Double(r.ru_utime.tv_usec + r.ru_stime.tv_usec)/1e6
    var childUsage = rusage(); getrusage(RUSAGE_CHILDREN, &childUsage)
    var row: [String: Any] = ["phase": phase, "dataBytes": bytes, "rss": resident(), "peakRSS": r.ru_maxrss,
        "cpu": cpu, "wall": ProcessInfo.processInfo.systemUptime-started,
        "childrenPeakRSS": childUsage.ru_maxrss, "childrenCPU": Double(childUsage.ru_utime.tv_sec + childUsage.ru_stime.tv_sec) + Double(childUsage.ru_utime.tv_usec + childUsage.ru_stime.tv_usec)/1e6, "diskRead": disk(0), "diskWrite": disk(1), "pid": getpid(), "role": "diagnostic-parent"]
    row.merge(facts) { _, new in new }
    print(String(data: try! JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]), encoding: .utf8)!)
    fflush(stdout)
}
func require(_ yes: Bool) throws { if !yes { throw NSError(domain: "ProfileCorrectness", code: 1) } }
@main struct Probe {
    @MainActor static func main() async throws {
        // mode input output-dir fixture-dir native-helper worker
        let args=CommandLine.arguments
        guard args.count == 7 else { fatalError("mode input output fixture helper worker") }
        let mode=args[1], input=URL(fileURLWithPath:args[2]), out=URL(fileURLWithPath:args[3])
        let fixture=URL(fileURLWithPath:args[4]), helper=URL(fileURLWithPath:args[5]), worker=URL(fileURLWithPath:args[6])
        let cert=try Data(contentsOf:fixture.appendingPathComponent("certificate.der"))
        let certificate=SignumCertificate(label:"Synthetic",identifier:Data([1]))
        mark("start")
        let client=IsolatedPKCS11Client(executable:worker)
        var binding: SigningProviderContext?
        if ["cades-job","pades","pades-visible","pades-incremental","batch","batch-budget"].contains(mode) {
            let inspected=try MiddlewareFileSecurity.inspect(fixture.appendingPathComponent("synthetic-provider.dylib").path,automatic:false)
            let token=try client.scan(provider:inspected.canonicalPath).tokens[0]
            binding=SigningProviderContext(version:1,provider:inspected.canonicalPath,moduleIdentity:inspected.identity,automatic:false,
                token:token,objectID:certificate.identifier,certificateSHA256:DocumentSnapshot.digest(cert),routeID:String(repeating:"a",count:64),discoveryID:UUID())
            mark("public-synthetic-context")
        }
        switch mode {
        case "acquisition":
            var io=DocumentSnapshot.CaptureIO(), readBytes=0, reads=0, clones=0
            let originalRead=io.read, originalClone=io.clone
            io.read={ fd, pointer, count in let n=originalRead(fd,pointer,count); reads+=1; if n>0 { readBytes+=n }; return n }
            io.clone={ fd, directory, name in clones+=1; return originalClone(fd,directory,name) }
            var snapshot: DocumentSnapshot? = try DocumentSnapshot.capture(source:input,format:.cades,privateRoot:out,io:io)
            mark("clone-read-hash",snapshot!.identity.byteCount,facts:["captureReadBytes":readBytes,"captureReadCalls":reads,"cloneCalls":clones])
            _ = try snapshot!.verifiedBytes(); mark("identity-read-compare-hash",snapshot!.identity.byteCount)
            let path=snapshot!.fileURL; snapshot!.close(); snapshot=nil
            try require(!FileManager.default.fileExists(atPath:path.path)); mark("cleanup")
        case "cms":
            let bytes=try Data(contentsOf:input); mark("read",bytes.count)
            let prepared=try CAdES.Prepared(document:bytes,certificateDER:cert); mark("prepare",prepared.attributesToSign.count)
            let keyBytes=try Data(contentsOf:fixture.appendingPathComponent("key.der"))
            let key=SecKeyCreateWithData(keyBytes as CFData,[kSecAttrKeyType:kSecAttrKeyTypeRSA,kSecAttrKeyClass:kSecAttrKeyClassPrivate] as CFDictionary,nil)!
            let signature=SecKeyCreateSignature(key,.rsaSignatureMessagePKCS1v15SHA256,prepared.attributesToSign as CFData,nil)! as Data
            mark("synthetic-software-sign",signature.count)
            let cms=try prepared.finish(signature:signature); mark("serialize",cms.count)
            try cms.write(to:out.appendingPathComponent("result.p7m")); mark("output-written",cms.count)
            withExtendedLifetime((bytes,prepared,cms)) {}
        case "metadata":
            let bytes=try Data(contentsOf:input); mark("read",bytes.count)
            try require(CMSDescription.isSignedData(bytes)); mark("content-type",bytes.count)
            try require(try CMSDescription.signers(in:bytes).count == 1); mark("signer-metadata",bytes.count)
            withExtendedLifetime(bytes) {}
        case "attached":
            let bytes=try Data(contentsOf:input), original=try Data(contentsOf:URL(fileURLWithPath:input.path+".source"))
            mark("read",bytes.count+original.count)
            try CAdESVerifier.verifyAttached(data:bytes,expectedDocument:original); mark("independent-attached-verifier",bytes.count)
        case "cades-job":
            let snapshot=try DocumentSnapshot.capture(source:input,format:.cades,privateRoot:out)
            mark("capture",snapshot.identity.byteCount)
            let job=try SigningJob(snapshot:snapshot,providerPath:fixture.appendingPathComponent("synthetic-provider.dylib").path,slot:7,
                certificate:certificate,certificateDER:cert,destination:out.appendingPathComponent("result.p7m"),
                destinationDirectoryIdentity:OutputDirectoryIdentity.inspect(out).1,providerContext:binding)
            try job.executeCAdES { bytes in
                mark("pre-private-snapshot-checked",bytes.count)
                let prepared=try CAdES.Prepared(document:bytes,certificateDER:cert); mark("prepare",bytes.count)
                // Fixed follow-up records one standalone worker's resources.
                // The synthetic request is removed by the external adapter and
                // is never logged or included in the evidence archive.
                var request=PKCS11WorkerRequest(version:2,id:UUID(),action:.rsaSHA256,provider:job.providerPath,slot:7,
                    certificate:WorkerCertificate(certificate,der:cert),attributes:prepared.attributesToSign,pin:"synthetic",leaseWaitMilliseconds:10000)
                request.providerContext=binding; request.expectedModule=binding?.moduleIdentity; request.automaticModule=false
                try JSONEncoder().encode(request).write(to:out.appendingPathComponent("worker-request.json"))
                try prepared.attributesToSign.write(to:out.appendingPathComponent("attributes"))
                let signature=try client.sign(provider:job.providerPath,slot:7,certificate:certificate,der:cert,
                    attributes:prepared.attributesToSign,pin:"synthetic",id:job.id,providerContext:binding)
                mark("isolated-worker-returned",signature.count)
                let cms=try prepared.finish(signature:signature); mark("serialize",cms.count); return cms
            }
            mark("staged-readback-verified-published",snapshot.identity.byteCount)
            try require(!FileManager.default.fileExists(atPath:snapshot.fileURL.path))
        case "pades", "pades-visible", "pades-incremental":
            let snapshot=try DocumentSnapshot.capture(source:input,format:.pades,privateRoot:out); mark("capture",snapshot.identity.byteCount)
            let preflight=try PAdESSourcePreflight.inspect(snapshot,helper:helper); mark("source-preflight",snapshot.identity.byteCount)
            var appearance: RenderedPAdESAppearance?
            if mode != "pades" {
                var c=PAdESAppearanceConfiguration(); c.showSigner=false; c.customText="Synthetic profile"
                appearance=try PAdESAppearanceRenderer.render(c,certificateDER:cert,cropBox:CGRect(x:0,y:0,width:595,height:842))
            }
            mark("appearance",appearance?.pdf.count ?? 0)
            let job=try SigningJob(snapshot:snapshot,providerPath:fixture.appendingPathComponent("synthetic-provider.dylib").path,slot:7,
                certificate:certificate,certificateDER:cert,destination:out.appendingPathComponent("result.pdf"),
                destinationDirectoryIdentity:OutputDirectoryIdentity.inspect(out).1,padesSourcePreflight:preflight,padesAppearance:appearance,providerContext:binding)
            try SignumPAdESHelper.sign(job:job,pin:"synthetic",appearanceName:"",field:nil,executable:helper)
            mark("native-sign-write-readback-verify-publish",snapshot.identity.byteCount)
            try require(!FileManager.default.fileExists(atPath:snapshot.fileURL.path))
        case "verify":
            var result: VerificationReport? = try SignumVerificationService.verify(file:input,helper:helper)
            try require(result!.integrity == .verified || result!.documentState == "unsigned")
            mark("open-native-parse-extract",result!.originalContent?.count ?? result!.previewPDF?.count ?? 0)
            if let pdf=result!.previewPDF { let page=try await PDFPreviewPreparation.page(pdf,index:0); mark("preview-with-annotations",page.png.count) }
            result=nil; mark("result-released")
        case "live-preview":
            _=NSApplication.shared
            let snapshot=try DocumentSnapshot.capture(source:input,format:.pades,privateRoot:out)
            final class State { var placement:PAdESPlacement?; var ready=false }
            let state=State()
            let pane=PAdESPlacementPane(snapshot:snapshot,previewReady:{ _,ready in state.ready=ready },holder:"Synthetic",
                placement:Binding(get:{state.placement},set:{state.placement=$0}))
            var host:NSHostingView<PAdESPlacementPane>?=NSHostingView(rootView:pane)
            let window=NSWindow(contentRect:CGRect(x:0,y:0,width:850,height:700),styleMask:[.titled,.resizable],backing:.buffered,defer:false)
            window.isReleasedWhenClosed=false; window.contentView=host; window.orderFront(nil)
            let deadline=ProcessInfo.processInfo.systemUptime+10
            while !state.ready && ProcessInfo.processInfo.systemUptime<deadline { host?.layoutSubtreeIfNeeded(); try await Task.sleep(nanoseconds:10_000_000) }
            try require(state.ready); window.displayIfNeeded()
            mark("active-viewer-default-overlay-ready",snapshot.identity.byteCount,facts:["role":"production-view-in-diagnostic-host"])
            window.close(); window.contentView=nil; host=nil; snapshot.close()
            try await Task.sleep(nanoseconds:20_000_000)
            try require(!FileManager.default.fileExists(atPath:snapshot.fileURL.path))
            mark("active-window-closed-private-file-removed",snapshot.identity.byteCount,facts:["role":"production-view-in-diagnostic-host"])
        case "batch", "batch-budget":
            let coordinator=BatchSigningCoordinator()
            let urls=mode == "batch-budget" ? (0..<32).map { input.appendingPathComponent("\($0).bin") } : [input,URL(fileURLWithPath:input.path+".second")]
            await coordinator.addDocuments(urls,format:.cades)
            try require(coordinator.documents.count == urls.count); mark("two-retained-snapshots",coordinator.documents.reduce(0){$0+$1.snapshot.identity.byteCount})
            let paths=coordinator.documents.map{ $0.snapshot.fileURL }
            let approval=try await coordinator.prepareReview(provider:fixture.appendingPathComponent("synthetic-provider.dylib").path,
                slot:7,certificate:certificate,der:cert,destination:.commonDirectory(out),providerContext:binding)
            mark("review-read-compare-hash",approval.jobs.reduce(0){$0+$1.snapshotIdentity.byteCount})
            coordinator.reset()
            let deadline=ProcessInfo.processInfo.systemUptime+5
            while paths.contains(where:{FileManager.default.fileExists(atPath:$0.path)}) && ProcessInfo.processInfo.systemUptime<deadline { try await Task.sleep(nanoseconds:1_000_000) }
            try require(paths.allSatisfy{!FileManager.default.fileExists(atPath:$0.path)})
            mark("retired-private-files-approval-still-owned")
            withExtendedLifetime(approval) {}
        default: fatalError("unknown profile")
        }
        mark("scope-cleanup")
    }
}
