#if os(macOS)
import XCTest
import SwiftUI
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESOrientationWorkflowTests: XCTestCase {
    func folder() throws -> URL {
        let url=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:url,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);return url
    }
    func testMixedBatchFreezesIndividualOrientationAndSignsOnlyApprovedValues() async throws {
        let root=try folder();defer{try? FileManager.default.removeItem(at:root)}
        let helper=try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let worker=ProcessInfo.processInfo.environment["SIGNUM_TEST_BATCH_WORKER"].map(URL.init(fileURLWithPath:)) ??
            Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
        let box=CGRect(x:0,y:0,width:595,height:842)
        let files=[root.appendingPathComponent("A.pdf"),root.appendingPathComponent("B.pdf"),root.appendingPathComponent("C.txt")]
        try PAdESGeometryStabilizationTests.pdf(media:box,rotation:90).write(to:files[0])
        try PAdESGeometryStabilizationTests.pdf(media:box,rotation:0).write(to:files[1])
        try Data("Synthetic CAdES".utf8).write(to:files[2])
        let batch=BatchSigningCoordinator();defer{batch.reset()}
        await batch.addDocuments(Array(files.prefix(2)),format:.pades);await batch.addDocuments([files[2]],format:.cades)
        XCTAssertEqual(batch.documents.count,3)
        let der=signer.der,certificate=SignumCertificate(label:"Synthetic",identifier:Data([1]))
        var appearances:[UUID:RenderedPAdESAppearance]=[:]
        for (i,q) in [PAdESAppearanceOrientation.automatic,.degrees90].enumerated() {
            let c=try PAdESOrientationTests.config(crop:box,rotation:i==0 ? 90:0,orientation:q)
            appearances[batch.documents[i].id]=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:box,pageRotation:i==0 ? 90:0)
        }
        let old=try await batch.prepareReview(provider:mock.path.path,slot:7,certificate:certificate,der:der,destination:.originalFolders,appearances:appearances)
        let a=try XCTUnwrap(appearances[batch.documents[0].id])
        let c=try a.configuration.reoriented(to:.degrees0,fromPageRotation:90,toPageRotation:90,cropBox:box)
        let changed=try a.reoriented(c,cropBox:box,pageRotation:90)
        XCTAssertEqual(changed.pdf,a.pdf,"Automatic→0 keeps pixels but still revokes consent")
        XCTAssertNotEqual(changed.approvalIdentity,a.approvalIdentity)
        batch.invalidateReview()
        XCTAssertThrowsError(try batch.freezeReview(old))
        appearances[batch.documents[0].id]=changed
        let plan=try await batch.prepareReview(provider:mock.path.path,slot:7,certificate:certificate,der:der,destination:.originalFolders,appearances:appearances)
        try batch.freezeReview(plan);try batch.confirm(plan)
        appearances.removeAll()
        XCTAssertEqual(plan.jobs.map{$0.padesAppearance?.configuration.orientation},[.degrees0,.degrees90,nil])
        for _ in 0..<3 {
            try await batch.authorizeNext(pin:"synthetic-fixture") {job,pin,operation in
                if job.format == .pades {try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:operation,executable:URL(fileURLWithPath:helper))}
                else {try job.signCAdES(using:IsolatedPKCS11Client(executable:worker),pin:pin,operation:operation)}
            }
        }
        XCTAssertTrue(batch.documents.allSatisfy{$0.state == .completed})
        for job in plan.jobs {
            let report=try SignumVerificationService.verify(data:Data(contentsOf:job.destination),name:job.destination.lastPathComponent,helper:URL(fileURLWithPath:helper))
            XCTAssertEqual(report.integrity,.verified)
        }
    }
    func testSnapshotPageRotationMismatchRejectedBeforeSigning() throws {
        let root=try folder();defer{try? FileManager.default.removeItem(at:root)}
        let box=CGRect(x:0,y:0,width:595,height:842),file=root.appendingPathComponent("synthetic.pdf")
        try PAdESGeometryStabilizationTests.pdf(media:box,rotation:90).write(to:file)
        let snapshot=try DocumentSnapshot.capture(source:file,format:.pades);defer{snapshot.close()}
        let der=try CertificateEligibilityTests.fixtures.get().der("valid")
        let c=try PAdESOrientationTests.config(crop:box,rotation:0,orientation:.automatic)
        let art=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:box,pageRotation:0)
        XCTAssertThrowsError(try SigningJob(snapshot:snapshot,providerPath:"/synthetic/provider",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),
            certificateDER:der,destination:root.appendingPathComponent("signed.pdf"),padesAppearance:art))
        XCTAssertFalse(FileManager.default.fileExists(atPath:root.appendingPathComponent("signed.pdf").path))
        let correct=try c.reoriented(to:.automatic,fromPageRotation:0,toPageRotation:90,cropBox:box)
        let approved=try PAdESAppearanceRenderer.render(correct,certificateDER:der,cropBox:box,pageRotation:90)
        let job=try SigningJob(snapshot:snapshot,providerPath:"/synthetic/provider",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),
            certificateDER:der,destination:root.appendingPathComponent("signed.pdf"),padesAppearance:approved)
        XCTAssertEqual(job.padesAppearance?.resolvedOrientation?.artworkCounterclockwiseDegrees,90)
        let manual=try correct.reoriented(to:.degrees0,fromPageRotation:90,toPageRotation:90,cropBox:box)
        let changed=try approved.reoriented(manual,cropBox:box,pageRotation:90)
        XCTAssertEqual(changed.pdf,approved.pdf)
        XCTAssertThrowsError(try SignumPAdESHelper.sign(job:job,pin:"synthetic-fixture",appearanceName:"unused",field:nil,appearance:changed))
        XCTAssertFalse(FileManager.default.fileExists(atPath:job.destination.path))
    }
    func testOrientationChangesDuringRenderingPublishOnlyLatestAndClosureCancels() async throws {
        let first=expectation(description:"first"),latest=expectation(description:"latest"),release=DispatchSemaphore(value:0)
        let worker=PAdESRenderCoordinator(renderer:{c,der,crop,cancelled in
            if c.orientation == .automatic {first.fulfill();_ = release.wait(timeout:.now()+5)}
            return try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop,isCancelled:cancelled)
        })
        let crop=CGRect(x:0,y:0,width:595,height:842)
        var c=try PAdESOrientationTests.config(crop:crop,rotation:0,orientation:.automatic)
        worker.submit(c,der:Data(),crop:crop){_ in XCTFail("Stale automatic orientation")}
        await fulfillment(of:[first],timeout:5)
        for q in [PAdESAppearanceOrientation.degrees90,.degrees180,.degrees270] {
            c=try c.reoriented(to:q,fromPageRotation:0,toPageRotation:0,cropBox:crop)
            worker.submit(c,der:Data(),crop:crop){result in
                XCTAssertEqual(try? result.get().configuration.orientation,.degrees270);latest.fulfill()
            }
        }
        release.signal();await fulfillment(of:[latest],timeout:5)
        XCTAssertEqual(worker.started,2);XCTAssertEqual(worker.discarded,1)
        worker.submit(c,der:Data(),crop:crop){_ in XCTFail("Closed preview")}
        worker.cancel()
        for _ in 0..<100 {if worker.isIdle {break};try await Task.sleep(nanoseconds:10_000_000)}
        XCTAssertTrue(worker.isIdle)
    }
    final class State {
        var placement:PAdESPlacement?
        var readiness:[Bool]=[]
    }
    func testNativePaneRestoresIndividualOrientationAndRevokesOldPaneCallbacks() async throws {
        let root=try folder();defer{try? FileManager.default.removeItem(at:root)}
        let box=CGRect(x:0,y:0,width:1304,height:1843),file=root.appendingPathComponent("synthetic.pdf")
        try PAdESGeometryStabilizationTests.pdf(media:box,rotation:90).write(to:file)
        let snapshot=try DocumentSnapshot.capture(source:file,format:.pades);defer{snapshot.close()}
        let c=try PAdESOrientationTests.config(crop:box,rotation:90,orientation:.automatic)
        let a=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:box,pageRotation:90)
        let state=State();state.placement = .init(pageIndex:0,rectangle:c.rectangle,appearance:a)
        @MainActor func makePane()->PAdESPlacementPane {
            PAdESPlacementPane(snapshot:snapshot,previewReady:{_,ready in state.readiness.append(ready)},holder:"Synthetic",
                placement:Binding(get:{state.placement},set:{state.placement=$0}))
        }
        let host=NSHostingView(rootView:AnyView(makePane().id(UUID()))),window=SignaturePlacementOverlayTests().window(host);defer{window.close()}
        for _ in 0..<100 {host.layoutSubtreeIfNeeded();if state.readiness.last == true {break};try await Task.sleep(nanoseconds:10_000_000)}
        XCTAssertEqual(state.readiness.last,true)
        let center=try XCTUnwrap(state.placement?.rectangle)
        let next=try a.configuration.reoriented(to:.degrees90,fromPageRotation:90,toPageRotation:90,cropBox:box)
        let rotated=try a.reoriented(next,cropBox:box,pageRotation:90)
        state.placement = .init(pageIndex:0,rectangle:next.rectangle,appearance:rotated)
        state.readiness=[]
        // Force a real teardown/remount: the new pane must restore the stored
        // per-document value, while callbacks from the old pane are retired.
        host.rootView=AnyView(makePane().id(UUID()))
        for _ in 0..<100 {host.layoutSubtreeIfNeeded();if state.placement?.appearance?.configuration.orientation == .degrees90 && state.readiness.last == true {break};try await Task.sleep(nanoseconds:10_000_000)}
        let changed=try XCTUnwrap(state.placement?.appearance)
        XCTAssertEqual(changed.configuration.orientation,.degrees90);XCTAssertEqual(changed.pageRotation,90)
        XCTAssertEqual(changed.configuration.rectangle.midX,center.midX);XCTAssertEqual(changed.configuration.rectangle.midY,center.midY)
        XCTAssertEqual(changed.configuration.rectangle.width,240);XCTAssertEqual(changed.configuration.rectangle.height,100)
        XCTAssertEqual(state.readiness.first,false);XCTAssertEqual(state.readiness.last,true)
        XCTAssertEqual(state.placement?.appearance?.configuration.orientation,.degrees90)
    }
}
#endif
