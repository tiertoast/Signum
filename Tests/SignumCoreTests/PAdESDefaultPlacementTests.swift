#if os(macOS)
import XCTest
import PDFKit
import SwiftUI
@testable import SignumCore
@testable import SignumApp
@testable import SignumPlacementReference

@MainActor final class PAdESDefaultPlacementTests: XCTestCase {
    func document(_ media:CGRect,_ crop:CGRect?=nil,_ rotation:Int=0,_ unit:Int=1,_ vectors:Int=0) throws -> CGPDFDocument {
        try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:unit,vectors:vectors) as CFData))))
    }
    func testPhysicalDefaultMatchesIndependentCGPDFTransformForEveryPaperRotationUnitAndOrientation() throws {
        for size in [CGSize(width:595,height:842),CGSize(width:842,height:1191),CGSize(width:1684,height:2384),CGSize(width:2384,height:3370),CGSize(width:10000,height:7200)] {
            for rotation in [0,90,180,270] {for unit in [1,2,10] {
                let media=CGRect(x:20,y:-50,width:size.width/CGFloat(unit),height:size.height/CGFloat(unit)),crop=media.insetBy(dx:2,dy:3)
                let doc=try document(media,crop,rotation,unit),page=try XCTUnwrap(doc.page(at:1)),g=try PAdESPageGeometry(page:page)
                for orientation in PAdESAppearanceOrientation.allCases {
                    let c=try g.defaultAppearance(orientation:orientation)
                    let visual=rotation%180==90 ? CGSize(width:crop.height,height:crop.width):crop.size
                    let transform=page.getDrawingTransform(.cropBox,rect:CGRect(origin:.zero,size:visual),rotate:0,preserveAspectRatio:false)
                    let r=c.rectangle.applying(transform)
                    XCTAssertEqual((visual.width-r.maxX)*CGFloat(unit),10*72/25.4,accuracy:0.00001)
                    XCTAssertEqual((visual.height-r.maxY)*CGFloat(unit),10*72/25.4,accuracy:0.00001)
                    let raw=try c.contentSize(pageRotation:rotation)
                    XCTAssertEqual(raw.width*CGFloat(unit),240,accuracy:0.00001)
                    XCTAssertEqual(raw.height*CGFloat(unit),90,accuracy:0.00001)
                    XCTAssertTrue(c.visible);XCTAssertEqual(c.orientation,orientation);XCTAssertTrue(crop.contains(c.rectangle))
                }
            }}
        }
    }
    func testEffectiveIntersectionAndSmallPageMarginFallbackNeverScaleOrClip() throws {
        let g=try PAdESPageGeometry(mediaBox:CGRect(x:40,y:-20,width:250,height:100),cropBox:CGRect(x:0,y:-100,width:1000,height:1000),rotation:0)
        let c=try g.defaultAppearance(),r=c.rectangle
        XCTAssertEqual(r.width,240);XCTAssertEqual(r.height,90)
        XCTAssertEqual(g.cropBox.maxX-r.maxX,10);XCTAssertEqual(g.cropBox.maxY-r.maxY,10)
        let exact=try PAdESPageGeometry(mediaBox:CGRect(x:0,y:0,width:240,height:90),cropBox:CGRect(x:0,y:0,width:240,height:90),rotation:0)
        XCTAssertEqual(try exact.defaultAppearance().rectangle,exact.cropBox)
        for box in [CGRect(x:0,y:0,width:239,height:90),CGRect(x:0,y:0,width:240,height:89)] {
            XCTAssertThrowsError(try PAdESPageGeometry(mediaBox:box,cropBox:box,rotation:0).defaultAppearance())
        }
        for unit in [CGFloat(0),-1,.infinity,75001] {
            XCTAssertThrowsError(try PAdESPageGeometry(mediaBox:g.cropBox,cropBox:g.cropBox,rotation:0,userUnit:unit))
        }
        XCTAssertThrowsError(try PAdESPageGeometry(mediaBox:g.cropBox,cropBox:g.cropBox,rotation:45))
    }
    func coloredBounds(_ image:CGImage) throws -> CGRect {
        let c=try XCTUnwrap(CGContext(data:nil,width:image.width,height:image.height,bitsPerComponent:8,bytesPerRow:image.width*4,
            space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        c.draw(image,in:CGRect(x:0,y:0,width:image.width,height:image.height))
        let b=c.data!.assumingMemoryBound(to:UInt8.self)
        var xs:[Int]=[],ys:[Int]=[]
        for y in 0..<image.height {for x in 0..<image.width {
            let i=(y*image.width+x)*4,v=[Int(b[i]),Int(b[i+1]),Int(b[i+2])]
            if v.max()!>180 && v.max()!-v.min()!>120 {xs.append(x);ys.append(y)}
        }}
        XCTAssertFalse(xs.isEmpty)
        return CGRect(x:xs.min() ?? 0,y:ys.min() ?? 0,width:(xs.max() ?? 0)-(xs.min() ?? 0)+1,height:(ys.max() ?? 0)-(ys.min() ?? 0)+1)
    }
    func testInitialPlacementPixelsAppearTopRightAcrossRotationsAndUserUnit() throws {
        for rotation in [0,90,180,270] {for unit in [1,2,10] {
            let media=CGRect(x:20,y:-30,width:595/CGFloat(unit),height:842/CGFloat(unit)),crop=media.insetBy(dx:1,dy:1)
            let bytes=PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:unit,vectors:10000)
            let raw=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:bytes as CFData))))
            let doc=try XCTUnwrap(PDFDocument(data:bytes)),page=try XCTUnwrap(doc.page(at:0)),ref=try XCTUnwrap(raw.page(at:1))
            let g=try PAdESPageGeometry(page:ref)
            var c=try g.defaultAppearance();c.showSigner=false;c.showLabel=false;c.image=try PAdESOrientationTests.marker()
            let art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:rotation)
            page.addAnnotation(try XCTUnwrap(ReferenceAppearancePDFAnnotation(appearance:art)))
            let image=try XCTUnwrap(page.thumbnail(of:CGSize(width:1000,height:1000),for:.cropBox).cgImage(forProposedRect:nil,context:nil,hints:nil))
            let actual=try coloredBounds(image)
            // Independent target from physical paper size and the requirement,
            // not the production raw→visible mapping or CGPDF's no-upscale fit.
            let physicalWidth=(rotation%180==90 ? crop.height:crop.width)*CGFloat(unit)
            let physicalHeight=(rotation%180==90 ? crop.width:crop.height)*CGFloat(unit)
            let expectedX=CGFloat(image.width)*(1-(10*72/25.4+120)/physicalWidth)
            let expectedY=CGFloat(image.height)*(10*72/25.4+45)/physicalHeight
            XCTAssertEqual(actual.midX,expectedX,accuracy:2,"rotation=\(rotation),unit=\(unit)")
            XCTAssertEqual(actual.midY,expectedY,accuracy:2)
            XCTAssertGreaterThan(actual.midX,CGFloat(image.width)/2);XCTAssertLessThan(actual.midY,CGFloat(image.height)/2)
            withExtendedLifetime(doc) {};withExtendedLifetime(raw) {}
        }}
    }
    func testPhysicalArtworkRenderingAndResizeBoundsAcrossUnits() throws {
        let crop=CGRect(x:0,y:0,width:595,height:842)
        var reference:Data?
        for unit in [CGFloat(1),2,10] {
            let g=try PAdESPageGeometry(mediaBox:crop,cropBox:crop,rotation:90,userUnit:unit)
            var c=try g.defaultAppearance();c.showSigner=false;c.customText="Synthetic physical text"
            let art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:90)
            let doc=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:art.pdf as CFData))))
            XCTAssertEqual(try XCTUnwrap(doc.page(at:1)).getBoxRect(.mediaBox).width,90/unit,accuracy:0.001)
            let context=try XCTUnwrap(CGContext(data:nil,width:180,height:480,bitsPerComponent:8,bytesPerRow:720,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
            context.scaleBy(x:2*unit,y:2*unit);context.drawPDFPage(try XCTUnwrap(doc.page(at:1)))
            let pixels=Data(bytes:context.data!,count:720*480)
            if let reference {XCTAssertEqual(pixels,reference,"Physical typography must be identical")};reference=pixels
            let resized=try c.resized(toward:CGPoint(x:c.rectangle.minX+1,y:c.rectangle.minY+1),pageRotation:90,cropBox:crop)
            let size=try resized.contentSize(pageRotation:90)
            XCTAssertEqual(size.width*unit,80,accuracy:0.001);XCTAssertEqual(size.height*unit,40,accuracy:0.001)
        }
    }
    final class State {var placement:PAdESPlacement?;var readiness:[Bool]=[]}
    func awaitPreview(_ host:NSView,_ ready:@escaping @MainActor ()->Bool) async throws {
        for _ in 0..<300 {host.layoutSubtreeIfNeeded();if ready(){return};try await Task.sleep(nanoseconds:10_000_000)}
        XCTFail("Native preview did not reach expected state")
    }
    func testNativeInitialPaneWithoutCertificatePaintsWithoutClickAndPreservesZoomDragAndDraft() async throws {
        let root=try PAdESOrientationWorkflowTests().folder();defer{try? FileManager.default.removeItem(at:root)}
        let media=CGRect(x:20,y:-40,width:1304,height:1843),file=root.appendingPathComponent("synthetic.pdf")
        try PAdESGeometryStabilizationTests.pdf(media:media,rotation:90,vectors:10000).write(to:file)
        let snapshot=try DocumentSnapshot.capture(source:file,format:.pades);defer{snapshot.close()}
        let state=State()
        func pane()->PAdESPlacementPane {
            PAdESPlacementPane(snapshot:snapshot,previewReady:{_,r in state.readiness.append(r)},holder:"",placement:Binding(get:{state.placement},set:{state.placement=$0}))
        }
        let host=NSHostingView(rootView:AnyView(pane().id(UUID()))),window=SignaturePlacementOverlayTests().window(host);defer{window.close()}
        try await awaitPreview(host,{state.readiness.last == true})
        let view=try XCTUnwrap(PAdESGeometryStabilizationTests().descendants(host).compactMap{$0 as? PlacementPDFView}.first)
        let initial=try XCTUnwrap(state.placement?.appearance)
        XCTAssertTrue(initial.configuration.visible);XCTAssertEqual(initial.configuration.orientation,.automatic)
        XCTAssertTrue(view.signatureOverlay.artworkView.hasPainted);XCTAssertGreaterThan(view.signatureOverlay.artworkView.cachedPixelBytes,0)
        XCTAssertFalse(initial.configuration.showSigner);XCTAssertTrue(state.placement?.draft?.showSigner == true)
        let artView=view.signatureOverlay.artworkView
        let bitmap=try XCTUnwrap(artView.bitmapImageRepForCachingDisplay(in:artView.bounds))
        artView.cacheDisplay(in:artView.bounds,to:bitmap)
        var visibleInk=0
        for y in 0..<bitmap.pixelsHigh {for x in 0..<bitmap.pixelsWide {
            if let color=bitmap.colorAt(x:x,y:y)?.usingColorSpace(.deviceRGB),color.alphaComponent>0.5,
               max(color.redComponent,color.greenComponent,color.blueComponent)<0.7 {visibleInk+=1}
        }}
        XCTAssertGreaterThan(visibleInk,20,"Prepared default text/border must actually produce visible pixels")
        let capture=try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in:host.bounds))
        host.cacheDisplay(in:host.bounds,to:capture)
        let evidence = try FixtureFiles.directory("default-placement",evidence:true).appendingPathComponent("native-default.png")
        try XCTUnwrap(capture.representation(using:.png,properties:[:])).write(to:evidence)

        XCTAssertEqual(state.readiness.first,false)
        let page=try XCTUnwrap(view.currentPage)
        let pageBox=page.bounds(for:.cropBox),rotated=initial.configuration.rectangle.applying(try PAdESPageGeometry(page:try XCTUnwrap(page.pageRef)).rawToVisible)
        XCTAssertEqual(rotated.maxX,pageBox.height-10*72/25.4,accuracy:0.001)
        for zoom in [0.25,1,2] {
            view.scaleFactor=zoom;view.layoutSubtreeIfNeeded()
            XCTAssertEqual(state.placement?.rectangle,initial.configuration.rectangle)
        }
        view.onChoose?(page,CGPoint(x:media.midX,y:media.midY))
        try await awaitPreview(host,{state.placement?.appearance != nil && state.placement?.rectangle != initial.configuration.rectangle})
        let moved=try XCTUnwrap(state.placement?.draft)
        // Close with a draft whose artwork has not completed: preserve geometry,
        // orientation and size independently from successful AP publication.
        var draft=try moved.reoriented(to:.degrees270,fromPageRotation:90,toPageRotation:90,cropBox:media)
        draft=try draft.resized(contentSize:CGSize(width:260,height:110),pageRotation:90,cropBox:media)
        state.placement = .init(pageIndex:0,rectangle:draft.rectangle,draft:draft)
        state.readiness=[];host.rootView=AnyView(pane().id(UUID()))
        try await awaitPreview(host,{state.placement?.appearance?.configuration.orientation == .degrees270 && state.readiness.last == true})
        XCTAssertEqual(state.placement?.draft,draft);XCTAssertEqual(state.placement?.rectangle,draft.rectangle)
    }
    func testNativeSmallPageAndRendererErrorNeverApprove() async throws {
        let root=try PAdESOrientationWorkflowTests().folder();defer{try? FileManager.default.removeItem(at:root)}
        for small in [true,false] {
            let file=root.appendingPathComponent("synthetic-\(small).pdf"),state=State()
            try PAdESGeometryStabilizationTests.pdf(media:CGRect(x:0,y:0,width:small ? 100:595,height:small ? 80:842)).write(to:file)
            let snap=try DocumentSnapshot.capture(source:file,format:.pades);defer{snap.close()}
            let worker=PAdESRenderCoordinator(renderer:{_,_,_,_ in throw SignumError.module("Synthetic renderer failure")})
            let pane=PAdESPlacementPane(snapshot:snap,previewReady:{_,r in state.readiness.append(r)},holder:"",placement:Binding(get:{state.placement},set:{state.placement=$0}),renderCoordinator:worker)
            let host=NSHostingView(rootView:pane),window=SignaturePlacementOverlayTests().window(host);defer{window.close()}
            try await awaitPreview(host,{!state.readiness.isEmpty && worker.isIdle})
            XCTAssertFalse(state.readiness.contains(true));XCTAssertNil(state.placement?.appearance)
        }
    }
    func testJobRejectsSnapshotUserUnitMismatchAndSupportsInvisibleLegacyAPI() throws {
        let root=try PAdESOrientationWorkflowTests().folder();defer{try? FileManager.default.removeItem(at:root)}
        let box=CGRect(x:0,y:0,width:595,height:842),file=root.appendingPathComponent("synthetic.pdf")
        try PAdESGeometryStabilizationTests.pdf(media:box,rotation:90,unit:2).write(to:file)
        let snapshot=try DocumentSnapshot.capture(source:file,format:.pades);defer{snapshot.close()}
        let der=try CertificateEligibilityTests.fixtures.get().der("valid")
        var c=try PAdESPageGeometry(mediaBox:box,cropBox:box,rotation:90).defaultAppearance()
        var art=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:box,pageRotation:90)
        func job(_ a:RenderedPAdESAppearance) throws -> SigningJob {
            try SigningJob(snapshot:snapshot,providerPath:"/synthetic/provider",slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:der,destination:root.appendingPathComponent("signed.pdf"),padesAppearance:a)
        }
        XCTAssertThrowsError(try job(art))
        c=try PAdESPageGeometry(mediaBox:box,cropBox:box,rotation:90,userUnit:2).defaultAppearance()
        art=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:box,pageRotation:90)
        XCTAssertNoThrow(try job(art))
        c.visible=false;c.userUnit=nil
        let invisible=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:box)
        XCTAssertTrue(invisible.pdf.isEmpty);XCTAssertNoThrow(try job(invisible))
        var legacy=PAdESAppearanceConfiguration();legacy.showSigner=false
        let old=try PAdESAppearanceRenderer.render(legacy,certificateDER:der,cropBox:box,pageRotation:0)
        legacy.userUnit=1
        let explicit=try PAdESAppearanceRenderer.render(legacy,certificateDER:der,cropBox:box,pageRotation:0)
        XCTAssertNotEqual(old.approvalIdentity,explicit.approvalIdentity,"Legacy and snapshot-bound unit metadata are distinct consent inputs")
    }
}
#endif
