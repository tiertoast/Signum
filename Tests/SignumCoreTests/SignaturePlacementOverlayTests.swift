#if os(macOS)
import XCTest
import AppKit
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class SignaturePlacementOverlayTests: XCTestCase {
    func window(_ view: NSView) -> NSWindow {
        let w = NSWindow(contentRect:CGRect(x:0,y:0,width:800,height:650),styleMask:[.titled,.resizable],backing:.buffered,defer:false)
        w.isReleasedWhenClosed = false; w.contentView = view; w.orderFront(nil); return w
    }
    func pixels(_ view: NSView) throws -> Int {
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in:view.bounds))
        view.cacheDisplay(in:view.bounds,to:bitmap)
        let cg = try XCTUnwrap(bitmap.cgImage)
        let ctx = try XCTUnwrap(CGContext(data:nil,width:cg.width,height:cg.height,bitsPerComponent:8,bytesPerRow:cg.width*4,
            space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        ctx.draw(cg,in:CGRect(x:0,y:0,width:cg.width,height:cg.height))
        let b = ctx.data!.assumingMemoryBound(to:UInt8.self)
        return (0..<cg.width*cg.height).reduce(0) { $0 + (b[$1*4]>200 && Int(b[$1*4])-Int(b[$1*4+1])>60 ? 1:0) }
    }
    func testNativeOverlayPixelsAndMappingAcrossPageGeometryAndZoom() throws {
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650))
        let w=window(view); defer {w.close()}
        for size in [CGSize(width:1684,height:2384),CGSize(width:2384,height:3370),CGSize(width:5000,height:4000),CGSize(width:1304,height:1843)] {
            for rotation in [0,90,180,270] {
                let media=CGRect(origin:CGPoint(x:20,y:-500),size:size),crop=media.insetBy(dx:10,dy:20)
                let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:rotation==270 ? 10:1,vectors:10000)))
                view.install(document:doc,pageIndex:0);view.layoutSubtreeIfNeeded()
                var art=try PAdESGeometryStabilizationTests().redArtwork(crop:crop)
                for zoom in [0.25,1.0,2.0] {
                    view.scaleFactor=zoom
                    let page=try XCTUnwrap(doc.page(at:0))
                    view.go(to:PDFDestination(page:page,at:CGPoint(x:crop.midX,y:crop.midY)))
                    var config=art.configuration
                    let center=view.convert(CGPoint(x:view.bounds.midX,y:view.bounds.midY),to:page)
                    config.rectangle.origin=CGPoint(x:center.x-120,y:center.y-50)
                    // A visible central placement on the exact current page.
                    art=try art.placed(config,cropBox:crop)
                    XCTAssertNil(view.updatePlacementOverlay(art))
                    view.signatureOverlay.artworkView.displayIfNeeded()
                    XCTAssertGreaterThan(try pixels(view.signatureOverlay.artworkView),20)
                    let overlay=view.signatureOverlay, actual=overlay.artworkView.frame
                    let expected=view.convert(config.rectangle,from:page)
                    let mapped=overlay.convert(actual,to:view)
                    XCTAssertEqual(mapped.midX,expected.midX,accuracy:0.01)
                    XCTAssertEqual(mapped.midY,expected.midY,accuracy:0.01)
                    XCTAssertEqual(mapped.width,expected.width,accuracy:0.01)
                    XCTAssertEqual(mapped.height,expected.height,accuracy:0.01)
                    XCTAssertNil(view.previewAnnotation)
                    // Transparent to hit testing, scroll stays with PDFKit.
                    XCTAssertNil(overlay.hitTest(CGPoint(x:20,y:20)))
                }
            }
        }
    }
    func testMovementReusesPaintedLayerAndScrollUpdatesGeometry() throws {
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),w=window(view);defer{w.close()}
        let media=CGRect(x:0,y:0,width:3370,height:2384)
        let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:media,rotation:90,vectors:10000)))
        view.install(document:doc,pageIndex:0);view.layoutSubtreeIfNeeded()
        let art=try PAdESGeometryStabilizationTests().redArtwork(crop:media)
        view.updatePlacementOverlay(art);let overlay=view.signatureOverlay
        overlay.artworkView.displayIfNeeded()
        let draws=overlay.artworkView.drawCount
        for i in 0..<200 {
            var c=art.configuration;c.rectangle.origin=CGPoint(x:100+i,y:200+i)
            view.updatePlacementOverlay(try art.placed(c,cropBox:media))
            overlay.artworkView.displayIfNeeded()
        }
        XCTAssertEqual(overlay.artworkBuildCount,1)
        XCTAssertEqual(overlay.artworkView.drawCount,draws,"Dragging must move cached layer contents, not redraw PDF/image")
        let before=overlay.geometryUpdateCount
        view.scaleFactor=2;view.layoutSubtreeIfNeeded()
        let clips=descendants(view).compactMap{$0 as? NSClipView}
        let clip=try XCTUnwrap(clips.first);clip.postsBoundsChangedNotifications=true
        clip.scroll(to:CGPoint(x:200,y:300));(clip.superview as? NSScrollView)?.reflectScrolledClipView(clip)
        NotificationCenter.default.post(name:NSView.boundsDidChangeNotification,object:clip)
        XCTAssertGreaterThan(overlay.geometryUpdateCount,before)
        overlay.artworkView.displayIfNeeded()
        XCTAssertGreaterThan(overlay.artworkView.drawCount,draws,"Zoom invalidates only the small artwork layer")
        view.updatePlacementOverlay(nil)
        XCTAssertNil(overlay.artworkView.document);XCTAssertTrue(overlay.isHidden)
    }
    func descendants(_ v:NSView)->[NSView] {[v]+v.subviews.flatMap{descendants($0)}}
    func testErrorsInvisibleAndDocumentReplacementCannotShowOldArtwork() throws {
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),w=window(view);defer{w.close()}
        let box=CGRect(x:0,y:0,width:595,height:842)
        let bytes=PAdESGeometryStabilizationTests.pdf(media:box)
        view.install(document:try XCTUnwrap(PDFDocument(data:bytes)),pageIndex:0);view.layoutSubtreeIfNeeded()
        var c=PAdESAppearanceConfiguration();c.showSigner=false
        let broken=RenderedPAdESAppearance(configuration:c,pdf:Data("broken".utf8),certificateSHA256:"synthetic")
        XCTAssertNotNil(view.updatePlacementOverlay(broken))
        XCTAssertFalse(view.signatureOverlay.artworkView.hasPainted)
        XCTAssertTrue(view.signatureOverlay.isHidden)
        c.visible=false
        let invisible=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:box)
        XCTAssertNil(view.updatePlacementOverlay(invisible));XCTAssertTrue(view.signatureOverlay.isHidden)
        view.updatePlacementOverlay(try PAdESGeometryStabilizationTests().redArtwork(crop:box))
        XCTAssertNotNil(view.signatureOverlay.artworkView.document)
        view.install(document:try XCTUnwrap(PDFDocument(data:bytes)),pageIndex:0)
        XCTAssertNil(view.signatureOverlay.artworkView.document)
        XCTAssertNil(view.signatureOverlay.approvedAppearance)
    }
}
#endif
