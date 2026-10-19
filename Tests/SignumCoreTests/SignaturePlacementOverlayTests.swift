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
    func testMixedPagesResizeAndViewportCostWithLargeImages() throws {
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),w=window(view);defer{w.close()}
        let a=CGRect(x:0,y:0,width:3370,height:2384),b=CGRect(x:30,y:40,width:842,height:1191)
        let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:a,vectors:10000)))
        let second=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:b,rotation:270)))
        doc.insert(try XCTUnwrap(second.page(at:0)),at:1)
        for pixels in [0,1024,2800] {
            view.install(document:doc,pageIndex:0);view.layoutSubtreeIfNeeded()
            var c=PAdESAppearanceConfiguration();c.showSigner=false
            if pixels>0 {c.image=try PAdESAppearanceImage(data:PAdESPlacementPerformanceTests.png(pixels))}
            let begin=ProcessInfo.processInfo.systemUptime
            let art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:a)
            let renderedMS=(ProcessInfo.processInfo.systemUptime-begin)*1000
            let start=ProcessInfo.processInfo.systemUptime
            view.updatePlacementOverlay(art);view.signatureOverlay.artworkView.displayIfNeeded()
            let firstMS=(ProcessInfo.processInfo.systemUptime-start)*1000
            let overlay=view.signatureOverlay,draws=overlay.artworkView.drawCount
            var times:[Double]=[]
            for n in 0..<120 {
                c.rectangle.origin=CGPoint(x:100+n,y:200)
                let tick=ProcessInfo.processInfo.systemUptime
                view.updatePlacementOverlay(try art.placed(c,cropBox:a));overlay.artworkView.displayIfNeeded()
                times.append((ProcessInfo.processInfo.systemUptime-tick)*1000)
            }
            XCTAssertEqual(overlay.artworkView.drawCount,draws)
            let resizeStart=ProcessInfo.processInfo.systemUptime
            c.rectangle.size.width+=30
            let resized=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:a)
            view.updatePlacementOverlay(resized);overlay.artworkView.displayIfNeeded()
            let resizeMS=(ProcessInfo.processInfo.systemUptime-resizeStart)*1000
            XCTAssertGreaterThan(overlay.artworkView.drawCount,draws)
            let zoomStart=ProcessInfo.processInfo.systemUptime
            view.scaleFactor=2;overlay.updateGeometry();overlay.artworkView.displayIfNeeded()
            let zoomMS=(ProcessInfo.processInfo.systemUptime-zoomStart)*1000
            times.sort()
            print("B11 overlay pixels=\(pixels) artwork_ms=\(renderedMS) first_ms=\(firstMS) moves=120 median_ms=\(times[60]) p95_ms=\(times[114]) resize_ms=\(resizeMS) zoom_ms=\(zoomMS) drag_rasterizations=0")
            view.install(document:doc,pageIndex:1);view.layoutSubtreeIfNeeded()
            XCTAssertTrue(overlay.isHidden,"Old page artwork cannot remain visible")
            c.pageIndex=1;c.rectangle=CGRect(x:80,y:100,width:240,height:100)
            let other=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:b)
            view.updatePlacementOverlay(other);overlay.artworkView.displayIfNeeded()
            XCTAssertFalse(overlay.isHidden);XCTAssertEqual(overlay.approvedAppearance?.configuration.pageIndex,1)
        }
        withExtendedLifetime(second) {}
    }

    func testNativePointerGesturesAndManyImageSource() throws {
        let box=CGRect(x:0,y:0,width:2384,height:3370)
        let bytes=NSMutableData();var media=box
        let context=try XCTUnwrap(CGContext(consumer:try XCTUnwrap(CGDataConsumer(data:bytes)),mediaBox:&media,nil))
        context.beginPDFPage(nil)
        for i in 0..<40 {
            let bitmap=try XCTUnwrap(CGContext(data:nil,width:64,height:64,bitsPerComponent:8,bytesPerRow:256,
                space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
            bitmap.setFillColor(CGColor(red:CGFloat(i)/40,green:0.3,blue:0.6,alpha:1))
            bitmap.fill(CGRect(x:0,y:0,width:64,height:64))
            context.draw(try XCTUnwrap(bitmap.makeImage()),in:CGRect(x:(i%5)*400,y:(i/5)*400,width:300,height:300))
        }
        context.endPDFPage();context.closePDF()
        let doc=try XCTUnwrap(PDFDocument(data:bytes as Data));doc.page(at:0)?.rotation=90
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),w=window(view);defer{w.close()}
        view.install(document:doc,pageIndex:0);view.layoutSubtreeIfNeeded()
        let art=try PAdESGeometryStabilizationTests().redArtwork(crop:box)
        view.updatePlacementOverlay(art);view.signatureOverlay.artworkView.displayIfNeeded()
        XCTAssertGreaterThan(try pixels(view.signatureOverlay.artworkView),0)
        let page=try XCTUnwrap(doc.page(at:0)), raw=CGPoint(x:500,y:700)
        let location=view.convert(view.convert(raw,from:page),to:nil)
        var chosen:[CGPoint]=[],resized:[CGPoint]=[],interactions:[Bool]=[]
        view.onChoose={ _,p in chosen.append(p) };view.onResize={_,p in resized.append(p)}
        view.onInteraction={interactions.append($0)}
        @MainActor func event(_ type:NSEvent.EventType,_ flags:NSEvent.ModifierFlags=[])->NSEvent {
            NSEvent.mouseEvent(with:type,location:location,modifierFlags:flags,timestamp:0,windowNumber:w.windowNumber,
                context:nil,eventNumber:1,clickCount:1,pressure:1)!
        }
        view.mouseDown(with:event(.leftMouseDown));view.mouseDragged(with:event(.leftMouseDragged));view.mouseUp(with:event(.leftMouseUp))
        view.mouseDown(with:event(.leftMouseDown,.option));view.mouseDragged(with:event(.leftMouseDragged,.option));view.mouseUp(with:event(.leftMouseUp,.option))
        XCTAssertEqual(chosen.count,3);XCTAssertEqual(resized.count,3);XCTAssertEqual(interactions,[true,false,true,false])
        for p in chosen+resized {XCTAssertEqual(p.x,raw.x,accuracy:0.01);XCTAssertEqual(p.y,raw.y,accuracy:0.01)}
    }

}
#endif
