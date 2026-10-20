#if os(macOS)
import XCTest
import PDFKit
import ImageIO
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESOrientationTests: XCTestCase {
    static func marker() throws -> PAdESAppearanceImage {
        let c=try XCTUnwrap(CGContext(data:nil,width:160,height:80,bitsPerComponent:8,bytesPerRow:640,
            space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        for (color,rect) in [(CGColor(red:1,green:0,blue:0,alpha:1),CGRect(x:0,y:40,width:80,height:40)),
                             (CGColor(red:0,green:1,blue:0,alpha:1),CGRect(x:80,y:40,width:80,height:40)),
                             (CGColor(red:0,green:0,blue:1,alpha:1),CGRect(x:0,y:0,width:80,height:40)),
                             (CGColor(red:1,green:1,blue:0,alpha:1),CGRect(x:80,y:0,width:80,height:40))] {
            c.setFillColor(color);c.fill(rect)
        }
        let bytes=NSMutableData(),sink=try XCTUnwrap(CGImageDestinationCreateWithData(bytes,"public.png" as CFString,1,nil))
        CGImageDestinationAddImage(sink,try XCTUnwrap(c.makeImage()),nil);XCTAssertTrue(CGImageDestinationFinalize(sink))
        return try PAdESAppearanceImage(data:bytes as Data)
    }
    static func config(crop:CGRect,rotation:Int,orientation:PAdESAppearanceOrientation) throws -> PAdESAppearanceConfiguration {
        var c=PAdESAppearanceConfiguration();c.showSigner=false;c.showLabel=false
        c.customText="READ 123 ->";c.image=try marker()
        c.rectangle=CGRect(x:crop.midX-120,y:crop.midY-50,width:240,height:100)
        return try c.reoriented(to:orientation,fromPageRotation:0,toPageRotation:rotation,cropBox:crop)
    }
    func testPureResolverAndExactQuarterTurns() throws {
        for page in [0,90,180,270,-90,450] {
            for orientation in PAdESAppearanceOrientation.allCases {
                let r=try orientation.resolve(pageRotation:page)
                XCTAssertEqual((r.artworkCounterclockwiseDegrees+r.viewerClockwiseDegrees)%360,r.pageRotation)
                let size=CGSize(width:240,height:100), footprint=r.footprintSize(forContent:size)
                let corners=[CGPoint.zero,CGPoint(x:240,y:0),CGPoint(x:0,y:100),CGPoint(x:240,y:100)].map{$0.applying(r.transform(contentSize:size))}
                XCTAssertEqual(corners.map(\.x).min(),0);XCTAssertEqual(corners.map(\.y).min(),0)
                XCTAssertEqual(corners.map(\.x).max(),footprint.width);XCTAssertEqual(corners.map(\.y).max(),footprint.height)
            }
        }
        XCTAssertThrowsError(try PAdESAppearanceOrientation.automatic.resolve(pageRotation:45))
        XCTAssertEqual(try PAdESAppearanceOrientation.automatic.resolve(pageRotation:90).artworkCounterclockwiseDegrees,90)
        XCTAssertEqual(try PAdESAppearanceOrientation.degrees90.resolve(pageRotation:0).artworkCounterclockwiseDegrees,270)
    }
    func testGeometryPreservesCenterContentAndClampsWithoutStretching() throws {
        let crop=CGRect(x:30,y:-400,width:595,height:842)
        var c=try Self.config(crop:crop,rotation:90,orientation:.automatic)
        for q in PAdESAppearanceOrientation.allCases {
            let next=try c.reoriented(to:q,fromPageRotation:90,toPageRotation:90,cropBox:crop)
            XCTAssertEqual(next.rectangle.midX,c.rectangle.midX);XCTAssertEqual(next.rectangle.midY,c.rectangle.midY)
            XCTAssertEqual(try next.contentSize(pageRotation:90),try c.contentSize(pageRotation:90))
            c=next
        }
        c.rectangle.origin=CGPoint(x:crop.minX,y:crop.minY)
        let changed=try c.reoriented(to:.degrees0,fromPageRotation:0,toPageRotation:90,cropBox:crop)
        XCTAssertTrue(crop.contains(changed.rectangle))
        XCTAssertEqual(try changed.contentSize(pageRotation:90),try c.contentSize(pageRotation:0))
        XCTAssertThrowsError(try c.reoriented(to:.automatic,fromPageRotation:0,toPageRotation:90,cropBox:CGRect(x:0,y:0,width:80,height:80)))
        let sized=try changed.resized(toward:CGPoint(x:changed.rectangle.minX+120,y:changed.rectangle.minY+300),pageRotation:90,cropBox:crop)
        XCTAssertEqual(try sized.contentSize(pageRotation:90),CGSize(width:300,height:120))
    }
    func testOrientationReusesImmutableUprightArtworkAndChangesConsent() throws {
        let crop=CGRect(x:0,y:0,width:2384,height:3370)
        let c=try Self.config(crop:crop,rotation:90,orientation:.automatic)
        var art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:90)
        let content=art.contentArtworkID
        for orientation in PAdESAppearanceOrientation.allCases {
            let next=try art.configuration.reoriented(to:orientation,fromPageRotation:90,toPageRotation:90,cropBox:crop)
            let previous=art
            art=try art.reoriented(next,cropBox:crop,pageRotation:90)
            XCTAssertEqual(art.contentArtworkID,content)
            if next.orientation != previous.configuration.orientation {XCTAssertNotEqual(art.approvalIdentity,previous.approvalIdentity)}
            let doc=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:art.pdf as CFData))))
            XCTAssertEqual(doc.page(at:1)?.getBoxRect(.mediaBox).size,next.rectangle.size)
            var moved=next;moved.rectangle.origin.x+=1
            let placement=try art.placed(moved,cropBox:crop)
            XCTAssertEqual(placement.pdf,art.pdf);XCTAssertEqual(placement.artworkID,art.artworkID)
            XCTAssertEqual(placement.sha256,art.sha256);XCTAssertNotEqual(placement.approvalIdentity,art.approvalIdentity)
        }
        var changed=art.configuration;changed.customText="changed"
        XCTAssertFalse(art.canReorient(to:changed,pageRotation:90))
        XCTAssertThrowsError(try art.reoriented(changed,cropBox:crop,pageRotation:90))
        XCTAssertThrowsError(try art.reoriented(art.configuration,cropBox:crop,pageRotation:90,isCancelled:{true}))
    }
    func testNativeOverlayBoundsPixelsAndDragAcrossOrientationsPaperSizesAndZoom() throws {
        let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650))
        let w=SignaturePlacementOverlayTests().window(view);defer{w.close()}
        for size in [CGSize(width:595,height:842),CGSize(width:842,height:1191),CGSize(width:1684,height:2384),CGSize(width:2384,height:3370)] {
            for rotation in [0,90,180,270] {
                let media=CGRect(origin:CGPoint(x:20,y:-50),size:size),crop=media.insetBy(dx:10,dy:20)
                let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:rotation==270 ? 10:1,vectors:10000)))
                view.install(document:doc,pageIndex:0);view.layoutSubtreeIfNeeded()
                for q in PAdESAppearanceOrientation.allCases {
                    let c=try Self.config(crop:crop,rotation:rotation,orientation:q)
                    let art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:rotation)
                    view.updatePlacementOverlay(art)
                    for zoom in [0.25,1,2] {
                        view.scaleFactor=zoom;view.signatureOverlay.updateGeometry();view.signatureOverlay.artworkView.displayIfNeeded()
                        XCTAssertGreaterThan(try SignaturePlacementOverlayTests().pixels(view.signatureOverlay.artworkView),0)
                        let layer=view.signatureOverlay.artworkView
                        let bitmap=try XCTUnwrap(layer.bitmapImageRepForCachingDisplay(in:layer.bounds))
                        layer.cacheDisplay(in:layer.bounds,to:bitmap)
                        let points=try PAdESOrientationOutputTests().imageCenters(try XCTUnwrap(bitmap.cgImage))
                        let dx=points[1].x-points[0].x,dy=points[1].y-points[0].y
                        switch try q.resolve(pageRotation:0).viewerClockwiseDegrees {
                        case 0:XCTAssertGreaterThan(dx,2);XCTAssertEqual(dy,0,accuracy:1.5)
                        case 90:XCTAssertGreaterThan(dy,2);XCTAssertEqual(dx,0,accuracy:1.5)
                        case 180:XCTAssertLessThan(dx,-2);XCTAssertEqual(dy,0,accuracy:1.5)
                        default:XCTAssertLessThan(dy,-2);XCTAssertEqual(dx,0,accuracy:1.5)
                        }
                        let expected=view.convert(c.rectangle,from:try XCTUnwrap(doc.page(at:0)))
                        let mapped=view.signatureOverlay.convert(view.signatureOverlay.artworkView.frame,to:view)
                        XCTAssertEqual(mapped.midX,expected.midX,accuracy:0.01);XCTAssertEqual(mapped.midY,expected.midY,accuracy:0.01)
                    }
                    let builds=view.signatureOverlay.artworkBuildCount,rasters=view.signatureOverlay.artworkView.drawCount
                    var moved=c
                    for n in 0..<30 {
                        moved.rectangle.origin.x=c.rectangle.minX+CGFloat(n)
                        view.updatePlacementOverlay(try art.placed(moved,cropBox:crop))
                        view.signatureOverlay.artworkView.displayIfNeeded()
                    }
                    XCTAssertEqual(view.signatureOverlay.artworkBuildCount,builds);XCTAssertEqual(view.signatureOverlay.artworkView.drawCount,rasters)
                }
            }
        }
    }
    func testMixedPageChangeReorientsSameArtworkAndTracksScrolledTarget() throws {
        let first=CGRect(x:20,y:30,width:2384,height:3370),target=CGRect(x:50,y:-200,width:842,height:1191)
        let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:first,rotation:0)))
        let other=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:target,rotation:270,unit:10)))
        doc.insert(try XCTUnwrap(other.page(at:0)),at:1)
        let viewer=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),window=SignaturePlacementOverlayTests().window(viewer)
        defer {window.close()}
        viewer.install(document:doc,pageIndex:0);viewer.layoutSubtreeIfNeeded()
        let c=try Self.config(crop:first,rotation:0,orientation:.automatic)
        let art=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:first,pageRotation:0)
        viewer.updatePlacementOverlay(art)
        viewer.go(to:try XCTUnwrap(doc.page(at:1)));viewer.signatureOverlay.updateGeometry()
        XCTAssertTrue(viewer.signatureOverlay.isHidden,"Previous page artwork must be hidden")
        var next=try c.reoriented(to:.automatic,fromPageRotation:0,toPageRotation:270,cropBox:target);next.pageIndex=1
        let rotated=try art.reoriented(next,cropBox:target,pageRotation:270)
        XCTAssertEqual(rotated.contentArtworkID,art.contentArtworkID)
        XCTAssertNotEqual(rotated.approvalIdentity,art.approvalIdentity)
        XCTAssertEqual(try next.contentSize(pageRotation:270),CGSize(width:240,height:100))
        XCTAssertTrue(target.contains(next.rectangle))
        viewer.install(document:doc,pageIndex:1);viewer.layoutSubtreeIfNeeded()
        viewer.updatePlacementOverlay(rotated);viewer.scaleFactor=2
        let clip=try XCTUnwrap(SignaturePlacementOverlayTests().descendants(viewer).compactMap{$0 as? NSClipView}.first)
        clip.postsBoundsChangedNotifications=true;clip.scroll(to:CGPoint(x:200,y:300))
        (clip.superview as? NSScrollView)?.reflectScrolledClipView(clip)
        viewer.signatureOverlay.updateGeometry()
        let actual=viewer.signatureOverlay.convert(viewer.signatureOverlay.artworkView.frame,to:viewer)
        let expected=viewer.convert(next.rectangle,from:try XCTUnwrap(doc.page(at:1)))
        XCTAssertEqual(actual.midX,expected.midX,accuracy:0.01);XCTAssertEqual(actual.midY,expected.midY,accuracy:0.01)
        let artwork=viewer.signatureOverlay.artworkView
        let bitmap=try XCTUnwrap(artwork.bitmapImageRepForCachingDisplay(in:artwork.bounds));artwork.cacheDisplay(in:artwork.bounds,to:bitmap)
        let colors=try PAdESOrientationOutputTests().imageCenters(try XCTUnwrap(bitmap.cgImage))
        XCTAssertGreaterThan(colors[1].x-colors[0].x,2);XCTAssertEqual(colors[1].y,colors[0].y,accuracy:1.5)
        let resized=try next.resized(toward:CGPoint(x:next.rectangle.minX+120,y:next.rectangle.minY+300),pageRotation:270,cropBox:target)
        XCTAssertEqual(resized.rectangle,next.rectangle,"At the crop edge resizing cannot grow outside the target page")
        var interior=next;interior.rectangle.origin=CGPoint(x:target.minX+100,y:target.minY+100)
        let grown=try interior.resized(toward:CGPoint(x:interior.rectangle.minX+120,y:interior.rectangle.minY+300),pageRotation:270,cropBox:target)
        XCTAssertEqual(try grown.contentSize(pageRotation:270),CGSize(width:300,height:120))
        withExtendedLifetime(other) {}
    }

}
#endif
