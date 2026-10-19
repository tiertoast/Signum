#if os(macOS)
import XCTest
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESOrientationPerformanceTests: XCTestCase {
    func testRotatedDragKeepsArtworkHashAndRasterCacheWhileOrientationAndResizeInvalidate() throws {
        let crop=CGRect(x:0,y:0,width:3370,height:2384)
        let viewer=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650)),w=SignaturePlacementOverlayTests().window(viewer);defer{w.close()}
        let doc=try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:crop,rotation:90,vectors:10000)))
        viewer.install(document:doc,pageIndex:0);viewer.layoutSubtreeIfNeeded()
        for pixels in [0,1024,2800] {
            var c=PAdESAppearanceConfiguration();c.showSigner=false;c.customText="READ ->"
            if pixels>0 {c.image=try PAdESAppearanceImage(data:PAdESPlacementPerformanceTests.png(pixels))}
            c=try c.reoriented(to:.automatic,fromPageRotation:0,toPageRotation:90,cropBox:crop)
            let start=ProcessInfo.processInfo.systemUptime
            var artwork=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:90)
            let generate=(ProcessInfo.processInfo.systemUptime-start)*1000
            for q in [PAdESAppearanceOrientation.degrees90,.degrees180,.degrees270,.automatic] {
                let next=try c.reoriented(to:q,fromPageRotation:90,toPageRotation:90,cropBox:crop)
                let begin=ProcessInfo.processInfo.systemUptime
                let rotated=try artwork.reoriented(next,cropBox:crop,pageRotation:90)
                let orient=(ProcessInfo.processInfo.systemUptime-begin)*1000
                XCTAssertEqual(rotated.contentArtworkID,artwork.contentArtworkID)
                let show=ProcessInfo.processInfo.systemUptime
                viewer.updatePlacementOverlay(rotated);viewer.signatureOverlay.artworkView.displayIfNeeded()
                let overlay=(ProcessInfo.processInfo.systemUptime-show)*1000
                let builds=viewer.signatureOverlay.artworkBuildCount,rasters=viewer.signatureOverlay.artworkView.drawCount
                var times:[Double]=[]
                for n in 0..<120 {
                    var moved=next;moved.rectangle.origin=CGPoint(x:500+n,y:500)
                    let tick=ProcessInfo.processInfo.systemUptime
                    let value=try rotated.placed(moved,cropBox:crop)
                    viewer.updatePlacementOverlay(value);viewer.signatureOverlay.artworkView.displayIfNeeded()
                    times.append((ProcessInfo.processInfo.systemUptime-tick)*1000)
                    XCTAssertEqual(value.sha256,rotated.sha256)
                }
                XCTAssertEqual(viewer.signatureOverlay.artworkBuildCount,builds);XCTAssertEqual(viewer.signatureOverlay.artworkView.drawCount,rasters)
                times.sort()
                print("B12 performance pixels=\(pixels) orientation=\(q.rawValue) generate_ms=\(generate) orientation_ms=\(orient) overlay_ms=\(overlay) drag_median_ms=\(times[60]) drag_p95_ms=\(times[114]) drag_pdf_or_raster=0 cache_bytes=\(viewer.signatureOverlay.artworkView.cachedPixelBytes)")
                artwork=rotated;c=next
            }
            let resize=ProcessInfo.processInfo.systemUptime
            let size=try c.contentSize(pageRotation:90)
            c=try c.resized(contentSize:CGSize(width:size.width+20,height:size.height+10),pageRotation:90,cropBox:crop)
            let resized=try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,pageRotation:90)
            viewer.updatePlacementOverlay(resized);viewer.signatureOverlay.artworkView.displayIfNeeded()
            XCTAssertNotEqual(resized.contentArtworkID,artwork.contentArtworkID)
            print("B12 rotated_resize pixels=\(pixels) total_ms=\((ProcessInfo.processInfo.systemUptime-resize)*1000)")
        }
    }
}
#endif
