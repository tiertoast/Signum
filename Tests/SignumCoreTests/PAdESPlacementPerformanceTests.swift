#if os(macOS)
import XCTest
import PDFKit
import ImageIO
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESPlacementPerformanceTests: XCTestCase {
    static func png(_ size: Int) throws -> Data {
        let context = try XCTUnwrap(CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        for x in stride(from: 0, to: size, by: 32) {
            context.setFillColor(CGColor(red: Double(x%255)/255, green: 0.2, blue: 0.6, alpha: 0.8))
            context.fill(CGRect(x: x, y: 0, width: 32, height: size))
        }
        let result = NSMutableData(), destination = try XCTUnwrap(CGImageDestinationCreateWithData(result,"public.png" as CFString,1,nil))
        CGImageDestinationAddImage(destination,try XCTUnwrap(context.makeImage()),nil)
        XCTAssertTrue(CGImageDestinationFinalize(destination)); return result as Data
    }
    func testThirtyAndOneHundredTwentyMovesReuseBytesHashAndAnnotationForEveryImageSize() throws {
        let crop = CGRect(x: 0, y: 0, width: 3370, height: 2384)
        for pixels in [0,1024,2800] {
            var config = PAdESAppearanceConfiguration(); config.showSigner = false
            if pixels > 0 { config.image = try PAdESAppearanceImage(data: Self.png(pixels)) }
            let artwork = try PAdESAppearanceRenderer.render(config,certificateDER:Data(),cropBox:crop)
            let view = PlacementPDFView(frame:CGRect(x:0,y:0,width:850,height:600))
            view.install(document:try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:crop,vectors:10000))),pageIndex:0)
            view.layoutSubtreeIfNeeded(); XCTAssertNil(view.updateAppearance(artwork))
            let annotation = try XCTUnwrap(view.previewAnnotation)
            for events in [30,120] {
                var times:[Double] = []
                for index in 0..<events {
                    config.rectangle.origin = CGPoint(x: 40+index*2, y: 80)
                    let start = ProcessInfo.processInfo.systemUptime
                    let placed = try artwork.placed(config,cropBox:crop)
                    XCTAssertNil(view.updateAppearance(placed))
                    times.append((ProcessInfo.processInfo.systemUptime-start)*1000)
                    XCTAssertEqual(placed.pdf,artwork.pdf); XCTAssertEqual(placed.sha256,artwork.sha256)
                    XCTAssertEqual(placed.artworkID,artwork.artworkID)
                    XCTAssertEqual(view.previewAnnotation?.bounds,config.rectangle)
                    XCTAssertTrue(annotation === view.previewAnnotation)
                    XCTAssertEqual(view.appearanceBuildCount,1)
                    if index > 0 { XCTAssertNotEqual(placed.approvalIdentity,artwork.approvalIdentity) }
                }
                let sorted=times.sorted()
                print("STABILIZATION placement pixels=\(pixels) events=\(events) median_ms=\(sorted[events/2]) p95_ms=\(sorted[Int(Double(events)*0.95)]) artwork_builds=\(view.appearanceBuildCount)")
            }
            for change in 0..<5 {
                var changed=config
                switch change {
                case 0: changed.customText="changed"
                case 1: changed.rectangle.size.width += 10
                case 2: changed.fontSize += 1
                case 3: changed.visible=false
                default: changed.localDate=Date()
                }
                XCTAssertThrowsError(try artwork.placed(changed,cropBox:crop))
            }
        }
    }
}
#endif
