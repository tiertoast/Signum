#if os(macOS)
import XCTest
import SwiftUI
import PDFKit
import ImageIO
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESGeometryStabilizationTests: XCTestCase {
    static func pdf(media: CGRect, crop: CGRect? = nil, rotation: Int = 0, unit: Int = 1, vectors: Int = 0) -> Data {
        let c = crop ?? media
        let content = (0..<vectors).map { i in "0.8 G \(i % 2000) \(i % 1800) m \((i % 2000)+30) \((i % 1800)+40) l S" }.joined(separator: "\n")
        let objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [\(media.minX) \(media.minY) \(media.maxX) \(media.maxY)] /CropBox [\(c.minX) \(c.minY) \(c.maxX) \(c.maxY)] /Rotate \(rotation) /UserUnit \(unit) /Contents 4 0 R >>",
            "<< /Length \(content.utf8.count) >>\nstream\n" + content + "\nendstream"]
        var data = Data("%PDF-1.7\n".utf8), offsets = [0]
        for (i, object) in objects.enumerated() { offsets.append(data.count); data.append(Data("\(i+1) 0 obj\n\(object)\nendobj\n".utf8)) }
        let xref = data.count; data.append(Data("xref\n0 5\n0000000000 65535 f \n".utf8))
        for offset in offsets.dropFirst() { data.append(Data(String(format: "%010d 00000 n \n", offset).utf8)) }
        data.append(Data("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n\(xref)\n%%EOF\n".utf8)); return data
    }
    func redArtwork(crop: CGRect) throws -> RenderedPAdESAppearance {
        var c = PAdESAppearanceConfiguration(); c.showSigner = false; c.showLabel = false
        c.image = try PAdESAppearanceImage(data: PAdESAppearanceTests().image())
        c.rectangle = CGRect(x: crop.minX + 40, y: crop.minY + 50, width: 240, height: 100)
        return try PAdESAppearanceRenderer.render(c, certificateDER: Data(), cropBox: crop)
    }
    func testCropBoxPixelsAndPositionAcrossPaperSizesRotationsOriginsAndUserUnit() throws {
        let sizes = [(595.0,842.0),(842,1191),(1684,2384),(2384,3370),(14400,10000)]
        for (w,h) in sizes {
            for rotation in [0,90,180,270] {
                let media = CGRect(x: 20, y: 30, width: w, height: h)
                let crop = media.insetBy(dx: 10, dy: 20)
                let data = Self.pdf(media: media, crop: crop, rotation: rotation, unit: rotation == 270 ? 10 : 1)
                let doc = try XCTUnwrap(PDFDocument(data: data)), page = try XCTUnwrap(doc.page(at: 0))
                let appearance = try redArtwork(crop: crop)
                page.addAnnotation(try XCTUnwrap(AppearancePDFAnnotation(appearance: appearance)))
                let ns = page.thumbnail(of: CGSize(width: 1000, height: 1000), for: .cropBox)
                let image = try XCTUnwrap(ns.cgImage(forProposedRect: nil, context: nil, hints: nil))
                let ctx = try XCTUnwrap(CGContext(data: nil, width: image.width, height: image.height, bitsPerComponent: 8,
                    bytesPerRow: image.width*4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
                ctx.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
                let bytes = ctx.data!.assumingMemoryBound(to: UInt8.self)
                var points: [CGPoint] = []
                for y in 0..<image.height { for x in 0..<image.width {
                    let i = (y*image.width+x)*4
                    if bytes[i] > 200 && Int(bytes[i])-Int(bytes[i+1]) > 60 { points.append(CGPoint(x: x, y: image.height-1-y)) }
                } }
                XCTAssertFalse(points.isEmpty, "Missing red artwork \(w)x\(h) rotation=\(rotation)")
                let center = CGPoint(x: points.map(\.x).reduce(0,+)/CGFloat(max(1,points.count)), y: points.map(\.y).reduce(0,+)/CGFloat(max(1,points.count)))
                // Independent reference: exact artwork drawn into page content,
                // rather than assuming CGPDFPage's transform equals PDFKit's crop thumbnail transform.
                let flat = NSMutableData(); var box = media
                let cg = try XCTUnwrap(CGContext(consumer: try XCTUnwrap(CGDataConsumer(data: flat)), mediaBox: &box, nil))
                cg.beginPDFPage(nil); cg.translateBy(x: appearance.configuration.rectangle.minX, y: appearance.configuration.rectangle.minY)
                let ap = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: appearance.pdf as CFData))))
                cg.drawPDFPage(try XCTUnwrap(ap.page(at: 1))); cg.endPDFPage(); cg.closePDF()
                let reference = try XCTUnwrap(PDFDocument(data: flat as Data)), rp = try XCTUnwrap(reference.page(at: 0))
                rp.setBounds(crop, for: .cropBox); rp.rotation = rotation
                let ri = try XCTUnwrap(rp.thumbnail(of: CGSize(width: 1000, height: 1000), for: .cropBox).cgImage(forProposedRect: nil, context: nil, hints: nil))
                let rc = try XCTUnwrap(CGContext(data: nil, width: ri.width, height: ri.height, bitsPerComponent: 8, bytesPerRow: ri.width*4,
                    space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
                rc.draw(ri, in: CGRect(x: 0, y: 0, width: ri.width, height: ri.height))
                let rb = rc.data!.assumingMemoryBound(to: UInt8.self); var expectedPoints: [CGPoint] = []
                for y in 0..<ri.height { for x in 0..<ri.width {
                    let i = (y*ri.width+x)*4
                    if rb[i] > 200 && Int(rb[i])-Int(rb[i+1]) > 60 { expectedPoints.append(CGPoint(x: x, y: ri.height-1-y)) }
                } }
                XCTAssertFalse(expectedPoints.isEmpty)
                let expected = CGPoint(x: expectedPoints.map(\.x).reduce(0,+)/CGFloat(max(1,expectedPoints.count)), y: expectedPoints.map(\.y).reduce(0,+)/CGFloat(max(1,expectedPoints.count)))
                XCTAssertEqual(center.x, expected.x, accuracy: 2, "rotation=\(rotation)")
                XCTAssertEqual(center.y, expected.y, accuracy: 2, "rotation=\(rotation)")
                withExtendedLifetime(reference) {}
                withExtendedLifetime(doc) {}
            }
        }
    }
    func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap { descendants($0) } }
    func testLargeVectorPaneFitsAfterDocumentInstallationAndLayout() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let media = CGRect(x: 0, y: 0, width: 3370, height: 2384)
        let source = root.appendingPathComponent("synthetic-vector.pdf")
        try Self.pdf(media: media, vectors: 10000).write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .pades); defer { snapshot.close() }
        let artwork = try redArtwork(crop: media)
        let pane = PAdESPlacementPane(snapshot: snapshot, previewReady: {_,_ in}, holder: "Synthetic",
            placement: .constant(PAdESPlacement(pageIndex: 0, rectangle: artwork.configuration.rectangle, appearance: artwork)))
        let host = NSHostingView(rootView: pane)
        let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 850, height: 700), styleMask: [.titled,.resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentView = host; window.orderFront(nil); defer { window.close() }
        host.layoutSubtreeIfNeeded(); try await Task.sleep(nanoseconds: 300_000_000); host.layoutSubtreeIfNeeded()
        let view = try XCTUnwrap(descendants(host).compactMap { $0 as? PlacementPDFView }.first)
        XCTAssertLessThanOrEqual(view.minScaleFactor, view.scaleFactorForSizeToFit)
        XCTAssertEqual(view.scaleFactor, view.scaleFactorForSizeToFit, accuracy: 0.01)
        XCTAssertNotNil(view.signatureOverlay.approvedAppearance)
        XCTAssertTrue(view.signatureOverlay.artworkView.hasPainted)
        XCTAssertNil(view.previewAnnotation, "Live preview must not depend on a PDFKit annotation")
    }
    func testAnnotationConstructionFailureIsExplicitAndNotReportedAsReady() throws {
        let view = PlacementPDFView()
        view.document = try XCTUnwrap(PDFDocument(data: Self.pdf(media: CGRect(x: 0, y: 0, width: 595, height: 842))))
        var c = PAdESAppearanceConfiguration(); c.showSigner = false
        let corrupt = RenderedPAdESAppearance(configuration: c, pdf: Data("not a PDF".utf8), certificateSHA256: "synthetic")
        XCTAssertNotNil(view.updateAppearance(corrupt)); XCTAssertNil(view.previewAnnotation)
        XCTAssertNotNil(view.updateAppearance(corrupt))
    }

}
#endif
