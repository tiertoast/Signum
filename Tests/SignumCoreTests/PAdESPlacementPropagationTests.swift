#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore

@MainActor final class PAdESPlacementPropagationTests: XCTestCase {
    private func pdf(_ width: CGFloat, _ height: CGFloat, rotation: Int = 0) throws -> Data {
        try PAdESGeometryStabilizationTests.pdf(media: CGRect(x: 0, y: 0, width: width, height: height), crop: nil, rotation: rotation, unit: 1, vectors: 0)
    }
    private func template(on bytes: Data, at origin: CGPoint) throws -> RenderedPAdESAppearance {
        let page = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: bytes as CFData)))?.page(at: 1))
        let geometry = try PAdESPageGeometry(page: page)
        var config = try geometry.defaultAppearance()
        config.showSigner = false; config.customText = "Synthetic stamp"
        config.rectangle.origin = origin
        return try PAdESAppearanceRenderer.render(config, certificateDER: Data(), cropBox: geometry.cropBox, pageRotation: geometry.rotation)
    }

    func testSameGeometryKeepsTheExactPositionAndStyle() throws {
        let a4 = try pdf(595, 842), other = try pdf(595, 842)
        let source = try template(on: a4, at: CGPoint(x: 100, y: 120))
        let copy = try PAdESPlacementPropagation.appearance(from: source, templatePDF: a4, targetPDF: other, certificateDER: Data())
        XCTAssertEqual(copy.configuration.rectangle, source.configuration.rectangle)
        XCTAssertEqual(copy.configuration.customText, "Synthetic stamp")
        XCTAssertEqual(copy.configuration.pageIndex, 0)
        XCTAssertEqual(copy.certificateSHA256, source.certificateSHA256)
    }

    private func geometry(_ bytes: Data, page: Int = 1) throws -> PAdESPageGeometry {
        try PAdESPageGeometry(page: try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: bytes as CFData)))?.page(at: page)))
    }
    private func pages(_ count: Int, _ size: CGSize = CGSize(width: 595, height: 842)) throws -> Data {
        let output = NSMutableData(); var box = CGRect(origin: .zero, size: size)
        let context = try XCTUnwrap(CGContext(consumer: try XCTUnwrap(CGDataConsumer(data: output as CFMutableData)), mediaBox: &box, nil))
        for _ in 0..<count { context.beginPDFPage(nil); context.endPDFPage() }
        context.closePDF(); return output as Data
    }

    func testStampKeepsItsVisibleMarginsOnDifferentPages() throws {
        let a4 = try pdf(595, 842)
        let source = try template(on: a4, at: CGPoint(x: 100, y: 120)) // Bottom-left.
        for target in [try pdf(595.32, 841.92), try pdf(842, 1191), try pdf(595, 842, rotation: 90), try pdf(842, 595, rotation: 270)] {
            let copy = try PAdESPlacementPropagation.appearance(from: source, templatePDF: a4, targetPDF: target, certificateDER: Data())
            let g = try geometry(target)
            let visible = copy.configuration.rectangle.applying(g.rawToVisible), bounds = g.visibleBounds
            XCTAssertEqual(visible.minX - bounds.minX, 100, accuracy: 0.001)
            XCTAssertEqual(visible.minY - bounds.minY, 120, accuracy: 0.001)
            XCTAssertEqual(copy.configuration.customText, "Synthetic stamp")
        }
        let topRight = try template(on: a4, at: CGPoint(x: 595 - 30 - 240, y: 842 - 40 - 90))
        let a3 = try pdf(842, 1191)
        let copy = try PAdESPlacementPropagation.appearance(from: topRight, templatePDF: a4, targetPDF: a3, certificateDER: Data())
        XCTAssertEqual(copy.configuration.rectangle.maxX, 842 - 30, accuracy: 0.001)
        XCTAssertEqual(copy.configuration.rectangle.maxY, 1191 - 40, accuracy: 0.001)
    }

    func testStampOnLastPageFollowsTheLastPage() throws {
        let three = try pages(3), five = try pages(5), one = try pages(1)
        let g = try geometry(three, page: 3)
        var config = try g.defaultAppearance(pageIndex: 2); config.showSigner = false; config.customText = "Synthetic stamp"
        let last = try PAdESAppearanceRenderer.render(config, certificateDER: Data(), cropBox: g.cropBox, pageRotation: g.rotation)
        XCTAssertEqual(try PAdESPlacementPropagation.appearance(from: last, templatePDF: three, targetPDF: five, certificateDER: Data()).configuration.pageIndex, 4)
        XCTAssertEqual(try PAdESPlacementPropagation.appearance(from: last, templatePDF: three, targetPDF: one, certificateDER: Data()).configuration.pageIndex, 0)
        config.pageIndex = 0
        let first = try PAdESAppearanceRenderer.render(config, certificateDER: Data(), cropBox: g.cropBox, pageRotation: g.rotation)
        XCTAssertEqual(try PAdESPlacementPropagation.appearance(from: first, templatePDF: three, targetPDF: five, certificateDER: Data()).configuration.pageIndex, 0)
    }

    func testInvisibleTemplateAndUnreadablePDFAreRejected() throws {
        let a4 = try pdf(595, 842)
        let visible = try template(on: a4, at: CGPoint(x: 100, y: 120))
        XCTAssertThrowsError(try PAdESPlacementPropagation.appearance(from: visible, templatePDF: a4, targetPDF: Data("no pdf".utf8), certificateDER: Data()))
        var config = visible.configuration; config.visible = false
        let invisible = try PAdESAppearanceRenderer.render(config, certificateDER: Data(), cropBox: CGRect(x: 0, y: 0, width: 595, height: 842), pageRotation: 0)
        XCTAssertThrowsError(try PAdESPlacementPropagation.appearance(from: invisible, templatePDF: a4, targetPDF: a4, certificateDER: Data()))
    }
}
#endif
