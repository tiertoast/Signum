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

    func testDifferentPageUsesDefaultCornerWithSamePhysicalSize() throws {
        let a4 = try pdf(595, 842), a3 = try pdf(842, 1191), rotated = try pdf(595, 842, rotation: 90)
        let source = try template(on: a4, at: CGPoint(x: 100, y: 120))
        for target in [a3, rotated] {
            let copy = try PAdESPlacementPropagation.appearance(from: source, templatePDF: a4, targetPDF: target, certificateDER: Data())
            let page = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: target as CFData)))?.page(at: 1))
            let expected = try PAdESPageGeometry(page: page).defaultAppearance()
            XCTAssertEqual(copy.configuration.rectangle, expected.rectangle)
            XCTAssertEqual(copy.configuration.customText, "Synthetic stamp")
        }
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
