#if os(macOS)
import Foundation
import CoreGraphics

/// Geometry of the approved snapshot, in raw PDF units. UserUnit converts raw
/// lengths to physical points (1/72 inch). No viewer state or source-path reads.
public struct PAdESPageGeometry: Sendable {
    public let cropBox: CGRect
    public let rotation: Int
    public let userUnit: CGFloat
    public init(mediaBox: CGRect, cropBox: CGRect, rotation: Int, userUnit: CGFloat = 1) throws {
        let effective = mediaBox.intersection(cropBox)
        guard [mediaBox.minX,mediaBox.minY,mediaBox.width,mediaBox.height,cropBox.minX,cropBox.minY,cropBox.width,cropBox.height,userUnit].allSatisfy(\.isFinite),
              !effective.isEmpty, !effective.isNull, userUnit > 0, userUnit <= 75000 else {
            throw SignumError.module("Geometria PDF o UserUnit non valido.")
        }
        self.cropBox = effective
        self.rotation = try PAdESAppearanceOrientation.automatic.resolve(pageRotation:rotation).pageRotation
        self.userUnit = userUnit
    }
    public init(page: CGPDFPage) throws {
        var unit: CGPDFReal = 1
        if let dictionary = page.dictionary {
            var object: CGPDFObjectRef?
            if CGPDFDictionaryGetObject(dictionary,"UserUnit",&object),
               !CGPDFDictionaryGetNumber(dictionary,"UserUnit",&unit) {
                throw SignumError.module("UserUnit PDF non numerico.")
            }
        }
        try self.init(mediaBox:page.getBoxRect(.mediaBox),cropBox:page.getBoxRect(.cropBox),rotation:Int(page.rotationAngle),userUnit:unit)
    }
    /// Same quarter-turn matrices used by the appearance; inverse page rotation
    /// maps raw crop coordinates to the viewer's upright, bottom-left coordinates.
    public var rawToVisible: CGAffineTransform {
        let turn = try! PAdESAppearanceOrientation.automatic.resolve(pageRotation:(360-rotation)%360)
        return CGAffineTransform(translationX:-cropBox.minX,y:-cropBox.minY)
            .concatenating(turn.transform(contentSize:cropBox.size))
    }
    public var visibleBounds: CGRect { cropBox.applying(rawToVisible) }
    public func defaultAppearance(pageIndex: Int = 0, contentSize: CGSize = CGSize(width:240,height:90),
                                  orientation: PAdESAppearanceOrientation = .automatic) throws -> PAdESAppearanceConfiguration {
        let resolved = try orientation.resolve(pageRotation:rotation)
        let rawSize = CGSize(width:contentSize.width/userUnit,height:contentSize.height/userUnit)
        let footprint = resolved.footprintSize(forContent:rawSize)
        let visibleSize = CGRect(origin:.zero,size:footprint).applying(rawToVisible).size
        let bounds = visibleBounds
        guard pageIndex >= 0, contentSize.width.isFinite, contentSize.height.isFinite,
              visibleSize.width <= bounds.width, visibleSize.height <= bounds.height else {
            throw SignumError.module("La pagina è troppo piccola per il timbro di 240 × 90 pt. Scegli una pagina più grande.")
        }
        // Preserve size. If 10 mm do not fit, reduce each margin independently
        // to the available space, down to zero. Never scale or clip the stamp.
        let margin = 10 * 72 / 25.4 / userUnit
        let right = min(margin,max(0,bounds.width-visibleSize.width))
        let top = min(margin,max(0,bounds.height-visibleSize.height))
        let visible = CGRect(x:bounds.maxX-right-visibleSize.width,y:bounds.maxY-top-visibleSize.height,
                             width:visibleSize.width,height:visibleSize.height)
        var config = PAdESAppearanceConfiguration()
        config.pageIndex = pageIndex; config.orientation = orientation; config.userUnit = userUnit
        config.rectangle = visible.applying(rawToVisible.inverted())
        try config.validate(cropBox:cropBox,pageRotation:rotation)
        return config
    }
}

/// Reuse an approved visible stamp on other PDFs of the same batch, without
/// opening each preview. Style and physical size are kept. The exact rectangle
/// is kept only when the target page has the same geometry; otherwise the
/// stamp goes to the default top-right position of that page.
public enum PAdESPlacementPropagation {
    public static func appearance(from template: RenderedPAdESAppearance, templatePDF: Data,
                                  targetPDF: Data, certificateDER: Data,
                                  isCancelled: () -> Bool = { false }) throws -> RenderedPAdESAppearance {
        let source = template.configuration
        guard source.visible else { throw SignumError.module("Solo una firma visibile può essere applicata agli altri PDF.") }
        let sourceGeometry = try geometry(templatePDF, page: source.pageIndex)
        guard sourceGeometry.userUnit == source.effectiveUserUnit else { throw SignumError.module("UserUnit del timbro non coerente con il PDF di origine.") }
        let pages = try pageCount(targetPDF)
        let pageIndex = min(source.pageIndex, pages - 1)
        let target = try geometry(targetPDF, page: pageIndex)
        var next = source
        if pageIndex == source.pageIndex, target.cropBox == sourceGeometry.cropBox,
           target.rotation == sourceGeometry.rotation, target.userUnit == sourceGeometry.userUnit {
            next.pageIndex = pageIndex
        } else {
            let raw = try source.contentSize(pageRotation: sourceGeometry.rotation)
            let physical = CGSize(width: raw.width * source.effectiveUserUnit, height: raw.height * source.effectiveUserUnit)
            let placed = try target.defaultAppearance(pageIndex: pageIndex, contentSize: physical, orientation: source.orientation)
            next.pageIndex = placed.pageIndex; next.userUnit = placed.userUnit
            next.orientation = placed.orientation; next.rectangle = placed.rectangle
        }
        return try PAdESAppearanceRenderer.render(next, certificateDER: certificateDER, cropBox: target.cropBox,
                                                  pageRotation: target.rotation, isCancelled: isCancelled)
    }
    private static func document(_ bytes: Data) throws -> CGPDFDocument {
        guard let provider = CGDataProvider(data: bytes as CFData), let pdf = CGPDFDocument(provider),
              !pdf.isEncrypted, pdf.numberOfPages > 0 else { throw SignumError.module("PDF non disponibile o protetto.") }
        return pdf
    }
    private static func pageCount(_ bytes: Data) throws -> Int { try document(bytes).numberOfPages }
    private static func geometry(_ bytes: Data, page index: Int) throws -> PAdESPageGeometry {
        guard index >= 0, let page = try document(bytes).page(at: index + 1) else { throw SignumError.module("Pagina PDF non disponibile.") }
        return try PAdESPageGeometry(page: page)
    }
}
#endif
