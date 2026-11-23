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
/// opening each preview. Style and physical size are kept. The stamp keeps its
/// distance from the nearest page edges as seen on screen (e.g. 2 cm from the
/// bottom-left corner), so small page-size differences or rotations do not move
/// it to another corner. A stamp on the last page goes to the target's last page.
public enum PAdESPlacementPropagation {
    public static func appearance(from template: RenderedPAdESAppearance, templatePDF: Data,
                                  targetPDF: Data, certificateDER: Data,
                                  isCancelled: () -> Bool = { false }) throws -> RenderedPAdESAppearance {
        try appearance(from: template.configuration, templatePDF: templatePDF, targetPDF: targetPDF,
                       certificateDER: certificateDER, isCancelled: isCancelled)
    }
    /// Re-render a stamp on its own page, e.g. for a newly selected certificate.
    public static func rerender(_ configuration: PAdESAppearanceConfiguration, pdf: Data, certificateDER: Data,
                                isCancelled: () -> Bool = { false }) throws -> RenderedPAdESAppearance {
        let page = try geometry(pdf, page: configuration.pageIndex)
        return try PAdESAppearanceRenderer.render(configuration, certificateDER: certificateDER, cropBox: page.cropBox,
                                                  pageRotation: page.rotation, isCancelled: isCancelled)
    }
    /// `configuration` is the user's draft (it keeps showSigner even when the
    /// preview was rendered before a certificate was chosen).
    public static func appearance(from source: PAdESAppearanceConfiguration, templatePDF: Data,
                                  targetPDF: Data, certificateDER: Data,
                                  isCancelled: () -> Bool = { false }) throws -> RenderedPAdESAppearance {
        guard source.visible else { throw SignumError.module("Solo una firma visibile può essere applicata agli altri PDF.") }
        let sourcePages = try pageCount(templatePDF)
        let sourceGeometry = try geometry(templatePDF, page: source.pageIndex)
        guard sourceGeometry.userUnit == source.effectiveUserUnit else { throw SignumError.module("UserUnit del timbro non coerente con il PDF di origine.") }
        let pages = try pageCount(targetPDF)
        let onLastPage = sourcePages > 1 && source.pageIndex == sourcePages - 1
        let pageIndex = onLastPage ? pages - 1 : min(source.pageIndex, pages - 1)
        let target = try geometry(targetPDF, page: pageIndex)
        var next = source
        next.pageIndex = pageIndex
        if !(target.cropBox == sourceGeometry.cropBox && target.rotation == sourceGeometry.rotation &&
             target.userUnit == sourceGeometry.userUnit) {
            let raw = try source.contentSize(pageRotation: sourceGeometry.rotation)
            let physical = CGSize(width: raw.width * source.effectiveUserUnit, height: raw.height * source.effectiveUserUnit)
            // Default placement gives the right footprint and orientation; then
            // anchor it to the same visible edges and margins as the template.
            let placed = try target.defaultAppearance(pageIndex: pageIndex, contentSize: physical, orientation: source.orientation)
            let from = source.rectangle.applying(sourceGeometry.rawToVisible), fromBounds = sourceGeometry.visibleBounds
            let footprint = placed.rectangle.applying(target.rawToVisible).size, bounds = target.visibleBounds
            let scale = sourceGeometry.userUnit / target.userUnit // Same physical margins.
            let left = (from.minX - fromBounds.minX) * scale, right = (fromBounds.maxX - from.maxX) * scale
            let bottom = (from.minY - fromBounds.minY) * scale, top = (fromBounds.maxY - from.maxY) * scale
            var x = left <= right ? bounds.minX + left : bounds.maxX - right - footprint.width
            var y = bottom <= top ? bounds.minY + bottom : bounds.maxY - top - footprint.height
            x = min(max(x, bounds.minX), bounds.maxX - footprint.width)
            y = min(max(y, bounds.minY), bounds.maxY - footprint.height)
            next.userUnit = placed.userUnit; next.orientation = placed.orientation
            next.rectangle = CGRect(x: x, y: y, width: footprint.width, height: footprint.height)
                .applying(target.rawToVisible.inverted())
            try next.validate(cropBox: target.cropBox, pageRotation: target.rotation)
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
