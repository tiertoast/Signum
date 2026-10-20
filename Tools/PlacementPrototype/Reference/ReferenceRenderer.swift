#if os(macOS)
import AppKit
import PDFKit
import SignumCore

struct ReferencePlacement: Equatable {
    let pageIndex: Int
    let rectangle: CGRect
}

// Frozen PDFKit annotation/freeText reference. Linked only by tests and the
// diagnostic prototype, never by App/CLI/worker. Live placement uses the overlay.
final class ReferenceAppearancePDFAnnotation: PDFAnnotation {
    private let artwork: CGPDFDocument
    let artworkID: UUID
    init?(appearance:RenderedPAdESAppearance) {
        guard let source=CGDataProvider(data:appearance.pdf as CFData), let pdf=CGPDFDocument(source), pdf.numberOfPages == 1 else { return nil }
        artwork = pdf; artworkID = appearance.artworkID
        super.init(bounds:appearance.configuration.rectangle,forType:.stamp,withProperties:nil)
    }
    required init?(coder:NSCoder) { nil }
    override func draw(with box:PDFDisplayBox,in context:CGContext) {
        guard let page=artwork.page(at:1) else { return }
        context.saveGState()
        // Offline thumbnail reference only; the live viewport uses SignaturePlacementOverlay.
        // PDFKit's annotation draw callback receives box drawing coordinates.
        // Match its native /AP renderer, including nonzero origin and /Rotate.
        if let original=self.page?.pageRef {
            let cgBox:CGPDFBox = box == .mediaBox ? .mediaBox : .cropBox
            let source=original.getBoxRect(cgBox), rotated=abs(original.rotationAngle)%180 == 90
            let size=rotated ? CGSize(width:source.height,height:source.width) : source.size
            context.concatenate(original.getDrawingTransform(cgBox,rect:CGRect(origin:.zero,size:size),rotate:0,preserveAspectRatio:false))
        }
        context.translateBy(x:bounds.minX,y:bounds.minY)
        context.scaleBy(x:bounds.width/page.getBoxRect(.mediaBox).width,y:bounds.height/page.getBoxRect(.mediaBox).height)
        context.drawPDFPage(page); context.restoreGState()
    }
}

final class ReferencePlacementPDFView: PDFView {
    var previewAnnotation: PDFAnnotation?
    var currentPreviewPlacement: ReferencePlacement?
    private var currentPreviewName: String?
    private var currentPreviewVisible = false
    private var renderedIdentity: String?
    private var appearanceIssue: String?
    private var needsPageFit = false
    func install(document:PDFDocument,pageIndex:Int) {
        let changed = self.document !== document
        if changed {
            displayMode = .singlePage; displayBox = .cropBox
            self.document = document; renderedIdentity = nil
            needsPageFit = true
        }
        if let selected = document.page(at:pageIndex), currentPage !== selected {
            go(to:selected); needsPageFit = true
        }
        if needsPageFit { needsLayout = true }
    }
    override func layout() {
        super.layout()
        guard needsPageFit, document != nil, bounds.width > 0, bounds.height > 0 else { return }
        let fit = scaleFactorForSizeToFit
        guard fit.isFinite, fit > 0 else { return }
        needsPageFit = false
        // Set limits after document/layout. PDFKit setters can disable autoScales;
        // apply the measured fit explicitly, then preserve subsequent user zoom.
        autoScales = false; minScaleFactor = min(0.25,fit/4); maxScaleFactor = max(5,fit*2)
        scaleFactor = fit
    }
    private(set) var appearanceBuildCount = 0
    private(set) var placementUpdateCount = 0
    var onInteraction: ((Bool) -> Void)?
    var onResize: ((PDFPage, CGPoint) -> Void)?
    var onChoose: ((PDFPage, CGPoint) -> Void)?

    override func mouseDown(with event: NSEvent) {
        onInteraction?(true)
        choose(event)
    }

    override func mouseDragged(with event: NSEvent) {
        choose(event)
    }

    override func mouseUp(with event: NSEvent) {
        choose(event)
        onInteraction?(false)
    }

    private func choose(_ event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        guard let page = page(for: point, nearest: true) else { return }
        if event.modifierFlags.contains(.option) { onResize?(page,convert(point,to:page)) }
        else { onChoose?(page, convert(point, to: page)) }
    }

    @discardableResult func updateAppearance(_ value: RenderedPAdESAppearance?) -> String? {
        guard renderedIdentity != value?.approvalIdentity else { return appearanceIssue }
        appearanceIssue = nil
        renderedIdentity = value?.approvalIdentity
        if let value, value.configuration.visible,
           let page=document?.page(at:value.configuration.pageIndex),
           let old=previewAnnotation as? ReferenceAppearancePDFAnnotation, old.artworkID == value.artworkID {
            let previous = convert(old.bounds,from:old.page ?? page)
            if old.page !== page { old.page?.removeAnnotation(old); page.addAnnotation(old) }
            old.bounds = value.configuration.rectangle
            placementUpdateCount += 1
            setNeedsDisplay(previous.union(convert(old.bounds,from:page)).insetBy(dx:-2,dy:-2))
            return nil
        }
        if let old=previewAnnotation { old.page?.removeAnnotation(old); previewAnnotation=nil }
        guard let value, value.configuration.visible else { return nil }
        guard let page=document?.page(at:value.configuration.pageIndex) else {
            appearanceIssue = "Pagina dell’anteprima non disponibile."; return appearanceIssue
        }
        guard let annotation=ReferenceAppearancePDFAnnotation(appearance:value) else {
            appearanceIssue = "Annotazione grafica non costruita. Modifica l’aspetto o riseleziona il documento."
            return appearanceIssue
        }
        appearanceBuildCount += 1
        page.addAnnotation(annotation); previewAnnotation=annotation
        return nil
    }
    func updatePreview(_ placement: ReferencePlacement?, name: String, visible: Bool) {
        if currentPreviewPlacement != placement || currentPreviewName != name || currentPreviewVisible != visible {
            setPreview(placement, name: name, visible: visible)
        }
    }

    private func setPreview(_ placement: ReferencePlacement?, name: String, visible: Bool) {
        if let old = previewAnnotation {
            old.page?.removeAnnotation(old)
            previewAnnotation = nil
        }
        currentPreviewPlacement = placement
        currentPreviewName = name
        currentPreviewVisible = visible
        guard visible, let placement, let page = document?.page(at: placement.pageIndex) else { return }
        let annotation = PDFAnnotation(bounds: placement.rectangle, forType: .freeText, withProperties: nil)
        annotation.contents = "Firmato digitalmente da\n" + name
        annotation.font = NSFont.systemFont(ofSize: 10)
        annotation.fontColor = NSColor.labelColor
        annotation.color = NSColor.white
        annotation.border = PDFBorder()
        annotation.border?.lineWidth = 1
        page.addAnnotation(annotation)
        previewAnnotation = annotation
    }
}

#endif
