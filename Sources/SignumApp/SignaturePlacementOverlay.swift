#if os(macOS)
import AppKit
import PDFKit
import SignumCore

/// A viewport sibling of PDFKit's tiled document view. PDFKit supplies coordinate
/// conversion only; its annotation drawing callbacks are never used here.
final class SignaturePlacementOverlay: NSView {
    weak var viewer: PDFView?
    private(set) var approvedAppearance: RenderedPAdESAppearance?
    private(set) var artworkBuildCount = 0
    private(set) var geometryUpdateCount = 0
    let artworkView = SignatureArtworkView()
    var displayed: ((String, String?) -> Void)?
    private var artworkID: UUID?
    private var error: String?

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true; layer?.masksToBounds = true
        addSubview(artworkView)
        artworkView.didDraw = { [weak self] in self?.reportIfPainted() }
        artworkView.didFail = { [weak self] in
            guard let self, let value = self.approvedAppearance else { return }
            self.error = "Memoria insufficiente per visualizzare il timbro. Riduci lo zoom o l’immagine."
            self.isHidden = true; self.displayed?(value.approvalIdentity,self.error)
        }
        for name in [Notification.Name.PDFViewScaleChanged, .PDFViewPageChanged,
                     NSView.boundsDidChangeNotification, NSView.frameDidChangeNotification] {
            NotificationCenter.default.addObserver(self, selector: #selector(viewportChanged(_:)), name: name, object: nil)
        }
    }
    required init?(coder: NSCoder) { nil }
    deinit { NotificationCenter.default.removeObserver(self) }
    override var isOpaque: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    @objc private func viewportChanged(_ note: Notification) {
        guard let viewer else { return }
        if note.object as? PDFView === viewer ||
            (note.object as? NSClipView).map({ $0.isDescendant(of: viewer) }) == true {
            updateGeometry()
        }
    }
    func clear() {
        approvedAppearance = nil; artworkID = nil; error = nil
        artworkView.reset(); isHidden = true
    }
    @discardableResult func update(_ value: RenderedPAdESAppearance?) -> String? {
        guard let value else { clear(); return nil }
        approvedAppearance = value
        guard value.configuration.visible else {
            artworkView.reset(); artworkID = nil; isHidden = true
            displayed?(value.approvalIdentity, nil); return nil
        }
        if artworkID != value.artworkID {
            artworkView.reset(); error = nil
            guard let provider = CGDataProvider(data: value.pdf as CFData),
                  let doc = CGPDFDocument(provider), doc.numberOfPages == 1,
                  let page = doc.page(at: 1), !page.getBoxRect(.mediaBox).isEmpty else {
                error = "Artwork dell’anteprima non leggibile. Modifica l’aspetto o riseleziona il documento."
                isHidden = true; displayed?(value.approvalIdentity, error); return error
            }
            artworkView.document = doc; artworkID = value.artworkID; artworkBuildCount += 1
        }
        updateGeometry()
        reportIfPainted()
        return error
    }
    func updateGeometry() {
        guard let viewer, let value = approvedAppearance, value.configuration.visible,
              let page = viewer.document?.page(at: value.configuration.pageIndex),
              let ap = artworkView.document?.page(at: 1) else { isHidden = true; return }
        guard viewer.currentPage === page else { isHidden = true; return }
        // Exclude scroll bars, and clip partial artwork at the viewport boundary.
        let clip = viewer.subviews.compactMap { $0 as? NSScrollView }.first?.contentView
        let viewport = clip.map { viewer.convert($0.bounds, from: $0) } ?? viewer.bounds
        frame = viewport
        let r = value.configuration.rectangle, box = ap.getBoxRect(.mediaBox)
        func map(_ p: CGPoint) -> CGPoint { convert(viewer.convert(p, from: page), from: viewer) }
        let o = map(r.origin), x = map(CGPoint(x: r.maxX, y: r.minY)), y = map(CGPoint(x: r.minX, y: r.maxY))
        let fourth = CGPoint(x: x.x + y.x - o.x, y: x.y + y.y - o.y)
        let xs = [o.x,x.x,y.x,fourth.x], ys = [o.y,x.y,y.y,fourth.y]
        let target = CGRect(x: xs.min()!, y: ys.min()!, width: xs.max()! - xs.min()!, height: ys.max()! - ys.min()!)
        guard [target.minX,target.minY,target.width,target.height].allSatisfy({ $0.isFinite }),
              target.width > 0, target.height > 0 else {
            error = "Geometria dell’anteprima non disponibile."
            isHidden = true; displayed?(value.approvalIdentity,error); return
        }
        let a = (x.x-o.x)/box.width, b = (x.y-o.y)/box.width
        let c = (y.x-o.x)/box.height, d = (y.y-o.y)/box.height
        let transform = CGAffineTransform(a:a,b:b,c:c,d:d,
            tx:o.x-target.minX-a*box.minX-c*box.minY,
            ty:o.y-target.minY-b*box.minX-d*box.minY)
        geometryUpdateCount += 1
        artworkView.place(frame:target,transform:transform)
        isHidden = false
    }
    private func reportIfPainted() {
        guard let value = approvedAppearance, !isHidden, error == nil, artworkView.hasPainted else { return }
        displayed?(value.approvalIdentity, nil)
    }
}

/// Core Animation caches only the small generated artwork, never the source
/// document. Moving it changes the frame origin without drawing/decoding again.
final class SignatureArtworkView: NSView {
    var document: CGPDFDocument?
    var didDraw: (() -> Void)?
    var didFail: (() -> Void)?
    private var cachedPixels: CGImage?
    var cachedPixelBytes: Int { cachedPixels.map { $0.bytesPerRow * $0.height } ?? 0 }
    private(set) var hasPainted = false
    private(set) var drawCount = 0
    private(set) var transform = CGAffineTransform.identity
    override init(frame: NSRect) {
        super.init(frame:frame)
        wantsLayer = true
        layerContentsRedrawPolicy = .onSetNeedsDisplay
    }
    required init?(coder: NSCoder) { nil }
    override func viewDidChangeBackingProperties() {
        super.viewDidChangeBackingProperties()
        cachedPixels = nil; hasPainted = false; needsDisplay = true
    }
    override var isOpaque: Bool { false }
    override func hitTest(_ point:NSPoint)->NSView? { nil }
    func reset() {
        document = nil; cachedPixels = nil; hasPainted = false
        layer?.contents = nil; needsDisplay = true
    }
    func place(frame next: CGRect, transform t:CGAffineTransform) {
        let lhs = [transform.a,transform.b,transform.c,transform.d,transform.tx,transform.ty,frame.width,frame.height]
        let rhs = [t.a,t.b,t.c,t.d,t.tx,t.ty,next.width,next.height]
        let redraw = !hasPainted || zip(lhs,rhs).contains { abs($0-$1) > 0.000001 }
        frame = next
        if redraw { transform = t; cachedPixels = nil; hasPainted = false; needsDisplay = true }
    }
    override func draw(_ dirtyRect:NSRect) {
        guard let page = document?.page(at:1), let context = NSGraphicsContext.current?.cgContext else { return }
        if cachedPixels == nil {
            // PDFKit can invalidate an NSView even for frame-origin changes.
            // Cache the generated artwork pixels explicitly as well as the layer;
            // a drag can never re-enter PDF/image decoding.
            let requested = window?.backingScaleFactor ?? 2
            let scale = min(requested, 4096 / max(bounds.width,bounds.height))
            let width = max(1,Int(ceil(bounds.width*scale))), height = max(1,Int(ceil(bounds.height*scale)))
            guard let bitmap = CGContext(data:nil,width:width,height:height,bitsPerComponent:8,bytesPerRow:width*4,
                space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue) else {
                DispatchQueue.main.async { [weak self] in self?.didFail?() }; return
            }
            bitmap.scaleBy(x:CGFloat(width)/bounds.width,y:CGFloat(height)/bounds.height)
            bitmap.concatenate(transform); bitmap.drawPDFPage(page)
            cachedPixels = bitmap.makeImage(); drawCount += 1
        }
        guard let cachedPixels else { return }
        context.draw(cachedPixels,in:bounds)
        NSColor.controlAccentColor.withAlphaComponent(0.8).setStroke()
        let border = NSBezierPath(rect:bounds.insetBy(dx:0.5,dy:0.5)); border.lineWidth = 1; border.stroke()
        hasPainted = true
        // Never mutate SwiftUI state inside an AppKit drawing callback.
        DispatchQueue.main.async { [weak self] in self?.didDraw?() }
    }
}
#endif
