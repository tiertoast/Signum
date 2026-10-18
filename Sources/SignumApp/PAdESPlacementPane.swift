#if os(macOS)
import SwiftUI
import AppKit
import PDFKit
import UniformTypeIdentifiers
import SignumCore

struct PAdESPlacement: Equatable {
    let pageIndex: Int
    let rectangle: CGRect
    var appearance: RenderedPAdESAppearance? = nil
}

private actor AppearanceRenderWorker {
    static let shared = AppearanceRenderWorker()
    func render(_ config:PAdESAppearanceConfiguration,der:Data,crop:CGRect) throws -> RenderedPAdESAppearance {
        try Task.checkCancellation()
        return try PAdESAppearanceRenderer.render(config,certificateDER:der,cropBox:crop)
    }
}
struct PAdESPlacementPane: View {
    let snapshot: DocumentSnapshot
    let previewReady: (UUID, Bool) -> Void
    let holder: String
    var certificateDER: Data? = nil
    @Binding var placement: PAdESPlacement?
    @State private var configuration = PAdESAppearanceConfiguration()
    @State private var pdfDocument: PDFDocument?
    @State private var rendered: RenderedPAdESAppearance?
    @State private var issue = ""
    @State private var renderID = UUID()
    @State private var rendering = false
    @State private var annotationReady = false
    @State private var renderTask: Task<Void,Never>?
    private var crop: CGRect {
        guard let page = pdfDocument?.page(at: configuration.pageIndex)?.pageRef else { return .zero }
        return page.getBoxRect(.cropBox).intersection(page.getBoxRect(.mediaBox))
    }
    var body: some View {
        GroupBox("Firma grafica PAdES") {
            VStack(alignment:.leading, spacing:8) {
                HStack {
                    Toggle("Mostra firma nel PDF",isOn:editing(\.visible))
                    Spacer()
                    Picker("Pagina", selection:editing(\.pageIndex)) {
                        ForEach(0..<max(1,pdfDocument?.pageCount ?? 0),id:\.self) { Text("\($0+1)").tag($0) }
                    }.frame(width:150)
                }
                if configuration.visible {
                    HStack {
                        Toggle("Nome dal certificato",isOn:editing(\.showSigner))
                        Toggle("Firmato digitalmente",isOn:editing(\.showLabel))
                        Toggle("Data locale",isOn:Binding(get:{configuration.localDate != nil},set:{previewReady(snapshot.identity.id,false); configuration.localDate = $0 ? Date() : nil}))
                    }.font(.caption)
                    TextField("Testo personalizzato (distinto dall'identità del certificato)",text:editing(\.customText)).textFieldStyle(.roundedBorder)
                    HStack {
                        Button("PNG o JPEG…") { chooseImage() }
                        if configuration.image != nil { Button("Rimuovi immagine") { previewReady(snapshot.identity.id,false); configuration.image = nil } }
                        Picker("Allineamento",selection:editing(\.alignment)) {
                            Text("Sinistra").tag(PAdESAppearanceConfiguration.Alignment.leading)
                            Text("Centro").tag(PAdESAppearanceConfiguration.Alignment.center)
                            Text("Destra").tag(PAdESAppearanceConfiguration.Alignment.trailing)
                        }.frame(width:180)
                        Stepper("Testo \(Int(configuration.fontSize)) pt",value:editing(\.fontSize),in:7...18)
                    }
                    HStack {
                        Stepper("Larghezza \(Int(configuration.rectangle.width)) pt",value:Binding(get:{configuration.rectangle.width},set:{previewReady(snapshot.identity.id,false); configuration.rectangle.size.width=$0}),in:80...800,step:5)
                        Stepper("Altezza \(Int(configuration.rectangle.height)) pt",value:Binding(get:{configuration.rectangle.height},set:{previewReady(snapshot.identity.id,false); configuration.rectangle.size.height=$0}),in:40...500,step:5)
                    }.font(.caption)
                }
                if rendering { ProgressView("Preparazione appearance…").controlSize(.small) }
                if !issue.isEmpty { Label(issue, systemImage:"exclamationmark.triangle").foregroundStyle(.orange).textSelection(.enabled) }
                else if !rendering, let rendered {
                    Text(rendered.configuration.visible ? (annotationReady ? "Anteprima pronta" : "Preparazione annotazione…") : "Firma invisibile: nessun timbro previsto.")
                        .font(.caption)
                }
                if let pdfDocument {
                    AppearancePDFView(document:pdfDocument, page:configuration.pageIndex, appearance:rendered,
                        choose:{ index,point,resize in choose(index,point,resize) }, displayed: { identity, error in
                            guard !rendering, rendered?.approvalIdentity == identity else { return }
                            annotationReady = error == nil
                            issue = error ?? ""
                            previewReady(snapshot.identity.id, error == nil)
                        })
                        .frame(minHeight:300,maxHeight:.infinity)
                        .clipShape(RoundedRectangle(cornerRadius:6))
                }
                Text(configuration.visible ? "Clic/trascina per posizionare. Option+trascina per ridimensionare. L'anteprima usa le stesse risorse incorporate nel PDF finale." : "Firma invisibile: nessuna immagine, firma crittografica presente.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("L'aspetto grafico non prova l'integrità. La data locale non è una marca temporale qualificata.").font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
        .onAppear {
            pdfDocument = PDFDocument(data:snapshot.approvedBytes)
            if let saved = placement?.appearance { configuration = saved.configuration }
            else {
                configuration.visible = false
                configuration.showSigner = UserDefaults.standard.object(forKey:"signum.appearance.signer") as? Bool ?? true
                configuration.showLabel = true
            }
            resetRectangleIfNeeded(); render()
        }
        .onChange(of:configuration) { _ in render() }
        .onChange(of:certificateDER) { _ in render() }
        .onDisappear { renderID = UUID(); renderTask?.cancel() }
    }
    private func editing<T>(_ path:WritableKeyPath<PAdESAppearanceConfiguration,T>)->Binding<T> {
        Binding(get:{configuration[keyPath:path]},set:{previewReady(snapshot.identity.id,false); configuration[keyPath:path]=$0})
    }
    private func resetRectangleIfNeeded() { if !crop.contains(configuration.rectangle) { resetRectangle() } }
    private func resetRectangle() {
        configuration.rectangle = CGRect(x:crop.minX+min(20,crop.width/10),y:crop.minY+min(20,crop.height/10),width:min(240,crop.width-40),height:min(100,crop.height-40))
    }
    private func choose(_ index:Int,_ point:CGPoint,_ resize:Bool) {
        var next = configuration
        next.pageIndex = index
        let r = next.rectangle
        if resize {
            next.rectangle.size = CGSize(width:min(max(80,point.x-r.minX),min(800,crop.maxX-r.minX)),height:min(max(40,point.y-r.minY),min(500,crop.maxY-r.minY)))
        } else {
            next.rectangle.origin = CGPoint(x:min(max(point.x-r.width/2,crop.minX),crop.maxX-r.width),y:min(max(point.y-r.height/2,crop.minY),crop.maxY-r.height))
        }
        guard next != configuration else { return }
        renderTask?.cancel(); renderID = UUID()
        previewReady(snapshot.identity.id,false)
        configuration = next
    }
    private func render() {
        renderTask?.cancel(); renderID = UUID(); annotationReady = false
        guard let pdfDocument, !pdfDocument.isEncrypted, pdfDocument.pageCount > configuration.pageIndex, !crop.isEmpty else {
            issue="PDF non disponibile o protetto."; rendered=nil; rendering=false; previewReady(snapshot.identity.id,false); return
        }
        renderTask?.cancel()
        let id=UUID(); renderID=id; rendering=true; issue=""; previewReady(snapshot.identity.id,false)
        let config=configuration, der=certificateDER ?? Data(), bounds=crop
        renderTask = Task { @MainActor in
            let result:Result<RenderedPAdESAppearance,Error>
            do { result = .success(try await AppearanceRenderWorker.shared.render(config,der:der,crop:bounds)) }
            catch { result = .failure(error) }
            guard renderID == id, !Task.isCancelled else { return }; rendering=false
            switch result {
            case .success(let value): rendered=value; issue=""; placement = PAdESPlacement(pageIndex:config.pageIndex,rectangle:config.rectangle,appearance:value)
            case .failure(let error): issue=error.localizedDescription; rendered=nil; previewReady(snapshot.identity.id,false)
            }
        }
    }
    private func chooseImage() {
        let chooser=NSOpenPanel(); chooser.allowedContentTypes=[.png,.jpeg]; chooser.allowsMultipleSelection=false
        guard chooser.runModal() == .OK, let url=chooser.url else { return }
        do { let image = try PAdESAppearanceImage.load(url); previewReady(snapshot.identity.id,false); configuration.image = image } catch { issue=error.localizedDescription }
    }
}

final class AppearancePDFAnnotation: PDFAnnotation {
    private let artwork: CGPDFDocument
    init?(appearance:RenderedPAdESAppearance) {
        guard let source=CGDataProvider(data:appearance.pdf as CFData), let pdf=CGPDFDocument(source), pdf.numberOfPages == 1 else { return nil }
        artwork = pdf
        super.init(bounds:appearance.configuration.rectangle,forType:.stamp,withProperties:nil)
    }
    required init?(coder:NSCoder) { nil }
    override func draw(with box:PDFDisplayBox,in context:CGContext) {
        guard let page=artwork.page(at:1) else { return }
        context.saveGState()
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

private struct AppearancePDFView:NSViewRepresentable {
    let document:PDFDocument, page:Int, appearance:RenderedPAdESAppearance?
    let choose:(Int,CGPoint,Bool)->Void
    let displayed:(String,String?)->Void
    final class Coordinator { var reported: String? }
    func makeCoordinator()->Coordinator { Coordinator() }
    func makeNSView(context:Context)->PlacementPDFView {
        PlacementPDFView()
    }
    func updateNSView(_ v:PlacementPDFView,context:Context) {
        v.install(document:document,pageIndex:page)
        v.onChoose = { p,point in choose(document.index(for:p),point,false) }
        v.onResize = { p,point in choose(document.index(for:p),point,true) }
        let error = v.updateAppearance(appearance)
        if let identity = appearance?.approvalIdentity {
            let result = identity + "|" + (error ?? "ready")
            if context.coordinator.reported != result {
                context.coordinator.reported = result
                DispatchQueue.main.async { displayed(identity,error) }
            }
        }
    }
}
final class PlacementPDFView: PDFView {
    var previewAnnotation: PDFAnnotation?
    var currentPreviewPlacement: PAdESPlacement?
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
    var onResize: ((PDFPage, CGPoint) -> Void)?
    var onChoose: ((PDFPage, CGPoint) -> Void)?

    override func mouseDown(with event: NSEvent) {
        choose(event)
    }

    override func mouseDragged(with event: NSEvent) {
        choose(event)
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
        if let old=previewAnnotation { old.page?.removeAnnotation(old); previewAnnotation=nil }
        renderedIdentity = value?.approvalIdentity
        guard let value, value.configuration.visible else { return nil }
        guard let page=document?.page(at:value.configuration.pageIndex) else {
            appearanceIssue = "Pagina dell’anteprima non disponibile."; return appearanceIssue
        }
        guard let annotation=AppearancePDFAnnotation(appearance:value) else {
            appearanceIssue = "Annotazione grafica non costruita. Modifica l’aspetto o riseleziona il documento."
            return appearanceIssue
        }
        page.addAnnotation(annotation); previewAnnotation=annotation
        return nil
    }
    func updatePreview(_ placement: PAdESPlacement?, name: String, visible: Bool) {
        if currentPreviewPlacement != placement || currentPreviewName != name || currentPreviewVisible != visible {
            setPreview(placement, name: name, visible: visible)
        }
    }

    private func setPreview(_ placement: PAdESPlacement?, name: String, visible: Bool) {
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
