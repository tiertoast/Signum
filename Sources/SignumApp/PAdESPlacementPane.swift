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
    var draft: PAdESAppearanceConfiguration? = nil
}

struct PAdESPlacementPane: View {
    let snapshot: DocumentSnapshot
    let previewReady: (UUID, Bool) -> Void
    let holder: String
    var certificateDER: Data? = nil
    @Binding var placement: PAdESPlacement?
    @State private var configuration = PAdESAppearanceConfiguration()
    @State private var imageURL: URL?
    @State private var pdfDocument: PDFDocument?
    @State private var rendered: RenderedPAdESAppearance?
    @State private var issue = ""
    @State private var renderID = UUID()
    @State private var rendering = false
    @State private var annotationReady = false
    @State private var renderedDER: Data?
    @State private var isPlacing = false
    @State private var isActive = false
    @State private var initializationIssue: String?
    @StateObject private var renderCoordinator = PAdESRenderCoordinator()
    init(snapshot:DocumentSnapshot, previewReady:@escaping (UUID,Bool)->Void, holder:String,
         certificateDER:Data? = nil, placement:Binding<PAdESPlacement?>,
         renderCoordinator:PAdESRenderCoordinator? = nil) {
        self.snapshot = snapshot; self.previewReady = previewReady; self.holder = holder
        self.certificateDER = certificateDER; _placement = placement
        _renderCoordinator = StateObject(wrappedValue:renderCoordinator ?? PAdESRenderCoordinator())
    }
    private var crop: CGRect { crop(for:configuration.pageIndex) }
    private func crop(for index:Int)->CGRect {
        guard let page = pdfDocument?.page(at:index)?.pageRef else { return .zero }
        return page.getBoxRect(.cropBox).intersection(page.getBoxRect(.mediaBox))
    }
    private func rotation(for index:Int)->Int { Int(pdfDocument?.page(at:index)?.pageRef?.rotationAngle ?? 0) }
    private func geometry(for index:Int) throws -> PAdESPageGeometry {
        guard let page=pdfDocument?.page(at:index)?.pageRef else {throw SignumError.module("Pagina PDF non disponibile.")}
        return try PAdESPageGeometry(page:page)
    }
    private var contentSize:CGSize {
        let raw=(try? configuration.contentSize(pageRotation:rotation(for:configuration.pageIndex))) ?? configuration.rectangle.size
        return CGSize(width:raw.width*configuration.effectiveUserUnit,height:raw.height*configuration.effectiveUserUnit)
    }
    var body: some View {
        GroupBox("Firma grafica PAdES") {
            VStack(alignment:.leading, spacing:8) {
                HStack {
                    Spacer()
                    Picker("Pagina", selection:editing(\.pageIndex)) {
                        ForEach(0..<max(1,pdfDocument?.pageCount ?? 0),id:\.self) { Text("\($0+1)").tag($0) }
                    }.frame(width:150)
                }
                if configuration.visible {
                    HStack {
                        Picker("Orientamento",selection:editing(\.orientation)) {
                            ForEach(PAdESAppearanceOrientation.allCases,id:\.self) { Text($0.title).tag($0) }
                        }.frame(width:240)
                        Text("Angoli in senso orario rispetto alla lettura sullo schermo.").font(.caption).foregroundStyle(.secondary)
                    }
                    HStack {
                        Toggle("Nome dal certificato",isOn:editing(\.showSigner))
                        Toggle("Firmato digitalmente",isOn:editing(\.showLabel))
                        Toggle("Data locale",isOn:Binding(get:{configuration.localDate != nil},set:{ value in change { $0.localDate = value ? Date() : nil } }))
                    }.font(.caption)
                    TextField("Testo personalizzato (distinto dall'identità del certificato)",text:editing(\.customText)).textFieldStyle(.roundedBorder)
                    HStack {
                        Button("PNG o JPEG…") { chooseImage() }
                        if configuration.image != nil { Button("Rimuovi immagine") { imageURL=nil; change { $0.image = nil } } }
                        Picker("Allineamento",selection:editing(\.alignment)) {
                            Text("Sinistra").tag(PAdESAppearanceConfiguration.Alignment.leading)
                            Text("Centro").tag(PAdESAppearanceConfiguration.Alignment.center)
                            Text("Destra").tag(PAdESAppearanceConfiguration.Alignment.trailing)
                        }.frame(width:180)
                        Stepper("Testo \(Int(configuration.fontSize)) pt",value:editing(\.fontSize),in:7...18)
                    }
                    HStack {
                        Stepper("Larghezza \(Int(contentSize.width)) pt",value:Binding(get:{contentSize.width},set:{ value in resizeContent(width:value,height:contentSize.height) }),in:80...800,step:5)
                        Stepper("Altezza \(Int(contentSize.height)) pt",value:Binding(get:{contentSize.height},set:{ value in resizeContent(width:contentSize.width,height:value) }),in:40...500,step:5)
                    }.font(.caption)
                }
                if certificateDER == nil {
                    Text("Anteprima senza certificato: il nome sarà aggiornato quando scegli un certificato. La firma richiede un certificato idoneo.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if rendering { ProgressView("Preparazione appearance…").controlSize(.small) }
                if !issue.isEmpty { Label(issue, systemImage:"exclamationmark.triangle").foregroundStyle(.orange).textSelection(.enabled) }
                else if !rendering, let rendered {
                    Text(rendered.configuration.visible ? (annotationReady ? "Anteprima pronta" : "Preparazione anteprima…") : "Firma invisibile: nessun timbro previsto.")
                        .font(.caption)
                }
                if let pdfDocument {
                    AppearancePDFView(document:pdfDocument, page:configuration.pageIndex, appearance:rendered,
                        choose:{ index,point,resize in choose(index,point,resize) }, interaction: { active in
                            isPlacing = active
                            if active { previewReady(snapshot.identity.id,false) }
                            else if annotationReady, !rendering, issue.isEmpty { previewReady(snapshot.identity.id,true) }
                        }, displayed: { identity, error in
                            guard isActive, !rendering, rendered?.approvalIdentity == identity else { return }
                            annotationReady = error == nil
                            issue = error ?? ""
                            previewReady(snapshot.identity.id, error == nil && !isPlacing)
                        })
                        .frame(minHeight:300,maxHeight:.infinity)
                        .clipShape(RoundedRectangle(cornerRadius:6))
                }
                Text(configuration.visible ? "Clic/trascina per posizionare. Option+trascina per ridimensionare. L'anteprima usa le stesse risorse incorporate nel PDF finale." : "Firma invisibile: nessuna immagine, firma crittografica presente.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("L'aspetto grafico non prova l'integrità. La data locale non è una marca temporale qualificata.").font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
        .task(id: snapshot.identity.id) {
            isActive = true
            previewReady(snapshot.identity.id,false)
            do {
                let prepared = try await PDFPreviewPreparation.document(snapshot)
                try Task.checkCancellation()
                // PDFKit object construction and all later viewer access stay MainActor-bound.
                pdfDocument = PDFDocument(data:prepared.bytes)
            } catch {
                if !Task.isCancelled { initializationIssue=error.localizedDescription; render() }
                return
            }
            if let saved = placement?.draft ?? placement?.appearance?.configuration {
                configuration = saved
                configuration.visible = true
                // Migrate only metadata for an existing geometry; never reposition it.
                if configuration.userUnit == nil { configuration.userUnit = try? geometry(for:configuration.pageIndex).userUnit }
            } else {
                do {
                    configuration = try geometry(for:0).defaultAppearance()
                    configuration.showSigner = UserDefaults.standard.object(forKey:"signum.appearance.signer") as? Bool ?? true
                } catch { initializationIssue=error.localizedDescription }
            }
            render()
        }
        .task(id: imageURL) {
            guard let url = imageURL else { return }
            do {
                let image = try await PDFPreviewPreparation.image(url)
                try Task.checkCancellation()
                guard isActive, imageURL == url else { return }
                imageURL = nil
                change { $0.image = image }
            } catch { if !Task.isCancelled, isActive, imageURL == url { imageURL=nil; rendering=false; issue=error.localizedDescription } }
        }
        .onChange(of:configuration) { _ in render() }
        .onChange(of:certificateDER) { _ in render() }
        .onDisappear { isActive = false; renderID = UUID(); renderCoordinator.cancel() }
    }
    private func change(_ mutation:(inout PAdESAppearanceConfiguration)->Void) {
        var next = configuration; mutation(&next)
        guard next != configuration else { return }
        renderCoordinator.cancel(); renderID = UUID(); annotationReady = false
        previewReady(snapshot.identity.id,false)
        if next.pageIndex != configuration.pageIndex || next.orientation != configuration.orientation {
            do {
                let source=configuration
                let target=try geometry(for:next.pageIndex)
                let size=try source.contentSize(pageRotation:rotation(for:source.pageIndex))
                var base=source; base.orientation=next.orientation; base.userUnit=target.userUnit
                var oriented=try base.resized(contentSize:CGSize(width:size.width*source.effectiveUserUnit/target.userUnit,
                    height:size.height*source.effectiveUserUnit/target.userUnit),pageRotation:target.rotation,cropBox:target.cropBox)
                oriented.pageIndex=next.pageIndex
                next=oriented
            } catch { rejectEdit(error); return }
        }
        initializationIssue = nil
        // Persist edits immediately, before asynchronous rendering. A late result
        // cannot restore earlier geometry or mark this new draft ready.
        placement = PAdESPlacement(pageIndex:next.pageIndex,rectangle:next.rectangle,draft:next)
        configuration = next
    }
    private func editing<T>(_ path:WritableKeyPath<PAdESAppearanceConfiguration,T>)->Binding<T> {
        Binding(get:{configuration[keyPath:path]},set:{ value in change { $0[keyPath:path] = value } })
    }
    private func resizeContent(width:CGFloat,height:CGFloat) {
        do {
            let next=try configuration.resized(contentSize:CGSize(width:width/configuration.effectiveUserUnit,height:height/configuration.effectiveUserUnit),
                pageRotation:rotation(for:configuration.pageIndex),cropBox:crop)
            change {$0=next}
        } catch { rejectEdit(error) }
    }
    private func rejectEdit(_ error:Error) {
        renderCoordinator.cancel();renderID=UUID();annotationReady=false;rendering=false
        previewReady(snapshot.identity.id,false);issue=error.localizedDescription
    }
    private func choose(_ index:Int,_ point:CGPoint,_ resize:Bool) {
        var next = configuration
        next.pageIndex = index
        let r = next.rectangle, crop = crop(for:index)
        if resize {
            do { next=try next.resized(toward:point,pageRotation:rotation(for:index),cropBox:crop) }
            catch { rejectEdit(error);return }
        } else {
            next.rectangle.origin = CGPoint(x:min(max(point.x-r.width/2,crop.minX),crop.maxX-r.width),y:min(max(point.y-r.height/2,crop.minY),crop.maxY-r.height))
        }
        change { $0 = next }
    }
    private func render() {
        renderCoordinator.cancel(); renderID = UUID(); annotationReady = false
        guard imageURL == nil else { rendering=true; previewReady(snapshot.identity.id,false); return }
        if let initializationIssue {
            issue=initializationIssue; rendered=nil; rendering=false; previewReady(snapshot.identity.id,false); return
        }
        guard let pdfDocument, !pdfDocument.isEncrypted, pdfDocument.pageCount > configuration.pageIndex, !crop.isEmpty else {
            issue="PDF non disponibile o protetto."; rendered=nil; rendering=false; previewReady(snapshot.identity.id,false); return
        }
        renderCoordinator.cancel()
        let id=UUID(); renderID=id; rendering=true; issue=""; previewReady(snapshot.identity.id,false)
        var config=configuration
        // A certificate-free preview has no invented signer identity. The desired
        // showSigner preference stays in the draft and is reapplied when DER arrives.
        if certificateDER == nil { config.showSigner=false }
        let der=certificateDER ?? Data(), bounds=crop, pageRotation=rotation(for:configuration.pageIndex)
        let draft=configuration
        placement = PAdESPlacement(pageIndex:config.pageIndex,rectangle:config.rectangle,draft:draft)
        do {
            guard try geometry(for:config.pageIndex).userUnit == config.effectiveUserUnit else {
                throw SignumError.module("UserUnit della pagina diverso dalla configurazione del timbro.")
            }
        } catch { issue=error.localizedDescription;rendered=nil;rendering=false;return }
        if let previous = rendered, renderedDER == der, previous.configuration.hasSameArtwork(as: config), (previous.pageRotation ?? 0) == pageRotation {
            do {
                let value = try previous.placed(config,cropBox:bounds)
                rendered = value; rendering = false
                placement = PAdESPlacement(pageIndex:config.pageIndex,rectangle:config.rectangle,appearance:value,draft:draft)
            } catch { issue=error.localizedDescription; rendered=nil; rendering=false }
            return
        }
        do { try config.validate(cropBox:bounds,pageRotation:pageRotation) }
        catch { issue="Posizionamento non valido: " + error.localizedDescription; rendered=nil; rendering=false; return }
        renderCoordinator.submit(config,der:der,crop:bounds,pageRotation:pageRotation,previous:rendered) { result in
            guard isActive, renderID == id else { return }; rendering=false
            switch result {
            case .success(let value): rendered=value; renderedDER=der; issue=""; placement = PAdESPlacement(pageIndex:config.pageIndex,rectangle:config.rectangle,appearance:value,draft:draft)
            case .failure(let error): issue=error.localizedDescription; rendered=nil; previewReady(snapshot.identity.id,false)
            }
        }
    }
    private func chooseImage() {
        let chooser=NSOpenPanel(); chooser.allowedContentTypes=[.png,.jpeg]; chooser.allowsMultipleSelection=false
        guard chooser.runModal() == .OK, let url=chooser.url else { return }
        renderCoordinator.cancel(); renderID=UUID(); annotationReady=false; rendering=true
        previewReady(snapshot.identity.id,false)
        imageURL = url
    }
}

final class AppearancePDFAnnotation: PDFAnnotation {
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

private struct AppearancePDFView:NSViewRepresentable {
    let document:PDFDocument, page:Int, appearance:RenderedPAdESAppearance?
    let choose:(Int,CGPoint,Bool)->Void
    let interaction:(Bool)->Void
    let displayed:(String,String?)->Void
    final class Coordinator { var reported: String? }
    func makeCoordinator()->Coordinator { Coordinator() }
    func makeNSView(context:Context)->PlacementPDFView {
        PlacementPDFView()
    }
    func updateNSView(_ v:PlacementPDFView,context:Context) {
        v.install(document:document,pageIndex:page)
        v.onInteraction = interaction
        v.onChoose = { p,point in choose(document.index(for:p),point,false) }
        v.onResize = { p,point in choose(document.index(for:p),point,true) }
        v.signatureOverlay.displayed = { identity, error in
            let result = identity + "|" + (error ?? "ready")
            if context.coordinator.reported != result {
                context.coordinator.reported = result
                DispatchQueue.main.async { displayed(identity,error) }
            }
        }
        v.updatePlacementOverlay(appearance)
    }
}
final class PlacementPDFView: PDFView {
    let signatureOverlay = SignaturePlacementOverlay()
    @discardableResult func updatePlacementOverlay(_ value: RenderedPAdESAppearance?) -> String? {
        if signatureOverlay.superview == nil {
            signatureOverlay.viewer = self
            addSubview(signatureOverlay, positioned:.above, relativeTo:nil)
        }
        return signatureOverlay.update(value)
    }
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
            signatureOverlay.clear()
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
        defer { signatureOverlay.updateGeometry() }
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
           let old=previewAnnotation as? AppearancePDFAnnotation, old.artworkID == value.artworkID {
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
        guard let annotation=AppearancePDFAnnotation(appearance:value) else {
            appearanceIssue = "Annotazione grafica non costruita. Modifica l’aspetto o riseleziona il documento."
            return appearanceIssue
        }
        appearanceBuildCount += 1
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
