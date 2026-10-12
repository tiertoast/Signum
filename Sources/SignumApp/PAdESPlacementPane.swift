#if os(macOS)
import SwiftUI
import AppKit
import PDFKit

/// Coordinates are PDF page space (points, origin bottom-left), NOT view pixels.
/// They can be passed to the eventual PoDoFo signature widget.
struct PAdESPlacement: Equatable {
    let pageIndex: Int
    let rectangle: CGRect
}

/// PDFKit is used exclusively for preview and interactive field placement.
/// NEVER save PDFKit's temporary annotation as though it were a PAdES signature.
struct PAdESPlacementPane: View {
    let fileURL: URL
    let holder: String
    @Binding var placement: PAdESPlacement?
    @State private var page = 0
    @State private var visible = true
    @State private var pdfDocument: PDFDocument?
    @AppStorage("signum.appearance.style") private var style = GraphicStyle.imageAndText.rawValue
    @AppStorage("signum.appearance.image") private var imagePath = ""
    @AppStorage("signum.appearance.date") private var showDate = true

    private var pageCount: Int { pdfDocument?.pageCount ?? 0 }

    var body: some View {
        GroupBox("Firma grafica — posizionamento PDF") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Toggle("Mostra firma nel PDF", isOn: $visible)
                    Spacer()
                    Text("Pagina")
                    Picker("Pagina", selection: $page) {
                        ForEach(0..<max(1, pageCount), id: \.self) { index in
                            Text("\(index + 1)").tag(index)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 85)
                    .disabled(pageCount == 0)
                }
                if let pdfDocument, pageCount > 0 {
                    SignaturePlacementPDFView(
                        document: pdfDocument, selectedPage: $page,
                        placement: $placement, holder: holder,
                        visible: visible
                    )
                    .frame(height: 255)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))
                    Text(visible
                         ? "Clicca o trascina sul PDF per posizionare il riquadro di firma. Usa il menu pagina per spostarti."
                         : "Firma invisibile: nessun riquadro grafico, ma la firma crittografica sarà presente.")
                        .font(.caption).foregroundStyle(.secondary)
                    if visible {
                        HStack {
                            Text("Aspetto selezionato:")
                                .font(.caption).foregroundStyle(.secondary)
                            SignumGraphicAppearancePreview(
                                fullName: holder,
                                style: style,
                                imagePath: imagePath,
                                showDate: showDate
                            )
                            .frame(height: 85)
                            Spacer()
                        }
                    }
                    if let placement, visible {
                        Text("Pagina \(placement.pageIndex + 1) · x \(Int(placement.rectangle.minX)), y \(Int(placement.rectangle.minY)) · \(Int(placement.rectangle.width)) × \(Int(placement.rectangle.height)) pt")
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                } else {
                    Text("Impossibile aprire il PDF. Seleziona un documento valido e non protetto.")
                        .foregroundStyle(.orange)
                }
                Text("Solo anteprima. La creazione effettiva della firma PAdES sarà disponibile dopo il collaudo del motore PDF.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(5)
        }
        .onAppear { pdfDocument = PDFDocument(url: fileURL) }
        .onChange(of: fileURL) { _ in
            page = 0
            placement = nil
            pdfDocument = PDFDocument(url: fileURL)
        }
        .onChange(of: visible) { newValue in if !newValue { placement = nil } }
    }
}

private final class PlacementPDFView: PDFView {
    var previewAnnotation: PDFAnnotation?
    var currentPreviewPlacement: PAdESPlacement?
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
        onChoose?(page, convert(point, to: page))
    }

    func setPreview(_ placement: PAdESPlacement?, name: String, visible: Bool) {
        if let old = previewAnnotation {
            old.page?.removeAnnotation(old)
            previewAnnotation = nil
        }
        currentPreviewPlacement = placement
        guard visible, let placement, let page = document?.page(at: placement.pageIndex) else { return }
        let annotation = PDFAnnotation(bounds: placement.rectangle, forType: .freeText, withProperties: nil)
        annotation.contents = "Firmato digitalmente da\n" + name
        annotation.font = NSFont.systemFont(ofSize: 10)
        annotation.fontColor = NSColor.labelColor
        annotation.color = NSColor.systemBlue.withAlphaComponent(0.14)
        annotation.border = PDFBorder()
        annotation.border?.lineWidth = 1
        page.addAnnotation(annotation)
        previewAnnotation = annotation
    }
}

private struct SignaturePlacementPDFView: NSViewRepresentable {
    let document: PDFDocument
    @Binding var selectedPage: Int
    @Binding var placement: PAdESPlacement?
    let holder: String
    let visible: Bool

    func makeNSView(context: Context) -> PlacementPDFView {
        let viewer = PlacementPDFView()
        viewer.autoScales = true
        viewer.displayMode = .singlePageContinuous
        viewer.backgroundColor = NSColor.windowBackgroundColor
        viewer.displaysPageBreaks = true
        return viewer
    }

    func updateNSView(_ viewer: PlacementPDFView, context: Context) {
        context.coordinator.parent = self
        if viewer.document !== document {
            viewer.document = document
            viewer.autoScales = true
            viewer.previewAnnotation = nil
            viewer.currentPreviewPlacement = nil
        }

        viewer.onChoose = { [weak viewer] page, point in
            guard let viewer, self.visible, let document = viewer.document else { return }
            let index = document.index(for: page)
            guard index != NSNotFound else { return }
            let crop = page.bounds(for: .cropBox)
            let width = min(190.0, crop.width)
            let height = min(62.0, crop.height)
            guard width > 0, height > 0 else { return }
            let x = min(max(point.x - width / 2, crop.minX), crop.maxX - width)
            let y = min(max(point.y - height / 2, crop.minY), crop.maxY - height)
            let selected = PAdESPlacement(
                pageIndex: index,
                rectangle: CGRect(x: x, y: y, width: width, height: height)
            )
            DispatchQueue.main.async {
                self.selectedPage = index
                self.placement = selected
            }
        }

        if let doc = viewer.document,
           let selected = doc.page(at: selectedPage), viewer.currentPage !== selected {
            viewer.go(to: selected)
        }
        if viewer.currentPreviewPlacement != placement || !visible && viewer.previewAnnotation != nil {
            viewer.setPreview(placement, name: holder, visible: visible)
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    final class Coordinator {
        var parent: SignaturePlacementPDFView
        init(parent: SignaturePlacementPDFView) { self.parent = parent }
    }
}
#endif
