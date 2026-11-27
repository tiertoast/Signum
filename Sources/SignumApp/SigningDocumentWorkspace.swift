#if os(macOS)
import SwiftUI
import AppKit
import PDFKit
import UniformTypeIdentifiers
import SignumCore

extension SignumWindow {
    var documentWorkspace: some View {
        VStack(spacing: 0) {
            if !batch.documents.isEmpty {
                HStack {
                    Text("Documenti").font(.headline)
                    Spacer()
                    Button(action: chooseFile) { Image(systemName: "plus") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Aggiungi documenti")
                        .accessibilityIdentifier("signum.add-more-documents")
                        .help("Aggiungi altri documenti")
                        .disabled(interfaceLocked || batch.isFrozen)
                }.padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 4)
                List(selection: Binding<UUID?>(get: { selectedDocument?.id }, set: { id in
                    guard !batch.isRunning, !interaction.isSubmittingPIN else { return }
                    showDocument(id)
                })) {
                    ForEach(batch.documents) { entry in
                        HStack(spacing: 8) {
                            Image(systemName: BatchWorkspaceSummary.symbol(entry.state))
                            Text(entry.snapshot.originalURL.lastPathComponent).lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 4)
                            Text(BatchWorkspaceSummary.status(entry.state)).font(.caption).foregroundStyle(.secondary)
                            SessionRemovalButton(name: entry.snapshot.originalURL.lastPathComponent,
                                disabled: !canRemoveSessionDocuments || !batch.canRemove(entry.id)) { removeSessionDocument(entry.id) }
                        }.accessibilityElement(children: .contain)
                            .accessibilityAction(named: Text("Rimuovi dalla sessione")) {
                                withAnimation(NSWorkspace.shared.accessibilityDisplayShouldReduceMotion ? nil : .default) {
                                    removeSessionDocument(entry.id)
                                }
                            }
                            .padding(.horizontal, 12).tag(entry.id).help(entry.snapshot.originalURL.lastPathComponent + (entry.result.isEmpty ? "" : "\n" + entry.result))
                    }
                }.listStyle(.plain)
                    .frame(height: CGFloat(min(batch.documents.count, 3) * 30 + 8))
                    .accessibilityIdentifier("signum.document-list")
                Divider()
                if let entry = selectedDocument {
                    let destination = displayedDestination(for: entry)
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(destination.final ? "Destinazione" : "Destinazione prevista")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button("Esito e dettagli…") { showingDocumentDetails = true }
                                .buttonStyle(.borderless)
                                .popover(isPresented: $showingDocumentDetails) {
                                    ScrollView { documentRow(entry).padding(16) }.frame(width: 440, height: 280)
                                }
                            if entry.format == .pades {
                                Button(workspace.showingPDFPreview ? "Conferma anteprima" : "Modifica aspetto…") {
                                    if workspace.showingPDFPreview { stamps.confirmStamp(entry.id, in: batch.documents) }
                                    workspace.showingPDFPreview.toggle()
                                }.disabled(interfaceLocked || batch.isFrozen || (workspace.showingPDFPreview && !stamps.isConfirmed(entry.id)))
                            }
                        }
                        Text(verbatim: destination.url?.path ?? "Scegli la cartella di destinazione nell’inspector.")
                            .font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                            .accessibilityIdentifier("signum.document-output-path")
                    }.padding(.horizontal, 16).padding(.vertical, 10)
                    if entry.format == .pades && workspace.showingPDFPreview {
                        ScrollView { pdfWorkspace.frame(minHeight: 540) }
                    } else if DocumentSigningConfiguration.canSelectPAdES(for: entry.snapshot) {
                        ReadOnlyDocumentPreview(snapshot: entry.snapshot,
                            appearance: entry.format == .pades ? stamps.confirmedAppearance(entry.id) : nil).id(entry.id)
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "doc.text").font(.system(size: 44)).foregroundStyle(.secondary)
                            Text("Anteprima non disponibile per questo documento.")
                                .font(.callout).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding()
                    }
                }
                if !results.receipts.isEmpty {
                    DisclosureGroup("Attività recenti") { SigningReceiptsView(receipts: results.receipts, clear: results.clear, retryEnabled: canRetryCancelled, retry: retryCancelled).transition(.opacity).frame(height: 180) }.padding(12)
                }
            } else {
                if !results.receipts.isEmpty {
                    SigningReceiptsView(receipts: results.receipts, clear: results.clear, retryEnabled: canRetryCancelled, retry: retryCancelled).transition(.opacity)
                }
                if results.receipts.isEmpty { Spacer(minLength: 0) }
                SignumEmptyDocumentsView(choose: chooseFile).padding(22)
                if results.receipts.isEmpty { Spacer(minLength: 0) }
            }
            if !batch.selectionIssues.isEmpty {
                Text(batch.selectionIssues.joined(separator: "\n")).font(.caption).padding(12).textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(dropTargeted ? SignumAppearance.burgundy : .clear, lineWidth: 2))
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $dropTargeted, perform: receiveDrop)
    }
}

struct SigningReceiptsView: View {
    let receipts: [SigningReceipt]
    let clear: () -> Void
    var retryEnabled = false
    var retry: (Set<UUID>) -> Void = { _ in }
    static let retryHelp = "Rilegge il file dal disco e lo rimette in lista. Prima di firmare servono di nuovo il controllo del riepilogo e il PIN."
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Label("Attività recenti", systemImage: "clock").font(.title2.weight(.semibold))
                    Spacer()
                    let retryable = Set(receipts.filter(\.canRetry).map(\.id))
                    if retryable.count > 1 {
                        Button("Riprova gli annullati") { retry(retryable) }
                            .disabled(!retryEnabled).help(Self.retryHelp)
                            .accessibilityIdentifier("signum.retry-cancelled")
                    }
                    Button("Elimina tutto") {
                        withAnimation(reduceMotion ? nil : .default) { clear() }
                    }.help("Rimuove solo l’elenco in memoria. I file rimangono sul disco.")
                        .accessibilityIdentifier("signum.clear-recent")
                }
                ForEach(receipts) { receipt in
                    VStack(alignment: .leading, spacing: 6) {
                        Label(receipt.name, systemImage: BatchWorkspaceSummary.symbol(receipt.state)).font(.headline)
                        Text(receipt.state.message + " · " + receipt.format).font(.callout)
                        if !receipt.detail.isEmpty { Text(receipt.detail).font(.caption).textSelection(.enabled) }
                        if receipt.canRetry {
                            Button("Riprova") { retry([receipt.id]) }
                                .disabled(!retryEnabled).help(Self.retryHelp)
                        }
                        if receipt.state == .completed, let output = receipt.output {
                            HStack {
                                Button("Apri file firmato") { NSWorkspace.shared.open(output) }
                                Button("Mostra nel Finder") { NSWorkspace.shared.activateFileViewerSelecting([output]) }
                            }
                        }
                    }.padding(.vertical, 6)
                    Divider()
                }
            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Verified immutable snapshot bytes; never used to approve a PAdES appearance.
struct ReadOnlyDocumentPreview: View {
    let snapshot: DocumentSnapshot
    /// Confirmed or propagated stamp, drawn read-only on its page.
    var appearance: RenderedPAdESAppearance? = nil
    @State private var bytes: Data?
    @State private var issue = ""
    var body: some View {
        Group {
            if let bytes, let appearance, appearance.configuration.visible { StampedPDFView(bytes: bytes, appearance: appearance) }
            else if let bytes { ReadOnlyPDFView(bytes: bytes) }
            else if !issue.isEmpty { Text(issue).foregroundStyle(.secondary).padding() }
            else { ProgressView("Preparazione anteprima…") }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task(id: snapshot.identity.id) {
            do {
                let prepared = try await PDFPreviewPreparation.document(snapshot)
                try Task.checkCancellation()
                bytes = prepared.bytes
            } catch is CancellationError { }
            catch { issue = error.localizedDescription }
        }
    }
}
struct ReadOnlyPDFView: NSViewRepresentable {
    let bytes: Data
    func makeCoordinator() -> PaperDocumentDelegate { PaperDocumentDelegate() }
    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true; view.displayMode = .singlePageContinuous
        let document = PDFDocument(data: bytes)
        document?.delegate = context.coordinator
        view.document = document
        return view
    }
    func updateNSView(_ view: PDFView, context: Context) { }
}
/// Read-only page with the stamp overlay used by the placement pane; no editing.
struct StampedPDFView: NSViewRepresentable {
    let bytes: Data
    let appearance: RenderedPAdESAppearance
    final class Coordinator { var document: PDFDocument?; let delegate = PaperDocumentDelegate() }
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> PlacementPDFView {
        let document = PDFDocument(data: bytes)
        document?.delegate = context.coordinator.delegate
        context.coordinator.document = document
        return PlacementPDFView()
    }
    func updateNSView(_ view: PlacementPDFView, context: Context) {
        guard let document = context.coordinator.document else { return }
        view.install(document: document, pageIndex: appearance.configuration.pageIndex)
        view.updatePlacementOverlay(appearance)
    }
}
/// Set the PDF initial graphics state explicitly, independent of semantic UI
/// colors. Explicit colors and annotations remain rendered by PDFKit.
final class PaperPDFPage: PDFPage {
    override func draw(with box: PDFDisplayBox, to context: CGContext) {
        context.saveGState()
        context.setFillColor(CGColor(gray: 0, alpha: 1))
        context.setStrokeColor(CGColor(gray: 0, alpha: 1))
        super.draw(with: box, to: context)
        context.restoreGState()
    }
}
final class PaperDocumentDelegate: NSObject, PDFDocumentDelegate {
    func classForPage() -> AnyClass { PaperPDFPage.self }
}
#endif
