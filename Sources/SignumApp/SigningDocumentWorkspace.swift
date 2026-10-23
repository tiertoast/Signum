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
                ScrollView(.horizontal) {
                    HStack(spacing: 8) {
                        ForEach(batch.documents) { entry in
                            Button { showDocument(entry.id) } label: {
                                Label(entry.snapshot.originalURL.lastPathComponent, systemImage: entry.id == documentSnapshot?.identity.id ? "doc.fill" : "doc")
                                    .lineLimit(1).frame(maxWidth: 210)
                                    .padding(8)
                                    .background(entry.id == documentSnapshot?.identity.id ? Color.secondary.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 7))
                            }
                            .buttonStyle(.plain)
                            .disabled(batch.isRunning || interaction.isSubmittingPIN)
                            .accessibilityAddTraits(entry.id == documentSnapshot?.identity.id ? .isSelected : [])
                        }
                    }.padding(12)
                }.frame(height: 64)
                Divider()
                if let entry = selectedDocument {
                    HStack {
                        Text(entry.snapshot.originalURL.lastPathComponent).font(.headline).lineLimit(1)
                        Spacer()
                        if entry.format == .pades {
                            Button(workspace.showingPDFPreview ? "Conferma anteprima" : "Modifica aspetto…") {
                                workspace.showingPDFPreview.toggle()
                            }.disabled(interfaceLocked || batch.isFrozen || (workspace.showingPDFPreview && !readyPreviews.contains(entry.id)))
                        }
                    }.padding(.horizontal, 16).padding(.vertical, 10)
                    if entry.format == .pades && workspace.showingPDFPreview {
                        ScrollView { pdfWorkspace.frame(minHeight: 540) }
                    } else if DocumentSigningConfiguration.canSelectPAdES(for: entry.snapshot) {
                        ReadOnlyDocumentPreview(snapshot: entry.snapshot).id(entry.id)
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "doc.text").font(.system(size: 44)).foregroundStyle(.secondary)
                            Text(entry.snapshot.originalURL.lastPathComponent).font(.headline).textSelection(.enabled)
                            Text("\(entry.format.title) · \(ByteCountFormatter.string(fromByteCount: Int64(entry.snapshot.identity.byteCount), countStyle: .file))")
                                .foregroundStyle(.secondary)
                            Text("Il contenuto non dispone di un’anteprima PDF.").font(.callout).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding()
                    }
                }
                Divider()
                DisclosureGroup("Documenti ed esiti · \(batch.documents.count)") {
                    ScrollView { VStack(alignment: .leading) { ForEach(batch.documents) { documentRow($0) } } }.frame(maxHeight: 170)
                }.padding(12)
                if !results.receipts.isEmpty {
                    DisclosureGroup("Operazioni precedenti") { SigningReceiptsView(receipts: results.receipts).frame(height: 180) }.padding(12)
                }
            } else {
                if !results.receipts.isEmpty {
                    SigningReceiptsView(receipts: results.receipts)
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
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label("Operazioni concluse", systemImage: "checkmark.circle").font(.title2.weight(.semibold))
                ForEach(receipts) { receipt in
                    VStack(alignment: .leading, spacing: 6) {
                        Label(receipt.name, systemImage: BatchWorkspaceSummary.symbol(receipt.state)).font(.headline)
                        Text(receipt.state.message + " · " + receipt.format).font(.callout)
                        if !receipt.detail.isEmpty { Text(receipt.detail).font(.caption).textSelection(.enabled) }
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
    @State private var bytes: Data?
    @State private var issue = ""
    var body: some View {
        Group {
            if let bytes { ReadOnlyPDFView(bytes: bytes) }
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
