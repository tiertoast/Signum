#if os(macOS)
import SwiftUI
import PDFKit
import AppKit
import UniformTypeIdentifiers
import SignumCore

enum VerificationDropLoader {
    static func urls(from providers: [NSItemProvider]) async -> [URL] {
        guard providers.count <= 32 else { return [] }
        var result: [URL] = []
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            let url: URL? = await withCheckedContinuation { continuation in
                provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
                    continuation.resume(returning: (value as? URL) ?? (value as? Data).flatMap { URL(dataRepresentation: $0, relativeTo: nil) })
                }
            }
            if let url, url.isFileURL { result.append(url) }
        }
        return result
    }
}

@MainActor final class VerificationWorkspace: ObservableObject {
    struct Row: Identifiable {
        let id = UUID()
        let name: String
        var report: VerificationReport?
        var issue = ""
    }
    @Published private(set) var rows: [Row] = []
    @Published private(set) var busy = false
    @Published private(set) var issue = ""
    private var operation: SigningOperation?
    typealias Verifier = @Sendable (URL, SigningOperation) throws -> VerificationReport
    func cancel() { operation?.requestCancellation() }
    func verify(_ files: [URL], using verifier: @escaping Verifier = { url, control in
        try SignumVerificationService.verify(file: url, isCancelled: { control.isCancellationRequested })
    }) async {
        guard !busy else { return }
        var seen = Set<String>()
        let urls = files.filter { $0.isFileURL && seen.insert($0.standardizedFileURL.path).inserted }
        guard !urls.isEmpty, urls.count <= 32 else { issue = "Seleziona da 1 a 32 documenti locali."; return }
        let control = SigningOperation(); operation = control; busy = true; issue = ""
        rows = urls.map { Row(name: $0.lastPathComponent) }
        defer { busy = false; operation = nil }
        var retainedPreviewBytes = 0
        for (index, url) in urls.enumerated() {
            if control.isCancellationRequested {
                for pending in index..<rows.count { rows[pending].issue = "Verifica annullata." }; break
            }
            let result = await Task.detached(priority: .userInitiated) { Result { try verifier(url, control) } }.value
            switch result {
            case .success(var report):
                let count = report.originalContent?.count ?? report.previewPDF?.count ?? 0
                if count > SigningResourceLimits.maximumSessionBytes - retainedPreviewBytes {
                    report = report.withoutPreview()
                    rows[index].issue = "Contenuto non conservato: limite memoria della sessione. Il risultato di verifica è disponibile."
                } else { retainedPreviewBytes += count }
                rows[index].report = report
            case .failure(let error): rows[index].issue = error.localizedDescription
            }
        }
    }
}

struct UnifiedVerificationPane: View {
    @StateObject private var workspace = VerificationWorkspace()
    @State private var targeted = false
    @State private var preview: VerificationReport?
    @State private var extractionIssue = ""
    @State private var exporting = false
    var body: some View {
        GroupBox("Verifica") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    VStack(alignment: .leading) {
                        Text("Apri o trascina documenti da verificare")
                        Text("Riconoscimento automatico CAdES/PAdES · nessun token o PIN · massimo 132 MiB per file")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Apri documenti…", action: choose).disabled(workspace.busy)
                    if workspace.busy { ProgressView().controlSize(.small); Button("Annulla") { workspace.cancel() } }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8).stroke(targeted ? Color.accentColor : Color.secondary.opacity(0.4), style: StrokeStyle(dash: [5,4])))
                .onDrop(of: [UTType.fileURL.identifier], isTargeted: $targeted, perform: drop)
                if !workspace.issue.isEmpty { Text(workspace.issue).font(.caption) }
                if !extractionIssue.isEmpty { Text(extractionIssue).font(.caption) }
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(workspace.rows) { row in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(row.name).font(.headline).lineLimit(2)
                                if let report = row.report {
                                    Text("\(format(report.format)) · \(report.signatures.count) firme")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Text(report.summary)
                                    if report.signatures.contains(where: \.laterChanges) {
                                        Text("Modifiche successive presenti · accettabilità non valutata").font(.caption)
                                    }
                                    if !report.issue.isEmpty { Text(report.issue).font(.caption) }
                                    DisclosureGroup("Dettagli") {
                                        VStack(alignment: .leading, spacing: 7) {
                                            Text("SHA-256: " + report.sha256).textSelection(.enabled)
                                            ForEach(report.signatures) { signature in
                                                VStack(alignment: .leading, spacing: 3) {
                                                    Text("Firma \(signature.id+1) · " + signature.integrity.description)
                                                    if let cert = signature.certificate {
                                                        Text(cert.subject); Text("Emittente: " + cert.issuer)
                                                        Text("Certificato SHA-256: " + cert.sha256).textSelection(.enabled)
                                                    } else { Text("Certificato non disponibile") }
                                                    Text("Algoritmo: " + signature.algorithm)
                                                    if !signature.declaredTime.isEmpty { Text("Data dichiarata, non qualificata: " + signature.declaredTime) }
                                                    if let end = signature.signedRevisionEnd { Text("Revisione firmata: byte 0…\(end) · " + (signature.laterChanges ? "byte successivi presenti" : "nessun byte successivo")) }
                                                    if report.format == .cades { Text("Livello CMS \(signature.cmsLayer)") }
                                                    if !signature.reason.isEmpty { Text(signature.reason) }
                                                }
                                            }
                                            if report.format == .pades { Text(VerificationReport.revisionScope) }
                                        }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                    if report.previewPDF != nil { Button("Anteprima PDF in sola lettura") { preview = report } }
                                    if report.originalContent != nil { Button("Estrai originale…") { extract(report) }.disabled(exporting || workspace.busy) }
                                } else if row.issue.isEmpty { Text(workspace.busy ? "In attesa di verifica…" : "Nessun risultato").font(.caption) }
                                if !row.issue.isEmpty { Text(row.issue).font(.caption) }
                                Divider()
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(minHeight: 180)
                Text(VerificationReport.scope).font(.caption).foregroundStyle(.secondary)
                Text("XML/XAdES: supporto futuro. Nessun file estratto viene salvato automaticamente.").font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
        .sheet(item: $preview) { report in VerificationPDFPreview(report: report) }
        .onDisappear { workspace.cancel() }
    }
    private func format(_ format: VerifiedDocumentFormat) -> String {
        switch format { case .cades: return "CAdES / CMS"; case .pades: return "PDF / PAdES"; case .xml: return "XML"; case .unknown: return "Sconosciuto" }
    }
    private func choose() {
        let chooser = NSOpenPanel(); chooser.allowsMultipleSelection = true; chooser.canChooseDirectories = false
        if chooser.runModal() == .OK { start(chooser.urls) }
    }
    private func extract(_ report: VerificationReport) {
        guard !exporting, report.integrity == .verified, let content = report.originalContent else { return }
        let chooser = NSSavePanel(); chooser.title = "Estrai il contenuto verificato"
        var name = report.documentName
        for _ in 0..<5 where name.lowercased().hasSuffix(".p7m") { name.removeLast(4) }
        chooser.nameFieldStringValue = name.isEmpty ? "documento-estratto" : name
        guard chooser.runModal() == .OK, let destination = chooser.url else { return }
        extractionIssue = "Esportazione in corso…"
        exporting = true
        Task {
            defer { exporting = false }
            let result = await Task.detached(priority: .userInitiated) { Result { try SignumFileOutput.writeNew(content, to: destination) } }.value
            switch result {
            case .success: extractionIssue = "Contenuto esportato."
            case .failure(let error): extractionIssue = error.localizedDescription
            }
        }
    }
    private func start(_ urls: [URL]) { guard !workspace.busy else { return }; Task { await workspace.verify(urls) } }
    private func drop(_ providers: [NSItemProvider]) -> Bool {
        guard !workspace.busy, providers.count <= 32 else { return false }
        Task { start(await VerificationDropLoader.urls(from: providers)) }
        return true
    }
}

/// PDFKit renders a static page thumbnail: no link, JavaScript, attachment or
/// document action can be clicked. The source is immutable in-memory data.
private struct VerificationPDFPreview: View {
    let report: VerificationReport
    @Environment(\.dismiss) private var dismiss
    @State private var document: PDFDocument?
    @State private var page = 0
    var body: some View {
        VStack(alignment: .leading) {
            HStack { Text(report.documentName).font(.headline); Spacer(); Button("Chiudi") { dismiss() } }
            if let document, document.pageCount > 0 {
                Picker("Pagina", selection: $page) { ForEach(0..<min(1000, document.pageCount), id: \.self) { Text("\($0+1)").tag($0) } }
                if let current = document.page(at: page) {
                    Image(nsImage: current.thumbnail(of: CGSize(width: 1000, height: 1000), for: .cropBox))
                        .resizable().scaledToFit().frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else { Text("Anteprima PDF non disponibile.") }
            Text("Sola lettura · l'immagine della pagina non costituisce verifica crittografica.").font(.caption)
        }.padding().frame(width: 780, height: 680)
        .onAppear { document = report.previewPDF.flatMap(PDFDocument.init(data:)) }
    }
}
#endif
