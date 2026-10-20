#if os(macOS)
import SwiftUI
import PDFKit
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration
import SignumTrustAuthentication
import SignumCertificateValidation

enum VerificationDropLoader {
    @MainActor static func urls(from providers: [NSItemProvider], timeout: TimeInterval = 10) async -> [URL] {
        guard providers.count <= 32 else { return [] }
        return await FileDropResolution.resolve(providers.filter { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }, timeout: timeout)
    }
}

@MainActor final class VerificationWorkspace: ObservableObject {
    struct Row: Identifiable {
        let id = UUID()
        let name: String
        var report: VerificationReport?
        var paths: [Int: CertificatePathResult] = [:]
        var issue = ""
    }
    private let catalog: (any TrustedListCatalogProviding)?
    init(catalog: (any TrustedListCatalogProviding)? = nil) { self.catalog = catalog }
    @Published private(set) var rows: [Row] = []
    @Published private(set) var busy = false
    @Published private(set) var acquiring = false
    @Published private(set) var issue = ""
    private var request = UUID()
    private var operation: SigningOperation?
    private var acquisition: Task<Void,Never>?
    private var verification: Task<Void,Never>?
    typealias Verifier = @Sendable (URL, SigningOperation) throws -> VerificationReport
    private static let defaultVerifier: Verifier = { url, control in
        try SignumVerificationService.verify(file: url, isCancelled: { control.isCancellationRequested })
    }
    func cancel() {
        request = UUID(); acquisition?.cancel(); acquisition = nil
        verification?.cancel(); verification = nil; operation?.requestCancellation(); operation = nil
        busy = false; acquiring = false
        for index in rows.indices where rows[index].report == nil { rows[index].issue = "Verifica annullata." }
    }
    func reset() { cancel(); rows = []; issue = "" }
    @discardableResult func acquire(using load: @escaping @MainActor () async -> [URL], verifier: Verifier? = nil) -> Task<Void,Never> {
        cancel(); let id = request
        busy = true; acquiring = true; issue = ""; rows = []
        let task = Task { @MainActor in
            let files = await load()
            guard request == id, !Task.isCancelled else { return }
            acquiring = false
            await perform(files, request: id, using: verifier ?? Self.defaultVerifier)
            if request == id { acquisition = nil }
        }
        acquisition = task
        return task
    }
    @discardableResult func start(_ files: [URL], using verifier: Verifier? = nil) -> Task<Void,Never> {
        cancel(); let id = request; busy = true
        let task = Task { @MainActor in
            await perform(files, request: id, using: verifier ?? Self.defaultVerifier)
            if request == id { verification = nil }
        }
        verification = task
        return task
    }
    func verify(_ files: [URL], using verifier: Verifier? = nil) async {
        cancel(); let id = request; busy = true
        await perform(files, request: id, using: verifier ?? Self.defaultVerifier)
    }
    private func perform(_ files: [URL], request id: UUID, using verifier: @escaping Verifier) async {
        guard request == id, !Task.isCancelled else { return }
        defer { if request == id { busy = false; operation = nil } }
        var seen = Set<String>()
        let urls = files.filter { $0.isFileURL && seen.insert($0.standardizedFileURL.path).inserted }
        guard !urls.isEmpty, urls.count <= 32 else { issue = "Seleziona da 1 a 32 documenti locali. Acquisizione scaduta o non disponibile: riprova."; return }
        let control = SigningOperation(); operation = control; issue = ""
        rows = urls.map { Row(name: $0.lastPathComponent) }
        var retainedPreviewBytes = 0
        let list = try? await catalog?.currentCatalog()
        guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
        for (index, url) in urls.enumerated() {
            guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
            let work = Task.detached(priority: .userInitiated) { Result { try verifier(url, control) } }
            let result = await withTaskCancellationHandler(operation: { await work.value },
                onCancel: { control.requestCancellation(); work.cancel() })
            guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
            switch result {
            case .success(var report):
                let count = report.originalContent?.count ?? report.previewPDF?.count ?? 0
                if count > SigningResourceLimits.maximumSessionBytes - retainedPreviewBytes {
                    report = report.withoutPreview()
                    rows[index].issue = "Contenuto non conservato: limite memoria della sessione. Il risultato di verifica è disponibile."
                } else { retainedPreviewBytes += count }
                rows[index].report = report
                guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
                let signatures = report.signatures
                let paths = await Task.detached(priority: .utility) {
                    var paths: [Int: CertificatePathResult] = [:]
                    for signature in signatures {
                        if control.isCancellationRequested { break }
                        if let signer = signature.signerDER {
                            paths[signature.id] = CertificatePathValidator.evaluate(signer: signer, intermediates: signature.embeddedCertificateDERs,
                                authenticatedLists: list.map { [$0] } ?? [], isCancelled: { control.isCancellationRequested })
                        } else { paths[signature.id] = .unavailable("Certificato DER del firmatario non disponibile.") }
                    }
                    return paths
                }.value
                guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
                rows[index].paths = paths
            case .failure(let error): rows[index].issue = error.localizedDescription
            }
        }
    }
}

struct UnifiedVerificationPane: View {
    @StateObject private var workspace: VerificationWorkspace
    init(catalog: (any TrustedListCatalogProviding)? = nil) { _workspace = StateObject(wrappedValue: VerificationWorkspace(catalog: catalog)) }
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
                    Button("Apri documenti…", action: choose).disabled(workspace.busy && !workspace.acquiring)
                    if workspace.busy { ProgressView().controlSize(.small); Button("Annulla") { workspace.cancel() } }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8).stroke(targeted ? Color.accentColor : Color.secondary.opacity(0.4), style: StrokeStyle(dash: [5,4])))
                .onDrop(of: [UTType.fileURL.identifier], isTargeted: $targeted, perform: drop)
                if workspace.acquiring { Text("Acquisizione documenti…").font(.caption) }
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
                                    ForEach(report.signatures) { signature in
                                        if let path = row.paths[signature.id] {
                                            Text("Firma \(signature.id + 1) · " + pathLabel(path.state)).fontWeight(.medium)
                                            if let service = path.service {
                                                Text((path.state == .verified ? "Prestatore: " : "Servizio candidato: ") + service.provider + " · " + service.country + " · " + service.service).font(.caption)
                                            }
                                            if path.state != .verified { Text(path.reason).font(.caption) }
                                        } else { Text("Catena X.509: in attesa di valutazione").font(.caption) }
                                    }
                                    Text("Revoca: non ancora verificata · Qualificazione eIDAS: non ancora determinata").font(.caption).foregroundStyle(.secondary)
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
                                                    if let path = row.paths[signature.id] {
                                                        Text("Catena X.509: " + pathLabel(path.state)).fontWeight(.medium)
                                                        if let service = path.service { Text("Prestatore: \(service.provider) · \(service.country)\nServizio: \(service.service)\nTL: \(service.listSequence) · stato: \(service.status)") }
                                                        Text(path.reason)
                                                        Text("Valutata al: " + path.evaluatedAt.formatted(date: .abbreviated, time: .shortened))
                                                        ForEach(Array(path.path.enumerated()), id: \.offset) { i, certificate in
                                                            Text("\(i + 1). \(certificate.subject) · \(certificate.sha256)").textSelection(.enabled)
                                                        }
                                                    } else { Text("Catena X.509: in attesa di valutazione") }
                                                    Text("Revoca: non ancora verificata · Qualificazione eIDAS: non ancora determinata")
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
                Text("La verifica della catena non stabilisce da sola l’attendibilità completa o la qualificazione della firma. Revoca e validazione temporale avanzata non valutate.").font(.caption).foregroundStyle(.secondary)
                Text("XML/XAdES: supporto futuro. Nessun file estratto viene salvato automaticamente.").font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
        .sheet(item: $preview) { report in VerificationPDFPreview(report: report) }
        .onDisappear { workspace.cancel() }
    }
    private func pathLabel(_ state: CertificatePathState) -> String {
        switch state { case .verified: return "Catena verificata"; case .invalid: return "Catena non valida"; case .notVerifiable: return "Non verificabile" }
    }
    private func format(_ format: VerifiedDocumentFormat) -> String {
        switch format { case .cades: return "CAdES / CMS"; case .pades: return "PDF / PAdES"; case .xml: return "XML"; case .unknown: return "Sconosciuto" }
    }
    private func choose() {
        workspace.cancel()
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
    private func start(_ urls: [URL]) { workspace.start(urls) }
    private func drop(_ providers: [NSItemProvider]) -> Bool {
        guard !providers.isEmpty, providers.count <= 32 else { return false }
        workspace.acquire { await VerificationDropLoader.urls(from: providers) }
        return true
    }
}

/// PDFKit renders a static page thumbnail: no link, JavaScript, attachment or
/// document action can be clicked. The source is immutable in-memory data.
private struct VerificationPDFPreview: View {
    let report: VerificationReport
    @Environment(\.dismiss) private var dismiss
    @State private var thumbnail: NSImage?
    @State private var pageCount = 0
    @State private var previewIssue = ""
    @State private var page = 0
    var body: some View {
        VStack(alignment: .leading) {
            HStack { Text(report.documentName).font(.headline); Spacer(); Button("Chiudi") { dismiss() } }
            if pageCount > 0 {
                Picker("Pagina", selection: $page) { ForEach(0..<min(1000, pageCount), id: \.self) { Text("\($0+1)").tag($0) } }
            }
            if let thumbnail {
                Image(nsImage: thumbnail).resizable().scaledToFit().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if previewIssue.isEmpty { ProgressView("Preparazione anteprima…") }
            else { Text(previewIssue) }
            Text("Sola lettura · l'immagine della pagina non costituisce verifica crittografica.").font(.caption)
        }.padding().frame(width: 780, height: 680)
        .task(id: page) {
            thumbnail = nil; previewIssue = ""
            guard let bytes = report.previewPDF else { previewIssue = "Anteprima PDF non disponibile."; return }
            do {
                let prepared = try await PDFPreviewPreparation.page(bytes, index: page)
                try Task.checkCancellation()
                pageCount = prepared.pageCount; thumbnail = NSImage(data: prepared.png)
                if thumbnail == nil { previewIssue = "Anteprima PDF non disponibile." }
            } catch { if !Task.isCancelled { previewIssue = error.localizedDescription } }
        }
    }
}
#endif
