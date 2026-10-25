#if os(macOS)
import SwiftUI
import PDFKit
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration
import SignumTrustAuthentication
import SignumCertificateValidation
import SignumVerificationReports

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
        var verificationDate: Date?
        var paths: [Int: CertificatePathResult] = [:]
        var validations: [Int: CompleteSignatureValidationResult] = [:]
        var issue = ""
    }
    private let catalog: (any TrustedListCatalogProviding)?
    private let validationClock: @Sendable () -> Date
    init(catalog: (any TrustedListCatalogProviding)? = nil, validationClock: @escaping @Sendable () -> Date = { Date() }) { self.catalog = catalog; self.validationClock = validationClock }
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
        let european = catalog as? any EuropeanCatalogProviding
        let list = european == nil ? try? await catalog?.currentCatalog() : nil
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
                let assessmentReport = report
                let identity = Bundle.main.bundleIdentifier ?? "io.github.tiertoast.Signum.Beta.B7"
                let cacheURL = FileManager.default.urls(for:.cachesDirectory,in:.userDomainMask).first?.appendingPathComponent(identity).appendingPathComponent("Revocation")
                let service = SignatureQualificationService(cache:cacheURL.map { RevocationEvidenceCache(directory:$0) })
                let online = await european?.networkAllowed() ?? true
                let observedAt=validationClock();rows[index].verificationDate=observedAt
                let assessment = Task.detached(priority: .utility) {
                    if let european {
                        let result = await service.validate(assessmentReport, catalog: european.europeanService, mode: online ? .online : .offline, observedAt: observedAt, evaluationMode: .bestAvailable,
                            isCancelled: { control.isCancellationRequested })
                        if !control.isCancellationRequested, let view = result.catalog { await european.didUpdate(view) }
                        return result.signatures
                    }
                    return await service.validate(assessmentReport,authenticatedLists:list.map { [$0] } ?? [],mode:.online,observedAt:observedAt,evaluationMode:.bestAvailable,
                        isCancelled:{ control.isCancellationRequested })
                }
                let values = await withTaskCancellationHandler(operation: { await assessment.value }, onCancel: { assessment.cancel() })
                guard request == id, !Task.isCancelled, !control.isCancellationRequested else { return }
                rows[index].verificationDate = values.first?.qualification.verificationDate ?? observedAt
                rows[index].paths = Dictionary(values.map { ($0.signatureID,$0.path) },uniquingKeysWith:{ a,_ in a })
                rows[index].validations = Dictionary(values.map { ($0.signatureID,$0) },uniquingKeysWith:{ a,_ in a })
            case .failure(let error): rows[index].issue = error.localizedDescription
            }
        }
    }
}

struct UnifiedVerificationPane: View {
    @StateObject private var workspace: VerificationWorkspace
    init(catalog: (any TrustedListCatalogProviding)? = nil, workspace: VerificationWorkspace? = nil) { _workspace = StateObject(wrappedValue: workspace ?? VerificationWorkspace(catalog: catalog)) }
    @State private var targeted = false
    @State private var preview: VerificationReport?
    @State private var extractionIssue = ""
    @State private var exporting = false
    @State private var selectedDocument: UUID?
    @State private var selectedSignature: Int?
    @State private var detailsExpanded = false
    private var selectedRow: VerificationWorkspace.Row? {
        workspace.rows.first { $0.id == selectedDocument } ?? workspace.rows.first
    }
    var body: some View {
        VStack(spacing: 0) {
            if workspace.rows.isEmpty { emptyState }
            else {
                documentList
                Divider()
                if let row = selectedRow {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 24) {
                            if let report = row.report {
                                if report.signatures.count > 1 {
                                    Picker("Firma", selection: Binding(get: { selectedSignature ?? report.signatures.first!.id }, set: { selectedSignature = $0; detailsExpanded = false })) {
                                        ForEach(report.signatures) { signature in
                                            Text("\(signature.counterSignatureOf == nil ? "Firma" : "Controfirma") \(signature.id + 1) · \(signature.signerIdentity?.personalName ?? "Identità non disponibile")").tag(signature.id)
                                        }
                                    }.pickerStyle(.menu).frame(maxWidth: .infinity, alignment: .leading)
                                }
                                if let signature = report.signatures.first(where: { $0.id == selectedSignature }) ?? report.signatures.first {
                                    signatureSummary(signature, row: row)
                                    DisclosureGroup("Dettagli", isExpanded: $detailsExpanded) {
                                        technicalDetails(row, report: report, signature: signature)
                                            .padding(.top, 12)
                                    }
                                } else {
                                    Label(report.summary, systemImage: "questionmark.document").font(.title3)
                                    Text(report.issue.isEmpty ? "Nessuna firma supportata rilevata." : report.issue).foregroundStyle(.secondary)
                                }
                            } else {
                                Label(workspace.busy ? "Verifica in corso…" : "Verifica non disponibile", systemImage: "doc.text.magnifyingglass")
                            }
                            if !row.issue.isEmpty { Label(row.issue, systemImage: "exclamationmark.triangle").foregroundStyle(.secondary) }
                        }.frame(maxWidth: 780, alignment: .leading).padding(28).frame(maxWidth: .infinity, alignment: .center)
                    }
                    actions(row)
                }
            }
            if !workspace.issue.isEmpty { Text(workspace.issue).font(.callout).padding(10) }
            if !extractionIssue.isEmpty { Text(extractionIssue).font(.callout).padding(10) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .contentShape(Rectangle())
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $targeted, perform: drop)
        .background(targeted ? Color.accentColor.opacity(0.06) : Color.clear)
        .sheet(item: $preview) { report in VerificationPDFPreview(report: report) }
        .onChange(of: workspace.rows.map(\.id)) { ids in
            if !ids.contains(where: { $0 == selectedDocument }) { selectedDocument = ids.first; selectedSignature = nil; detailsExpanded = false }
        }
        .onChange(of: selectedDocument) { _ in selectedSignature = nil; detailsExpanded = false }
    }
    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.text.magnifyingglass").font(.system(size: 44, weight: .light)).foregroundStyle(.secondary)
            Text("Le tue firme, in chiaro").font(.title2).fontWeight(.semibold)
            Text("Trascina qui i documenti da verificare\no selezionali dal Mac.").multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button("Apri documenti…", action: choose).controlSize(.large)
            Button("Firma separata P7S e originale…", action: chooseDetached).buttonStyle(.link)
            if workspace.busy {
                ProgressView(workspace.acquiring ? "Acquisizione documenti…" : "Verifica in corso…")
                Button("Annulla") { workspace.cancel() }
            }
        }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private var documentList: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Documenti").font(.headline)
                Spacer()
                if workspace.busy { ProgressView().controlSize(.small); Button("Annulla") { workspace.cancel() } }
                Button(action: choose) { Image(systemName: "plus").accessibilityLabel("Apri documenti da verificare") }
                    .buttonStyle(.borderless).disabled(workspace.busy && !workspace.acquiring)
                Button("P7S e originale…", action: chooseDetached).disabled(workspace.busy)
            }.padding(.horizontal, 20).padding(.vertical, 10)
            List(selection: $selectedDocument) {
                ForEach(workspace.rows) { row in
                    HStack(spacing: 10) {
                        Image(systemName: "doc.text")
                        Text(row.name).lineLimit(1).truncationMode(.middle).help(row.name)
                        Spacer()
                        Text(row.report.map { $0.integrity == .verified ? "Integrità verificata" : $0.summary } ?? (workspace.busy ? "In verifica…" : "Non disponibile"))
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }.tag(row.id).padding(.vertical, 3)
                }
            }.listStyle(.plain).frame(height: min(144, CGFloat(workspace.rows.count * 36 + 8)))
        }
    }
    private func check(_ value: VerificationCheck) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: value.symbol).foregroundStyle(value.tone == .positive ? Color.green : value.tone == .negative ? Color.red : Color.secondary)
                .accessibilityLabel(value.tone == .positive ? "Verificato" : value.tone == .negative ? "Esito negativo" : "Indeterminato")
            Text(value.title).foregroundStyle(.secondary).frame(width: 170, alignment: .leading)
            Text(value.value).frame(maxWidth: .infinity, alignment: .leading)
        }.font(.body)
    }
    private func signatureSummary(_ signature: SignatureVerificationResult, row: VerificationWorkspace.Row) -> some View {
        let value = row.validations[signature.id]
        let path = row.paths[signature.id]
        let policy = CertificatePolicyPresentation(certificate: signature.signerDER)
        return VStack(alignment: .leading, spacing: 24) {
            VStack(alignment: .leading, spacing: 6) {
                Text(signature.counterSignatureOf == nil ? "Firmato da" : "Controfirmato da").foregroundStyle(.secondary)
                Text(signature.signerIdentity?.personalName ?? "Identità non disponibile").font(.title).fontWeight(.semibold).textSelection(.enabled)
                if let fiscal = signature.signerIdentity?.fiscalCode { Text("Codice fiscale: " + fiscal).foregroundStyle(.secondary).textSelection(.enabled) }
                if let service = path?.service, path?.state == .verified {
                    Text("Certificatore: " + VerificationPresentation.providerName(service.provider)).help("Trusted List autenticata: " + service.provider)
                } else if let issuer = signature.certificate?.issuer {
                    Text("Emittente dichiarato nel certificato: " + issuer).font(.callout).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 14) {
                check(VerificationPresentation.integrity(signature.integrity))
                check(VerificationPresentation.provider(path))
                check(VerificationPresentation.revocation(value?.evidence.revocation.state))
                check(VerificationPresentation.qualification(value?.qualification))
            }
            Divider()
            VStack(alignment: .leading, spacing: 12) {
                Text("Data della firma").font(.headline)
                Text("Data di firma dichiarata: " + VerificationPresentation.declaredDate(signature.declaredTime)).textSelection(.enabled)
                check(VerificationPresentation.timestamp(signature, time: value?.evidence.time))
                if value?.evidence.time.state == .proven, let date = value?.evidence.time.provenTime {
                    Text("La firma esisteva entro " + VerificationPresentation.localDate(date) + ". La marca dimostra questo limite temporale, non l’istante esatto di apposizione.").font(.callout).foregroundStyle(.secondary)
                } else {
                    Text("La data di firma è dichiarata dal firmatario e non è comprovata da una marca temporale.").font(.callout).foregroundStyle(.secondary)
                }
            }
            Text(policy.summary).font(.callout).foregroundStyle(.secondary)
        }
    }
    @ViewBuilder private func technicalDetails(_ row: VerificationWorkspace.Row, report: VerificationReport, signature: SignatureVerificationResult) -> some View {
        if let snapshot = try? VerificationReportDocument(report: report, validations: Array(row.validations.values), verificationDate: row.verificationDate ?? Date()) {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array(snapshot.fields.enumerated()), id: \.offset) { _, field in detail(field.label, field.value) }
                if let index = report.signatures.firstIndex(where: { $0.id == signature.id }), snapshot.signers.indices.contains(index) {
                    let signer = snapshot.signers[index]
                    ForEach(Array(signer.fields.enumerated()), id: \.offset) { _, field in detail(field.label, field.value) }
                    ForEach(Array(signer.outcomes.enumerated()), id: \.offset) { _, outcome in detail(outcome.label, outcome.state + " · " + outcome.reason) }
                    ForEach(Array(signer.details.enumerated()), id: \.offset) { _, field in detail(field.label, field.value) }
                }
                if let value = row.validations[signature.id] { evidenceResults(value) }
                ForEach(Array(snapshot.notes.enumerated()), id: \.offset) { _, note in Text(note).foregroundStyle(.secondary) }
                Text("XAdES: profilo Baseline-B enveloped, una firma RSA-SHA256. Nessun file estratto viene salvato automaticamente.").foregroundStyle(.secondary)
            }.font(.caption).textSelection(.enabled)
        } else {
            Text("Dettagli completi in preparazione. " + report.summary).font(.callout)
            Text("SHA-256: " + report.sha256).font(.caption).textSelection(.enabled)
            if let value = row.validations[signature.id] { evidenceResults(value).font(.caption) }
        }
    }
    private func detail(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) { Text(label).fontWeight(.medium); Text(value).foregroundStyle(.secondary) }
    }
    @ViewBuilder private func actions(_ row: VerificationWorkspace.Row) -> some View {
        Divider()
        HStack(spacing: 16) {
            if let report = row.report {
                Menu("Esporta rapporto") {
                    Button("PDF…") { exportReport(row, format: .pdf) }
                    Button("Testo (.txt)…") { exportReport(row, format: .text) }
                }.disabled(exporting || workspace.busy || row.verificationDate == nil)
                if report.previewPDF != nil { Button("Anteprima PDF") { preview = report } }
                if report.originalContent != nil {
                    Button("Estrai originale…") { extract(report) }.disabled(exporting || workspace.busy || report.integrity != .verified)
                }
            }
            Spacer(minLength: 0)
        }.padding(.horizontal, 20).padding(.vertical, 12)
    }
    @ViewBuilder private func evidenceResults(_ value: CompleteSignatureValidationResult) -> some View {
        Text("Revoca: " + (value.evidence.revocation.state == .good ? "verificata, non revocato" : value.evidence.revocation.state == .revoked ? "revocato" : "indeterminata"))
        Text(value.evidence.revocation.reason)
        Text("Tempo: " + (value.evidence.time.state == .proven ? "comprovato" : value.evidence.time.state == .invalid ? "evidenza non valida" : "non comprovato"))
        Text(value.evidence.time.reason)
        if let date = value.evidence.time.provenTime { Text("Esistenza comprovata entro: " + date.formatted(date:.abbreviated,time:.standard)) }
        if let date = value.qualification.verificationDate { Text("Data della verifica: " + date.formatted(date:.abbreviated,time:.standard)) }
        if let date = value.qualification.evaluatedAt {
            Text((value.qualification.evaluationMode == .currentTime ? "Valutazione corrente al: " : "Valutazione storica al: ") + date.formatted(date:.abbreviated,time:.standard))
        }
        Text("Certificato qualificato: " + (value.qualification.qualifiedCertificate == .demonstrated ? "dimostrato" : value.qualification.qualifiedCertificate == .notDemonstrated ? "non dimostrato" : "indeterminato"))
        Text("Qualificazione eIDAS della firma: " + value.qualification.state.description)
        Text(value.qualification.reason)
        if let service = value.qualification.service {
            Text("Servizio all’istante valutato: " + service.provider + " · " + service.service + " · " + service.country + (value.qualification.serviceStateFromHistory ? " · stato storico" : ""))
        }
        Text("QSCD: " + (value.qualification.qscd == .demonstrated ? "dimostrato" : value.qualification.qscd == .notDemonstrated ? "non dimostrato" : "indeterminato: valutazione non conclusa"))
    }
    private func pathLabel(_ state: CertificatePathState) -> String {
        switch state { case .verified: return "Catena verificata"; case .invalid: return "Catena non valida"; case .notVerifiable: return "Non verificabile" }
    }
    private func format(_ format: VerifiedDocumentFormat) -> String {
        switch format { case .cades: return "CAdES / CMS"; case .pades: return "PDF / PAdES"; case .xml: return "XML / XAdES"; case .asic: return "ASiC / XAdES"; case .unknown: return "Sconosciuto" }
    }
    private func chooseDetached() {
        let signature=NSOpenPanel();signature.title="Seleziona la firma detached .p7s";signature.allowsMultipleSelection=false;signature.canChooseDirectories=false;signature.canChooseFiles=true;signature.allowedContentTypes=[];signature.allowsOtherFileTypes=true
        guard signature.runModal() == .OK,let cms=signature.url else {return}
        let original=NSOpenPanel();original.title="Seleziona il documento originale della firma";original.allowsMultipleSelection=false;original.canChooseDirectories=false;original.canChooseFiles=true;original.allowedContentTypes=[];original.allowsOtherFileTypes=true
        guard original.runModal() == .OK,let content=original.url else {return}
        workspace.start([cms],using:{ signature,control in
            try SignumVerificationService.verifyDetached(signature:signature,content:content,isCancelled:{control.isCancellationRequested})
        })
    }
    private func choose() {
        workspace.cancel()
        let chooser = NSOpenPanel(); chooser.allowsMultipleSelection = true; chooser.canChooseDirectories = false; chooser.canChooseFiles = true; chooser.allowedContentTypes = []; chooser.allowsOtherFileTypes = true
        if chooser.runModal() == .OK { start(chooser.urls) }
    }
    private func exportReport(_ row: VerificationWorkspace.Row,format: VerificationReportExporter.Format) {
        guard !exporting,!workspace.busy,let report=row.report,let date=row.verificationDate else {return}
        let panel=NSSavePanel();panel.title="Esporta rapporto di verifica"
        panel.allowedContentTypes = format == .pdf ? [.pdf]:[.plainText]
        panel.nameFieldStringValue=URL(fileURLWithPath:report.documentName).lastPathComponent+"-rapporto."+format.pathExtension
        guard panel.runModal() == .OK,let destination=panel.url else {return}
        let values=Array(row.validations.values),version=AppVersion.label(info:Bundle.main.infoDictionary)
        exporting=true;extractionIssue="Esportazione del rapporto in corso…"
        Task {
            defer {exporting=false}
            let result=await Task.detached(priority:.userInitiated) {Result {
                let snapshot=try VerificationReportDocument(report:report,validations:values,verificationDate:date,productVersion:version)
                try VerificationReportExporter.write(snapshot,format:format,to:destination)
            }}.value
            switch result {case .success:extractionIssue="Rapporto esportato. Nessun file esistente è stato sostituito."
            case .failure(let error):extractionIssue=error.localizedDescription}
        }
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
