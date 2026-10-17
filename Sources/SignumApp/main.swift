#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore

private extension Result {
    var isSuccess: Bool { if case .success = self { return true }; return false }
}

func signingApprovalMessage(holder: String, job: SigningJob) -> String {
    "Firmatario: \(holder)\n" + job.approvalDescription
}


@main
struct SignumApp: App {
    var body: some Scene {
        WindowGroup("Signum") {
            SignumWindow()
                .frame(minWidth: 980, minHeight: 650)
        }
        .defaultSize(width: 1320, height: 830)
        // No contentSize restriction: the user can freely resize the window.
    }
}

private enum SignumOperation: String, Hashable {
    case sign, verify, settings
}

private enum SignumFormat: String, Hashable {
    case cades, pades, xades
}

@MainActor struct SignumWindow: View {
    @StateObject private var batch = BatchSigningCoordinator()
    @State private var placements: [UUID: PAdESPlacement] = [:]
    @State private var readyPreviews = Set<UUID>()
    @State private var approvedFields: [UUID: SignumPAdESHelper.Field] = [:]
    @State private var approvedHolder = ""
    @State private var provider = ProviderSelection()
    @State private var work: SigningOperation?
    @State private var workPhase: SigningOperationPhase = .idle
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @State private var documentSnapshot: DocumentSnapshot?
    @State private var previewSnapshotID: UUID?
    @State private var selectionRequestID = UUID()
    @State private var inputFile: URL?
    @State private var lastSignedFile: URL?
    @State private var dropTargeted = false
    @State private var status = "Collega un dispositivo e premi Carica."
    @State private var busy = false

    private var interfaceLocked: Bool { busy || batch.isPreparing || batch.isRunning }
    private var canApproveBatch: Bool {
        guard !interfaceLocked, !batch.isFrozen, !batch.documents.isEmpty,
              provider.signingProvider != nil, provider.selectedSlot != nil,
              let id = provider.selectedCertificateID, provider.certificateAssessments[id]?.permitsSigning == true else { return false }
        return batch.documents.allSatisfy { entry in
            !entry.state.isTerminal && (entry.snapshot.format != .pades ||
                (readyPreviews.contains(entry.id) && SignumPAdESHelper.available))
        }
    }
    private var canAuthorizeNext: Bool {
        batch.isApproved && !interfaceLocked && !batch.needsOutcomeReview &&
            batch.nextDocument != nil && !provider.pin.isEmpty
    }

    private var selectedHolder: String {
        guard let certificate = provider.certificates.first(where: { $0.id == provider.selectedCertificateID }) else {
            return "Firmatario"
        }
        return provider.certificateIdentities[certificate.id]?.fullName ?? certificate.label
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: "signature").font(.largeTitle)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Signum").font(.title2.bold())
                    Text("Firma digitale per macOS · sviluppo sperimentale")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(AppVersion.label).font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)
            .padding(.bottom, 12)

            Picker("Sezione", selection: $operation) {
                Text("Firma documento").tag(SignumOperation.sign)
                Text("Verifica .p7m").tag(SignumOperation.verify)
                Text("Impostazioni").tag(SignumOperation.settings)
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .disabled(interfaceLocked || batch.isFrozen)
            .padding(.horizontal, 20)
            .padding(.bottom, 12)

            Divider()

            if operation == .sign {
                HSplitView {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 14) {
                            formatPicker
                            documentPicker
                            tokenControls
                            certificateControls
                            signingControls
                            statusFooter
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                    }
                    .frame(minWidth: 350, idealWidth: 420, maxWidth: 550)

                    pdfWorkspace
                        .frame(minWidth: 440, maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        if operation == .verify {
                            CAdESVerificationPane()
                        } else {
                            SignumGraphicSettingsPane()
                        }
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
        }
        .onChange(of: format) { _ in provider.pin = "" }
        .onDisappear {
            work?.requestCancellation()
            batch.cancelAll()
            selectionRequestID = UUID()
            documentSnapshot = nil
        }
    }

    private var formatPicker: some View {
        GroupBox("Tipologia di firma") {
            Picker("Formato", selection: $format) {
                Text("CAdES — documento .p7m").tag(SignumFormat.cades)
                Text("PAdES — PDF firmato").tag(SignumFormat.pades)
                Text("XAdES — prossimamente").tag(SignumFormat.xades).disabled(true)
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .frame(maxWidth: .infinity, alignment: .leading)
            .disabled(interfaceLocked || batch.isFrozen)
            .padding(5)
        }
    }

    private var documentPicker: some View {
        GroupBox("Documenti da firmare") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("\(batch.documents.count) documenti · nuovi file in \(format.rawValue.uppercased())")
                        .font(.callout)
                    Spacer()
                    Button("Aggiungi…") { chooseFile() }.disabled(interfaceLocked || batch.isFrozen)
                }
                Text("Trascina qui uno o più documenti. Ogni documento richiede una propria autorizzazione.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 34)
                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.3)))
                    .onDrop(of: [UTType.fileURL.identifier], isTargeted: $dropTargeted, perform: receiveDrop)
                ForEach(batch.documents) { entry in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Button(entry.snapshot.originalURL.lastPathComponent) { showDocument(entry.id) }
                                .lineLimit(2).disabled(batch.isRunning)
                            Spacer()
                            if !batch.isFrozen {
                                Button("Rimuovi") {
                                    let selected = documentSnapshot?.identity.id == entry.id
                                    batch.remove(entry.id); placements[entry.id] = nil; readyPreviews.remove(entry.id)
                                    if selected { showDocument(batch.documents.first?.id) }
                                }.disabled(interfaceLocked)
                            } else if batch.isApproved && !entry.state.isTerminal {
                                Button("Annulla") { batch.cancelDocument(entry.id); provider.pin = "" }
                                    .disabled(batch.isRunning && batch.nextDocument?.id == entry.id)
                            }
                        }
                        Text("\(entry.snapshot.format.rawValue.uppercased()) · \(ByteCountFormatter.string(fromByteCount: Int64(entry.snapshot.identity.byteCount), countStyle: .file)) · \(entry.state.message)")
                            .font(.caption)
                        Text(entry.destination?.path ?? "Destinazione: cartella da scegliere alla conferma")
                            .font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                        if !entry.result.isEmpty { Text(entry.result).font(.caption) }
                    }.padding(.vertical, 4)
                }
                if let snapshot = documentSnapshot {
                    DisclosureGroup("Dettagli tecnici del documento selezionato") {
                        Text("\(snapshot.identity.byteCount) byte · SHA-256 \(snapshot.identity.sha256)")
                            .font(.caption2).textSelection(.enabled)
                    }
                }
                ForEach(Array(batch.selectionIssues.enumerated()), id: \.offset) { _, message in
                    Text(message).font(.caption).foregroundStyle(.secondary)
                }
                Text("Le modifiche successive agli originali non sono incluse. Massimo 32 documenti e 128 MiB per sessione.")
                    .font(.caption).foregroundStyle(.secondary)
                if !batch.documents.isEmpty {
                    Button("Nuova sessione") {
                        batch.reset(); placements = [:]; readyPreviews = []; approvedFields = [:]
                        showDocument(nil); provider.pin = ""; lastSignedFile = nil
                    }.disabled(interfaceLocked)
                    DisclosureGroup("Resoconto sessione") {
                        Text(batch.sessionReport).font(.caption).textSelection(.enabled)
                    }
                }
            }.padding(5)
        }
    }

    private var tokenControls: some View {
        GroupBox("Dispositivo e lettore") {
            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    TextField("Percorso PKCS#11", text: Binding(get: { provider.path }, set: { next in
                        guard next != provider.path else { return }
                        work?.requestCancellation()
                        provider.changePath(next)
                        work = nil; busy = false; workPhase = .idle
                        status = "Provider modificato. Premi Carica per selezionare nuovamente dispositivo e certificato."
                    }))
                        .textFieldStyle(.roundedBorder)
                        .disabled(interfaceLocked || batch.isFrozen)
                    Button("Carica") { load() }.disabled(interfaceLocked || batch.isFrozen)
                }
                List(provider.tokens, selection: Binding(
                    get: { provider.selectedSlot },
                    set: { slot in
                        provider.selectedSlot = slot
                        loadCertificates(slot: slot)
                    }
                )) { token in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: token.iconName)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(token.label).font(.subheadline.weight(.medium))
                            Text("\(token.deviceKind) · \(token.model)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .tag(token.slot)
                }
                .frame(height: 105)
                .disabled(interfaceLocked || batch.isFrozen)
            }
            .padding(5)
        }
    }

    private var certificateControls: some View {
        GroupBox("Certificato di firma") {
            VStack(alignment: .leading) {
                List(provider.certificates, selection: $provider.selectedCertificateID) { certificate in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(provider.certificateIdentities[certificate.id]?.title ?? certificate.label)
                            .font(.caption.weight(.semibold)).lineLimit(2)
                        Text("\(certificate.label) · ID \(certificate.id)")
                            .font(.caption2).foregroundStyle(.secondary)
                        Text(provider.certificateAssessments[certificate.id]?.status.description ?? "Idoneità indeterminata")
                            .font(.caption2)
                    }
                    .tag(certificate.id)
                }
                .frame(height: 130)
                .disabled(interfaceLocked || batch.isFrozen)
                if let id = provider.selectedCertificateID, let assessment = provider.certificateAssessments[id] {
                    Text(assessment.explanation).font(.caption)
                    Text(assessment.usageDescription).font(.caption2).foregroundStyle(.secondary)
                }
                Text(CertificateEligibility.scope)
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(5)
        }
    }

    private var signingControls: some View {
        GroupBox("Firma") {
            VStack(alignment: .leading, spacing: 10) {
                if !batch.isApproved {
                    Button("Conferma firma…") { prepareBatch() }.disabled(!canApproveBatch)
                    Text("Il riepilogo include tutti i documenti. Per ogni PDF apri prima l'anteprima dall'elenco.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("\(batch.finishedCount) di \(batch.documents.count) conclusi")
                    if let next = batch.nextDocument {
                        Text("Prossimo: \(next.snapshot.originalURL.lastPathComponent)").font(.caption)
                        SecureField("PIN per questo documento", text: $provider.pin)
                            .textFieldStyle(.roundedBorder).privacySensitive().disabled(interfaceLocked || batch.needsOutcomeReview)
                        Button("Autorizza questa firma") { authorizeNextDocument() }.disabled(!canAuthorizeNext)
                    }
                    if batch.needsOutcomeReview {
                        Text("Esito incerto: controlla dispositivo ed eventuale output prima di continuare. La firma non verrà ripetuta.").font(.caption)
                        Button("Ho verificato l'esito: consenti il prossimo documento") { batch.acknowledgeUncertainOutcome(); provider.pin = "" }
                            .disabled(batch.isRunning)
                    }
                    Button("Annulla documenti in attesa") { batch.cancelPending(); provider.pin = "" }
                        .disabled(batch.nextDocument == nil)
                    if batch.isRunning {
                        ProgressView().controlSize(.small)
                        Button("Interrompi firma corrente") { batch.activeOperation?.requestCancellation() }
                    }
                }
                if batch.isPreparing { ProgressView("Preparazione documenti…").controlSize(.small) }
                if batch.isPreparing {
                    Button("Annulla selezione in preparazione") { batch.cancelAll() }
                }
                if busy, work == nil, !batch.isPreparing {
                    Button("Annulla caricamento") { selectionRequestID = UUID(); busy = false }
                }
                if busy, let work {
                    ProgressView(workPhase.message).controlSize(.small)
                    Button("Annulla lettura") { work.requestCancellation() }
                }
                Text("Il PIN viene richiesto per ogni documento; il provider può richiedere USER e CONTEXT_SPECIFIC per quella firma. Nessun retry automatico. Attendibilità CA e revoca non valutate.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
    }

    private var statusFooter: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text(status).font(.caption).textSelection(.enabled)
            Spacer(minLength: 0)
            if let file = lastSignedFile {
                Button("Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([file])
                }
            }
        }
    }

    @ViewBuilder
    private var pdfWorkspace: some View {
        if let snapshot = documentSnapshot, snapshot.format == .pades {
            PAdESPlacementPane(
                snapshot: snapshot,
                previewReady: { id, ready in
                    guard documentSnapshot?.identity.id == id else { return }
                    if ready { previewSnapshotID = id; readyPreviews.insert(id) }
                    if !ready {
                        batch.remove(id); showDocument(batch.documents.first?.id); provider.pin = ""
                        status = "Anteprima non disponibile: seleziona un PDF valido e non protetto."
                    }
                },
                holder: selectedHolder,
                placement: Binding(get: { pdfPlacement }, set: { value in
                    guard !interfaceLocked, !batch.isFrozen, documentSnapshot?.identity.id == snapshot.identity.id else { return }
                    pdfPlacement = value; placements[snapshot.identity.id] = value
                })
            )
            .id(snapshot.identity.id)
            .disabled(interfaceLocked || batch.isFrozen)
            .allowsHitTesting(!busy)
            .padding(14)
        } else {
            VStack(spacing: 14) {
                Image(systemName: format == .pades ? "doc.text.magnifyingglass" : "doc.text")
                    .font(.system(size: 52))
                    .foregroundStyle(.tertiary)
                Text(format == .pades ? "Anteprima PDF" : "Firma documento")
                    .font(.title3.weight(.medium))
                Text(format == .pades
                     ? "Seleziona un PDF per visualizzarlo e posizionare la firma."
                     : "Con CAdES il documento viene incorporato in una busta .p7m.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func beginWork() -> SigningOperation {
        let id = UUID()
        let operation = SigningOperation(id: id) { phase in
            DispatchQueue.main.async { if self.work?.id == id { self.workPhase = phase } }
        }
        work = operation; workPhase = .preparing
        operation.transition(to: .preparing)
        return operation
    }

    private nonisolated static func readCertificates(_ worker: IsolatedPKCS11Client, provider: String,
                                         slot: UInt?, operation: SigningOperation) throws -> LoadedCertificates {
        dispatchPrecondition(condition: .notOnQueue(.main))
        guard let slot else { return LoadedCertificates() }
        var result = LoadedCertificates()
        for row in try worker.certificates(provider: provider, slot: slot,
                                           isCancelled: { operation.isCancellationRequested }) {
            let certificate = row.certificate, der = row.der
            result.certificates.append(certificate)
            result.derByID[certificate.id] = der
            result.assessments[certificate.id] = CertificateEligibility.evaluate(certificateDER: der)
            if let identity = try? SignumCertificateIdentity(certificateDER: der) { result.identities[certificate.id] = identity }
        }
        return result
    }

    private func applyCertificates(_ loaded: LoadedCertificates) {
        provider.applyCertificates(loaded)
        status = "\(loaded.certificates.count) certificati · \(loaded.identities.count) identità lette."
    }

    private func load(allowRetry: Bool = true) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let inputPath = provider.path, path = inputPath.trimmingCharacters(in: .whitespacesAndNewlines), previousSlot = provider.selectedSlot
        let request = provider.beginDiscovery(), operation = beginWork(), worker = IsolatedPKCS11Client()
        busy = true
        status = "Lettura del dispositivo in processo separato…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { () -> (IsolatedPKCS11Client.Scan, UInt?, LoadedCertificates) in
                let scan = try worker.scan(provider: path, isCancelled: { operation.isCancellationRequested })
                let next = scan.tokens.first(where: { $0.slot == previousSlot })?.slot ?? scan.tokens.first?.slot
                let cache = try Self.readCertificates(worker, provider: scan.provider, slot: next, operation: operation)
                return (scan, next, cache)
            }
            operation.transition(to: operation.isCancellationRequested ? .cancelled : (result.isSuccess ? .completed : .failed))
            DispatchQueue.main.async {
                guard self.provider.requestID == request else { return }
                self.busy = false; self.workPhase = operation.state; self.work = nil
                if operation.isCancellationRequested { self.status = "Lettura annullata."; return }
                switch result {
                case .success(let (scan, slot, cache)):
                    guard self.provider.acceptDiscovery(request: request, inputPath: inputPath, canonicalPath: scan.provider,
                        tokens: scan.tokens, slot: slot, certificates: cache) else { return }
                    self.status = "\(cache.certificates.count) certificati · \(cache.identities.count) identità lette."
                    if scan.unavailableSlots > 0 {
                        self.status = "\(scan.tokens.count) dispositivi pronti; \(scan.unavailableSlots) in inizializzazione."
                        if allowRetry {
                            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(450)) {
                                guard !self.busy, self.provider.requestID == request, !operation.isCancellationRequested,
                                      self.provider.path.trimmingCharacters(in: .whitespacesAndNewlines) == path else { return }
                                self.load(allowRetry: false) // Public discovery only: no PIN or signing retry.
                            }
                        }
                    } else if scan.tokens.isEmpty { self.status = "Nessun dispositivo riconosciuto." }
                case .failure(let error):
                    self.provider.beginDiscovery(); self.status = error.localizedDescription
                }
            }
        }
    }

    private func loadCertificates(slot: UInt?) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let request = provider.beginCertificateLoad()
        guard let path = provider.signingProvider, let slot else { return }
        let operation = beginWork(), worker = IsolatedPKCS11Client()
        busy = true; status = "Lettura certificati in processo separato…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Self.readCertificates(worker, provider: path, slot: slot, operation: operation) }
            operation.transition(to: operation.isCancellationRequested ? .cancelled : (result.isSuccess ? .completed : .failed))
            DispatchQueue.main.async {
                guard self.provider.requestID == request else { return }
                self.busy = false; self.workPhase = operation.state; self.work = nil
                if operation.isCancellationRequested { self.status = "Lettura annullata."; return }
                guard self.provider.selectedSlot == slot else { return }
                switch result {
                case .success(let cache): self.applyCertificates(cache)
                case .failure(let error): self.status = error.localizedDescription
                }
            }
        }
    }

    private func chooseFile() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona i documenti da firmare"
        picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if format == .pades { picker.allowedContentTypes = [.pdf] }
        if picker.runModal() == .OK { addDocuments(picker.urls) }
    }

    private func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !interfaceLocked, !batch.isFrozen else { return false }
        let items = Array(providers.filter { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }.prefix(BatchSigningCoordinator.maximumDocuments))
        guard !items.isEmpty else { return false }
        busy = true
        let request = UUID(); selectionRequestID = request
        Task { @MainActor in
            let urls = await FileDropResolution.resolve(items)
            guard selectionRequestID == request else { return }
            busy = false
            addDocuments(urls)
        }
        return true
    }

    private func addDocuments(_ urls: [URL]) {
        guard !interfaceLocked, !batch.isFrozen, let kind = SigningFormat(rawValue: format.rawValue) else { return }
        provider.pin = ""
        Task { @MainActor in
            await batch.addDocuments(urls, format: kind)
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(batch.documents.count) documenti nella selezione. Controllali prima della conferma."
        }
    }

    private func showDocument(_ id: UUID?) {
        if let old = documentSnapshot, batch.documents.contains(where: { $0.id == old.identity.id }) { placements[old.identity.id] = pdfPlacement }
        documentSnapshot = batch.documents.first(where: { $0.id == id })?.snapshot
        inputFile = documentSnapshot?.originalURL
        pdfPlacement = id.flatMap { placements[$0] }
        previewSnapshotID = nil
    }

    private func prepareBatch() {
        guard canApproveBatch, let selectedProvider = provider.signingProvider, let slot = provider.selectedSlot,
              let certificate = provider.certificates.first(where: { $0.id == provider.selectedCertificateID }),
              let der = provider.certificateDERs[certificate.id] else { return }
        let picker = NSOpenPanel()
        picker.title = "Cartella delle copie firmate"
        picker.canChooseFiles = false; picker.canChooseDirectories = true; picker.allowsMultipleSelection = false
        guard picker.runModal() == .OK, let directory = picker.url else { return }
        provider.pin = ""; busy = true
        let holder = selectedHolder
        if let snapshot = documentSnapshot { placements[snapshot.identity.id] = pdfPlacement }
        let fields = placements.mapValues { value in SignumPAdESHelper.Field(pageIndex: value.pageIndex,
            x: Double(value.rectangle.minX), y: Double(value.rectangle.minY), width: Double(value.rectangle.width), height: Double(value.rectangle.height)) }
        Task { @MainActor in
            defer { busy = false }
            do {
                let approval = try await batch.prepareApproval(provider: selectedProvider, slot: slot, certificate: certificate, der: der, directory: directory)
                let alert = NSAlert()
                alert.messageText = "Conferma firma"
                alert.informativeText = "Firmatario: \(holder)\n\(approval.jobs.count) documenti. Confermi questa lista? Ogni firma richiederà una propria autorizzazione."
                let content = NSHostingView(rootView: BatchConsentView(approval: approval))
                content.frame = NSRect(x: 0, y: 0, width: 560, height: 320)
                alert.accessoryView = content
                alert.addButton(withTitle: "Conferma documenti"); alert.addButton(withTitle: "Annulla")
                if alert.runModal() == .alertFirstButtonReturn {
                    try batch.confirm(approval)
                    approvedFields = fields; approvedHolder = holder
                    status = "Lista confermata. Autorizza il primo documento."
                } else { batch.declineApproval(); status = "Conferma annullata. Nessuna firma avviata." }
            } catch { status = error.localizedDescription }
        }
    }

    private func authorizeNextDocument() {
        guard canAuthorizeNext else { return }
        let secret = provider.pin; provider.pin = ""
        let fields = approvedFields, holder = approvedHolder
        Task { @MainActor in
            do {
                try await batch.authorizeNext(pin: secret) { job, pin, operation in
                    if job.format == .cades { try job.signCAdES(using: IsolatedPKCS11Client(), pin: pin, operation: operation) }
                    else { try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: holder,
                        field: fields[job.snapshotIdentity.id], operation: operation) }
                }
                lastSignedFile = batch.documents.last(where: { $0.state == .completed })?.destination
                status = batch.nextDocument == nil ? "Sessione conclusa. Consulta il resoconto." : "Esito registrato. Il prossimo documento attende una nuova autorizzazione."
            } catch { status = error.localizedDescription }
        }
    }

}
#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
