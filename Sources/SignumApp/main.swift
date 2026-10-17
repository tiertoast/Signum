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

private struct LoadedCertificates {
    var certificates: [SignumCertificate] = []
    var identities: [String: SignumCertificateIdentity] = [:]
    var assessments: [String: CertificateEligibility.Assessment] = [:]
    var derByID: [String: Data] = [:]
}

struct SignumWindow: View {
    @State private var modulePath = "/Library/bit4id/pkcs11/libbit4xpki.dylib"
    @State private var work: SigningOperation?
    @State private var workPhase: SigningOperationPhase = .idle
    @State private var activeModulePath: String?
    @State private var tokens: [SignumToken] = []
    @State private var certificates: [SignumCertificate] = []
    @State private var certificateIdentities: [String: SignumCertificateIdentity] = [:]
    @State private var certificateAssessments: [String: CertificateEligibility.Assessment] = [:]
    @State private var certificateDERs: [String: Data] = [:]
    @State private var selectedSlot: UInt?
    @State private var selectedCertificateID: String?
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @State private var documentSnapshot: DocumentSnapshot?
    @State private var previewSnapshotID: UUID?
    @State private var selectionRequestID = UUID()
    @State private var inputFile: URL?
    @State private var lastSignedFile: URL?
    @State private var dropTargeted = false
    @State private var pin = ""
    @State private var status = "Collega un dispositivo e premi Carica."
    @State private var busy = false
    @State private var discoveryID = UUID()

    private var canSign: Bool {
        guard !busy, !pin.isEmpty, selectedSlot != nil,
              let id = selectedCertificateID, certificateAssessments[id]?.permitsSigning == true,
              let snapshot = documentSnapshot, snapshot.format.rawValue == format.rawValue else { return false }
        switch format {
        case .cades: return true
        case .pades:
            return previewSnapshotID == snapshot.identity.id && SignumPAdESHelper.available
        case .xades: return false
        }
    }

    private var selectedHolder: String {
        guard let certificate = certificates.first(where: { $0.id == selectedCertificateID }) else {
            return "Firmatario"
        }
        return certificateIdentities[certificate.id]?.fullName ?? certificate.label
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
                Text("0.3.2 · Alpha").font(.caption).foregroundStyle(.secondary)
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
            .disabled(busy)
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
        .onChange(of: format) { nextFormat in
            pin = ""
            let previous = inputFile
            discardDocument()
            if let previous, nextFormat != .xades,
               nextFormat != .pades || previous.pathExtension.lowercased() == "pdf" {
                selectDocument(previous)
            }
        }
        .onDisappear {
            work?.requestCancellation()
            selectionRequestID = UUID()
            documentSnapshot = nil // An active immutable job retains its own snapshot.
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
            .disabled(busy)
            .padding(5)
        }
    }

    private var documentPicker: some View {
        GroupBox("Documento") {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    Image(systemName: "doc")
                    Text(inputFile?.lastPathComponent ?? "Trascina o seleziona un file")
                        .lineLimit(2)
                        .font(.callout)
                    Spacer(minLength: 4)
                    Button("Scegli…") { chooseFile() }.disabled(busy)
                }
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 7)
                        .strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.3),
                                      style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [5, 4]))
                )
                .onDrop(of: [UTType.fileURL.identifier],
                        isTargeted: $dropTargeted, perform: receiveDrop)
                if let snapshot = documentSnapshot {
                    Text("Copia selezionata · \(snapshot.identity.byteCount) byte · SHA-256 \(snapshot.identity.sha256)")
                        .font(.caption2).textSelection(.enabled)
                    Text("Le modifiche successive all'originale non sono incluse. Per aggiornarlo, selezionalo nuovamente.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(format == .pades ? "PDF · dimensione massima 64 MiB"
                      : "Qualsiasi file · dimensione massima 16 MiB")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(5)
        }
    }

    private var tokenControls: some View {
        GroupBox("Dispositivo e lettore") {
            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    TextField("Percorso PKCS#11", text: $modulePath)
                        .textFieldStyle(.roundedBorder)
                        .disabled(busy)
                    Button("Carica") { load() }.disabled(busy)
                }
                List(tokens, selection: Binding(
                    get: { selectedSlot },
                    set: { slot in
                        selectedSlot = slot
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
                .disabled(busy)
            }
            .padding(5)
        }
    }

    private var certificateControls: some View {
        GroupBox("Certificato di firma") {
            VStack(alignment: .leading) {
                List(certificates, selection: $selectedCertificateID) { certificate in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(certificateIdentities[certificate.id]?.title ?? certificate.label)
                            .font(.caption.weight(.semibold)).lineLimit(2)
                        Text("\(certificate.label) · ID \(certificate.id)")
                            .font(.caption2).foregroundStyle(.secondary)
                        Text(certificateAssessments[certificate.id]?.status.description ?? "Idoneità indeterminata")
                            .font(.caption2)
                    }
                    .tag(certificate.id)
                }
                .frame(height: 130)
                .disabled(busy)
                if let id = selectedCertificateID, let assessment = certificateAssessments[id] {
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
                if format == .pades {
                    if SignumPAdESHelper.available {
                        Text("Motore PoDoFo sperimentale rilevato. Riquadro con nome incorporato se posizionato; immagini personalizzate non ancora disponibili. Verifica sempre con InfoCamere.")
                            .font(.caption).foregroundStyle(.orange)
                    } else {
                        Text("Per abilitare PAdES, compila in locale il motore PoDoFo e ricrea Signum.app.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
                HStack(spacing: 10) {
                    SecureField("PIN del dispositivo", text: $pin)
                        .textFieldStyle(.roundedBorder)
                        .privacySensitive()
                        .disabled(busy || (format == .pades && !SignumPAdESHelper.available))
                    if busy {
                        ProgressView().controlSize(.small)
                    }
                    Button(busy ? "Firma in corso…" :
                           format == .pades ? "Firma PDF" : "Firma .p7m") {
                        if format == .pades { signPAdES() }
                        else { signDocument() }
                    }
                    .disabled(!canSign)
                    if busy, let work {
                        Button("Annulla") {
                            status = work.requestCancellation() ? "Annullamento richiesto…" : "La pubblicazione è già iniziata. Attendi l'esito."
                        }
                    }
                }
                if busy, work != nil { Text(workPhase.message).font(.caption).foregroundStyle(.secondary) }
                Text("Solo test con documenti fittizi. Validazione normativa eIDAS e revoche non implementate.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(5)
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
        if format == .pades, let snapshot = documentSnapshot {
            PAdESPlacementPane(
                snapshot: snapshot,
                previewReady: { id, ready in
                    guard documentSnapshot?.identity.id == id else { return }
                    if ready, previewSnapshotID != id { previewSnapshotID = id }
                    if !ready {
                        discardDocument(); pin = ""
                        status = "Anteprima non disponibile: seleziona un PDF valido e non protetto."
                    }
                },
                holder: selectedHolder,
                placement: Binding(get: { pdfPlacement }, set: { value in
                    guard !busy, documentSnapshot?.identity.id == snapshot.identity.id else { return }
                    pdfPlacement = value
                })
            )
            .id(snapshot.identity.id)
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

    private static func readCertificates(_ worker: IsolatedPKCS11Client, provider: String,
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
        certificates = loaded.certificates
        certificateIdentities = loaded.identities
        certificateDERs = loaded.derByID
        certificateAssessments = loaded.assessments
        selectedCertificateID = loaded.certificates.first(where: { loaded.assessments[$0.id]?.permitsSigning == true })?.id
        status = "\(loaded.certificates.count) certificati · \(loaded.identities.count) identità lette."
    }

    private func load(allowRetry: Bool = true) {
        guard !busy else { return }
        let path = modulePath.trimmingCharacters(in: .whitespacesAndNewlines), previousSlot = selectedSlot
        let request = UUID(), operation = beginWork(), worker = IsolatedPKCS11Client()
        discoveryID = request; selectedCertificateID = nil; busy = true
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
                guard self.discoveryID == request else { return }
                self.busy = false; self.workPhase = operation.state; self.work = nil
                if operation.isCancellationRequested { self.status = "Lettura annullata."; return }
                switch result {
                case .success(let (scan, slot, cache)):
                    self.activeModulePath = scan.provider; self.tokens = scan.tokens; self.selectedSlot = slot
                    self.applyCertificates(cache)
                    if scan.unavailableSlots > 0 {
                        self.status = "\(scan.tokens.count) dispositivi pronti; \(scan.unavailableSlots) in inizializzazione."
                        if allowRetry {
                            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(450)) {
                                guard !self.busy, self.discoveryID == request, !operation.isCancellationRequested,
                                      self.modulePath.trimmingCharacters(in: .whitespacesAndNewlines) == path else { return }
                                self.load(allowRetry: false) // Public discovery only: no PIN or signing retry.
                            }
                        }
                    } else if scan.tokens.isEmpty { self.status = "Nessun dispositivo riconosciuto." }
                case .failure(let error):
                    self.activeModulePath = nil; self.tokens = []; self.selectedSlot = nil
                    self.applyCertificates(LoadedCertificates()); self.status = error.localizedDescription
                }
            }
        }
    }

    private func loadCertificates(slot: UInt?) {
        guard !busy else { return }
        selectedCertificateID = nil; certificates = []; certificateIdentities = [:]
        certificateDERs = [:]; certificateAssessments = [:]
        let request = UUID(); discoveryID = request
        guard let path = activeModulePath, let slot else { return }
        let operation = beginWork(), worker = IsolatedPKCS11Client()
        busy = true; status = "Lettura certificati in processo separato…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Self.readCertificates(worker, provider: path, slot: slot, operation: operation) }
            operation.transition(to: operation.isCancellationRequested ? .cancelled : (result.isSuccess ? .completed : .failed))
            DispatchQueue.main.async {
                guard self.discoveryID == request else { return }
                self.busy = false; self.workPhase = operation.state; self.work = nil
                if operation.isCancellationRequested { self.status = "Lettura annullata."; return }
                guard self.selectedSlot == slot else { return }
                switch result {
                case .success(let cache): self.applyCertificates(cache)
                case .failure(let error): self.status = error.localizedDescription
                }
            }
        }
    }

    private func chooseFile() {
        guard !busy else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona un documento da firmare"
        picker.canChooseFiles = true
        picker.canChooseDirectories = false
        picker.allowsMultipleSelection = false
        if picker.runModal() == .OK, let url = picker.url {
            guard format != .pades || url.pathExtension.lowercased() == "pdf" else {
                status = "Per PAdES seleziona un documento .pdf."
                return
            }
            selectDocument(url)
        }
    }

    private func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !busy,
              let item = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) })
        else { return false }

        item.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
            let url: URL?
            if let file = value as? URL { url = file }
            else if let raw = value as? Data { url = URL(dataRepresentation: raw, relativeTo: nil) }
            else { url = nil }
            DispatchQueue.main.async {
                guard !self.busy, let url, url.isFileURL else { return }
                guard self.format != .pades || url.pathExtension.lowercased() == "pdf" else {
                    self.status = "Per PAdES seleziona un file PDF."
                    return
                }
                self.selectDocument(url)
            }
        }
        return true
    }

    private func discardDocument() {
        documentSnapshot?.close()
        documentSnapshot = nil
        inputFile = nil
        previewSnapshotID = nil
        pdfPlacement = nil
        lastSignedFile = nil
    }

    private func selectDocument(_ url: URL) {
        guard !busy, let requestedFormat = SigningFormat(rawValue: format.rawValue) else { return }
        discardDocument()
        pin = ""
        busy = true
        let request = UUID(); selectionRequestID = request
        status = "Acquisizione della copia privata del documento…"
        DispatchQueue.global(qos: .userInitiated).async {
            let captured = Result { try DocumentSnapshot.capture(source: url, format: requestedFormat) }
            DispatchQueue.main.async {
                guard selectionRequestID == request else {
                    if case .success(let snapshot) = captured { snapshot.close() }
                    return
                }
                busy = false
                switch captured {
                case .success(let snapshot):
                    documentSnapshot = snapshot
                    inputFile = snapshot.originalURL
                    status = "Copia acquisita. Controlla il documento prima di approvare la firma."
                case .failure(let error): status = error.localizedDescription
                }
            }
        }
    }

    private func signDocument() { approveAndSign() }
    private func signPAdES() { approveAndSign() }

    private func approveAndSign() {
        guard canSign, let snapshot = documentSnapshot, let provider = activeModulePath, let slot = selectedSlot,
              let certificate = certificates.first(where: { $0.id == selectedCertificateID }),
              let der = certificateDERs[certificate.id] else { return }
        // Freeze operation inputs before opening modal panels; the worker never
        // reads view state or the original document URL.
        let holder = selectedHolder
        let field = pdfPlacement.map { SignumPAdESHelper.Field(pageIndex: $0.pageIndex,
            x: Double($0.rectangle.minX), y: Double($0.rectangle.minY),
            width: Double($0.rectangle.width), height: Double($0.rectangle.height)) }
        busy = true
        var launched = false
        defer { if !launched { busy = false } }
        let save = NSSavePanel()
        save.title = "Destinazione della copia firmata"
        save.directoryURL = snapshot.originalURL.deletingLastPathComponent()
        save.nameFieldStringValue = snapshot.format == .cades
            ? snapshot.originalURL.lastPathComponent + ".p7m"
            : snapshot.originalURL.deletingPathExtension().lastPathComponent + "-firmato.pdf"
        guard save.runModal() == .OK, let destination = save.url else {
            discardDocument(); pin = ""; status = "Firma annullata. Riseleziona il documento."; return
        }
        let job: SigningJob
        do {
            job = try SigningJob(snapshot: snapshot, providerPath: provider, slot: slot,
                                 certificate: certificate, certificateDER: der, destination: destination)
            guard !FileManager.default.fileExists(atPath: destination.path) else {
                throw SignumError.module("La destinazione esiste già: scegli un altro nome.")
            }
        } catch {
            discardDocument(); pin = ""; status = error.localizedDescription; return
        }
        let approval = NSAlert()
        approval.messageText = "Approva i byte da firmare"
        approval.informativeText = signingApprovalMessage(holder: holder, job: job)
        approval.addButton(withTitle: "Approva e firma")
        approval.addButton(withTitle: "Annulla")
        guard approval.runModal() == .alertFirstButtonReturn else {
            discardDocument(); pin = ""; status = "Firma annullata. Copia privata scartata."; return
        }
        let secret = pin; pin = ""
        let operation = beginWork(), worker = IsolatedPKCS11Client()
        launched = true
        lastSignedFile = nil
        status = "Firma della copia approvata in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = Result {
                defer { job.snapshot.close() }
                if job.format == .cades {
                    try job.signCAdES(using: worker, pin: secret, operation: operation)
                } else {
                    try SignumPAdESHelper.sign(job: job, pin: secret, appearanceName: holder, field: field, operation: operation)
                    operation.transition(to: .completed)
                }
            }
            if !operation.state.isTerminal {
                if case .failure(let error) = outcome {
                    if case SignumError.outputUncertain = error { operation.transition(to: .outcomeUncertain) }
                    else { operation.transition(to: operation.isCancellationRequested ? .cancelled : .failed) }
                }
            }
            DispatchQueue.main.async {
                busy = false; workPhase = operation.state; work = nil
                discardDocument()
                switch outcome {
                case .success:
                    lastSignedFile = job.destination
                    status = "Documento firmato e integrità verificata. Attendibilità CA, revoca e qualificazione non valutate."
                case .failure(let error): status = error.localizedDescription
                }
            }
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
