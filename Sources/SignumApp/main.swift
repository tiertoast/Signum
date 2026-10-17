#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore

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
    var derByID: [String: Data] = [:]
}

struct SignumWindow: View {
    @State private var modulePath = "/Library/bit4id/pkcs11/libbit4xpki.dylib"
    @State private var module: PKCS11Module?
    @State private var activeModulePath: String?
    @State private var tokens: [SignumToken] = []
    @State private var certificates: [SignumCertificate] = []
    @State private var certificateIdentities: [String: SignumCertificateIdentity] = [:]
    @State private var certificateDERs: [String: Data] = [:]
    @State private var selectedSlot: UInt?
    @State private var selectedCertificateID: String?
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @State private var inputFile: URL?
    @State private var lastSignedFile: URL?
    @State private var dropTargeted = false
    @State private var pin = ""
    @State private var status = "Collega un dispositivo e premi Carica."
    @State private var busy = false
    @State private var discoveryID = UUID()

    private var canSign: Bool {
        guard !busy, !pin.isEmpty, selectedSlot != nil,
              selectedCertificateID != nil, let file = inputFile else { return false }
        switch format {
        case .cades: return true
        case .pades:
            return file.pathExtension.lowercased() == "pdf" && SignumPAdESHelper.available
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
            pdfPlacement = nil
            lastSignedFile = nil
            if nextFormat == .pades,
               let file = inputFile,
               file.pathExtension.lowercased() != "pdf" {
                inputFile = nil
            }
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
                    }
                    .tag(certificate.id)
                }
                .frame(height: 130)
                .disabled(busy)
                Text("Seleziona un certificato idoneo alla firma, non soltanto all'autenticazione.")
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
                }
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
        if format == .pades, let file = inputFile,
           file.pathExtension.lowercased() == "pdf" {
            PAdESPlacementPane(
                fileURL: file, holder: selectedHolder, placement: $pdfPlacement
            )
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

    private static func readCertificates(_ module: PKCS11Module, slot: UInt?) throws -> LoadedCertificates {
        dispatchPrecondition(condition: .notOnQueue(.main))
        guard let slot else { return LoadedCertificates() }
        var result = LoadedCertificates()
        result.certificates = try module.certificates(slot: slot)
        for certificate in result.certificates {
            // A DER failure must not leave a stale signer selectable. Display
            // parsing can still fall back to the certificate label.
            let der = try module.certificateDER(slot: slot, certificate: certificate)
            result.derByID[certificate.id] = der
            if let identity = try? SignumCertificateIdentity(certificateDER: der) {
                result.identities[certificate.id] = identity
            }
        }
        return result
    }

    private func applyCertificates(_ loaded: LoadedCertificates) {
        certificates = loaded.certificates
        certificateIdentities = loaded.identities
        certificateDERs = loaded.derByID
        selectedCertificateID = loaded.certificates.first?.id
        status = "\(loaded.certificates.count) certificati · \(loaded.identities.count) identità lette."
    }

    private func load(allowRetry: Bool = true) {
        guard !busy else { return }
        let path = modulePath.trimmingCharacters(in: .whitespacesAndNewlines)
        let previous = activeModulePath == path ? module : nil
        let previousSlot = selectedSlot
        let request = UUID()
        discoveryID = request
        selectedCertificateID = nil
        busy = true
        status = "Lettura del dispositivo in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { () -> (PKCS11Module, SignumTokenScan, UInt?, LoadedCertificates) in
                let loaded = try previous ?? PKCS11Module(path: path)
                let scan = try loaded.scanTokens()
                let next = scan.tokens.first(where: { $0.slot == previousSlot })?.slot ?? scan.tokens.first?.slot
                return (loaded, scan, next, try Self.readCertificates(loaded, slot: next))
            }
            DispatchQueue.main.async {
                guard self.discoveryID == request else { return }
                self.busy = false
                switch result {
                case .success(let (loaded, scan, slot, cache)):
                    self.module = loaded
                    self.activeModulePath = loaded.modulePath
                    self.tokens = scan.tokens
                    self.selectedSlot = slot
                    self.applyCertificates(cache)
                    if scan.unavailableSlots > 0 {
                        self.status = "\(scan.tokens.count) dispositivi pronti; \(scan.unavailableSlots) in inizializzazione."
                        if allowRetry {
                            // Discovery retry only; never resubmit a signing/PIN request.
                            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(450)) {
                                guard !self.busy, self.discoveryID == request,
                                      self.modulePath.trimmingCharacters(in: .whitespacesAndNewlines) == path else { return }
                                self.load(allowRetry: false)
                            }
                        }
                    } else if scan.tokens.isEmpty {
                        self.status = "Nessun dispositivo riconosciuto."
                    }
                case .failure(let error):
                    self.module = nil
                    self.activeModulePath = nil
                    self.tokens = []
                    self.selectedSlot = nil
                    self.applyCertificates(LoadedCertificates())
                    self.status = "Caricamento non riuscito: \(error.localizedDescription)"
                }
            }
        }
    }

    private func loadCertificates(slot: UInt?) {
        guard !busy else { return }
        selectedCertificateID = nil
        certificates = []
        certificateIdentities = [:]
        certificateDERs = [:]
        let request = UUID()
        discoveryID = request
        guard let module, let slot else { return }
        busy = true
        status = "Lettura certificati in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Self.readCertificates(module, slot: slot) }
            DispatchQueue.main.async {
                guard self.discoveryID == request else { return }
                self.busy = false
                guard self.selectedSlot == slot else { return }
                switch result {
                case .success(let cache): self.applyCertificates(cache)
                case .failure(let error): self.status = "Lettura certificati non riuscita: \(error.localizedDescription)"
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
            inputFile = url
            pdfPlacement = nil
            lastSignedFile = nil
            status = "Documento selezionato: \(url.lastPathComponent)"
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
                self.inputFile = url
                self.pdfPlacement = nil
                self.lastSignedFile = nil
                self.status = "Documento selezionato: \(url.lastPathComponent)"
            }
        }
        return true
    }

    private func signDocument() {
        guard format == .cades, !busy, let module, let slot = selectedSlot,
              let cert = certificates.first(where: { $0.id == selectedCertificateID }),
              let original = inputFile, !pin.isEmpty else { return }

        let save = NSSavePanel()
        save.title = "Salva il documento firmato CAdES"
        save.directoryURL = original.deletingLastPathComponent()
        save.nameFieldStringValue = original.lastPathComponent + ".p7m"
        save.canCreateDirectories = true
        guard save.runModal() == .OK, let destination = save.url else { return }
        guard destination.pathExtension.lowercased() == "p7m",
              original.standardizedFileURL != destination.standardizedFileURL else {
            status = "La destinazione deve avere estensione .p7m ed essere diversa dall'originale."
            return
        }

        if FileManager.default.fileExists(atPath: destination.path) {
            status = "Il file .p7m esiste già. Scegli un nome diverso."
            return
        }

        let suppliedPIN = pin
        pin = "" // Clear SwiftUI text field immediately.
        busy = true
        lastSignedFile = nil
        status = "Creazione della firma CAdES in corso…"

        // Keep this context alive and disable this window's edits. The native
        // provider owner serializes transactions from the other windows.
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<URL, Error>
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: original.path)
                guard let size = attributes[.size] as? NSNumber,
                      size.intValue > 0, size.intValue <= CAdES.maximumDocumentBytes else {
                    throw SignumError.module("Il file deve contenere tra 1 byte e 16 MiB.")
                }
                let document = try Data(contentsOf: original)
                guard !document.isEmpty && document.count <= CAdES.maximumDocumentBytes else {
                    throw SignumError.module("Documento vuoto o troppo grande.")
                }
                let cms = try module.createCAdES(document: document,
                                                  slot: slot, certificate: cert, pin: suppliedPIN)
                try SignumFileOutput.writeNew(cms, to: destination) { staged in
                    try CAdESVerifier.verifyAttached(data: staged, expectedDocument: document)
                }
                result = .success(destination)
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                self.busy = false
                switch result {
                case .success(let url):
                    self.lastSignedFile = url
                    self.status = "Busta .p7m creata: \(url.lastPathComponent). Verificala con InfoCamere o DSS."
                case .failure(let error):
                    self.status = "Firma non riuscita: \(error.localizedDescription)"
                }
            }
        }
    }


    private func signPAdES() {
        guard format == .pades, !busy, let original = inputFile,
              let slot = selectedSlot,
              let cert = certificates.first(where: { $0.id == selectedCertificateID }),
              !pin.isEmpty else { return }

        guard let path = activeModulePath, let expectedCertificate = certificateDERs[cert.id] else {
            status = "Ricarica il certificato prima di firmare il PDF."
            return
        }

        let picker = NSSavePanel()
        picker.title = "Salva PDF firmato PAdES — prototipo"
        picker.directoryURL = original.deletingLastPathComponent()
        picker.nameFieldStringValue = original.deletingPathExtension().lastPathComponent + "-firmato.pdf"
        guard picker.runModal() == .OK, let output = picker.url else { return }
        guard output.pathExtension.lowercased() == "pdf",
              output.standardizedFileURL != original.standardizedFileURL else {
            status = "Scegli un file PDF di destinazione diverso dall'originale."
            return
        }
        guard !FileManager.default.fileExists(atPath: output.path) else {
            status = "Il PDF di destinazione esiste già: scegli un altro nome."
            return
        }

        let field: SignumPAdESHelper.Field?
        if let placement = pdfPlacement {
            field = .init(pageIndex: placement.pageIndex,
                          x: Double(placement.rectangle.minX),
                          y: Double(placement.rectangle.minY),
                          width: Double(placement.rectangle.width),
                          height: Double(placement.rectangle.height))
        } else {
            field = nil
        }
        let secret = pin
        let holder = selectedHolder
        pin = ""
        busy = true
        lastSignedFile = nil
        status = "Firma PDF con PoDoFo e PKCS#11 in corso…"

        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = Result {
                try SignumPAdESHelper.sign(
                    input: original, output: output, modulePath: path,
                    slot: slot, certificateID: cert.id, expectedCertificate: expectedCertificate, pin: secret,
                    appearanceName: holder, field: field
                )
            }
            DispatchQueue.main.async {
                self.busy = false
                switch outcome {
                case .success:
                    self.lastSignedFile = output
                    self.status = "PDF firmato e integrità verificata. Attendibilità del certificato e qualificazione eIDAS non verificate."
                case .failure(let error):
                    if case SignumError.outputUncertain = error {
                        self.status = error.localizedDescription
                    } else {
                        self.status = "Firma PDF non riuscita: \(error.localizedDescription)"
                    }
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
