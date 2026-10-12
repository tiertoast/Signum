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
                .frame(width: 900, height: 760, alignment: .top)
        }
        .defaultSize(width: 900, height: 760)
        .windowResizability(.contentSize)
    }
}

private enum SignumOperation: String, Hashable {
    case sign
    case verify
    case settings
}

private enum SignumFormat: String, Hashable {
    case cades
    case pades
    case xades
}

struct SignumWindow: View {
    @State private var modulePath = "/Library/bit4id/pkcs11/libbit4xpki.dylib"
    @State private var module: PKCS11Module?
    @State private var activeModulePath: String?
    @State private var tokens: [SignumToken] = []
    @State private var certificates: [SignumCertificate] = []
    @State private var certificateIdentities: [String: SignumCertificateIdentity] = [:]
    @State private var selectedSlot: UInt?
    @State private var selectedCertificateID: String?
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @AppStorage("signum.appearance.style") private var graphicStyle = GraphicStyle.imageAndText.rawValue
    @AppStorage("signum.appearance.image") private var graphicImagePath = ""
    @AppStorage("signum.appearance.date") private var graphicDate = true
    @State private var inputFile: URL?
    @State private var lastSignedFile: URL?
    @State private var dropTargeted = false
    @State private var pin = ""
    @State private var status = "Collega un dispositivo e premi Carica."
    @State private var busy = false

    var body: some View {
        ScrollView {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: "signature").font(.largeTitle)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Signum").font(.title.bold())
                    Text("Firma digitale per macOS — prototipo sperimentale")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Text("0.3.0 · Alpha").font(.caption).foregroundStyle(.secondary)
            }

            Divider()

            if operation == .sign {
            Text("Libreria PKCS#11").font(.headline)
            HStack {
                TextField("Percorso completo del modulo", text: $modulePath)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Percorso modulo PKCS#11")
                    .disabled(busy)
                Button("Carica / Aggiorna") { load() }
                    .disabled(busy)
            }

            HStack(alignment: .top, spacing: 12) {
                GroupBox("Dispositivi collegati") {
                    List(tokens, selection: Binding(
                        get: { selectedSlot },
                        set: { slot in
                            selectedSlot = slot
                            loadCertificates(slot: slot)
                        }
                    )) { token in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: token.iconName).frame(width: 20)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(token.label).fontWeight(.medium)
                                Text("\(token.deviceKind) · \(token.model)")
                                    .font(.caption).foregroundStyle(.secondary)
                                Text(token.readerDescription)
                                    .font(.caption2).foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        .tag(token.slot)
                    }
                    .frame(height: 190) // Never expand to fill the desktop height.
                    .disabled(busy)
                }

                GroupBox("Certificati X.509") {
                    List(certificates, selection: $selectedCertificateID) { cert in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(certificateIdentities[cert.id]?.title ?? cert.label)
                                .font(.subheadline.weight(.semibold))
                                .lineLimit(2)
                            Text("\(cert.label) · ID \(cert.id)")
                                .font(.caption).foregroundStyle(.secondary)
                            if let issuer = certificateIdentities[cert.id]?.issuer {
                                Text("Emittente: \(issuer)")
                                    .font(.caption2).foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        .tag(cert.id)
                    }
                    .frame(height: 190)
                    .disabled(busy)
                }
            }

            }

            Picker("Operazione", selection: $operation) {
                Text("Firma documento").tag(SignumOperation.sign)
                Text("Verifica .p7m").tag(SignumOperation.verify)
                Text("Impostazioni").tag(SignumOperation.settings)
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .disabled(busy)

            if operation == .sign {
                HStack {
                    Text("Formato di firma").font(.headline)
                    Picker("Formato", selection: $format) {
                        Text("CAdES (.p7m)").tag(SignumFormat.cades)
                        Text("PAdES (.pdf)").tag(SignumFormat.pades)
                        Text("XAdES (prossimamente)").tag(SignumFormat.xades).disabled(true)
                    }
                    .pickerStyle(.menu)
                    .frame(width: 255)
                    Spacer()
                    if format == .pades {
                        Text("Motore PAdES in integrazione")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if operation == .verify {
                CAdESVerificationPane()
            } else if operation == .settings {
                SignumGraphicSettingsPane()
            } else {
            GroupBox("Firma documento") {
                VStack(alignment: .leading, spacing: 9) {
                    if operation == .sign {
                        HStack(spacing: 10) {
                            Image(systemName: "doc.badge.plus")
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(inputFile?.lastPathComponent ?? "Trascina qui un file, oppure selezionalo")
                                    .lineLimit(1)
                                Text(format == .cades
                                     ? "CAdES con documento incorporato · massimo 16 MiB"
                                     : "PAdES · PDF con firma incorporata")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Scegli file…") { chooseFile() }
                                .disabled(busy)
                        }
                        .padding(10)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.28),
                                              style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [5, 4]))
                        )
                        .onDrop(of: [UTType.fileURL.identifier],
                                isTargeted: $dropTargeted, perform: receiveDrop)
                        Text(format == .cades
                             ? "Il documento verrà firmato e salvato come .p7m."
                             : "PAdES conserverà il formato PDF e permetterà la firma grafica opzionale.")
                            .font(.caption).foregroundStyle(.secondary)
                    }

                    if let token = tokens.first(where: { $0.slot == selectedSlot }),
                       let cert = certificates.first(where: { $0.id == selectedCertificateID }) {
                        Text("\(token.deviceKind): \(token.label) · \(certificateIdentities[cert.id]?.title ?? cert.label)")
                            .font(.callout.weight(.medium))
                            .lineLimit(2)
                    }

                    if format == .pades {
                        Text("Il posizionamento grafico è già disponibile in anteprima. La firma PAdES sarà abilitata quando il motore PoDoFo/PKCS#11 avrà superato la verifica.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    HStack {
                        SecureField("PIN del dispositivo", text: $pin)
                            .textFieldStyle(.roundedBorder)
                            .privacySensitive()
                            .disabled(busy || format == .pades)
                        if busy {
                            ProgressView()
                                .controlSize(.small)
                                .accessibilityLabel("Operazione in corso")
                        }
                        Button(busy ? "Elaborazione…" : format == .cades ? "Firma .p7m" : "Firma PDF (in sviluppo)") {
                            if format == .cades { signDocument() }
                        }
                        .disabled(busy || format != .cades || pin.isEmpty || selectedSlot == nil ||
                                  selectedCertificateID == nil || inputFile == nil)
                    }
                    Text("Versione di prova: non controlla ancora la qualificazione eIDAS o lo stato di revoca. Non usare documenti di lavoro.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(5)
            }
            if format == .pades, let file = inputFile,
               file.pathExtension.lowercased() == "pdf" {
                PAdESPlacementPane(
                    fileURL: file,
                    holder: certificates.first(where: { $0.id == selectedCertificateID })
                        .flatMap { certificateIdentities[$0.id]?.fullName } ?? "Firmatario",
                    placement: $pdfPlacement
                )
            }
            }

            if operation == .sign {
            HStack(alignment: .center, spacing: 8) {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text(status)
                    .font(.callout)
                    .lineLimit(2)
                    .textSelection(.enabled)
                Spacer()
                if let signedFile = lastSignedFile {
                    Button("Mostra nel Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([signedFile])
                    }
                }
            }
            }
        }
        .padding(20)
        }
    }

    private func load(allowRetry: Bool = true) {
        let path = modulePath.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let loaded: PKCS11Module
            if let existing = module, activeModulePath == path {
                loaded = existing
            } else {
                selectedSlot = nil
                selectedCertificateID = nil
                certificates = []
                certificateIdentities = [:]
                tokens = []
                module = nil // Finalize the previous module before opening another.
                activeModulePath = nil
                loaded = try PKCS11Module(path: path)
                module = loaded
                activeModulePath = path
            }

            let scan = try loaded.scanTokens()
            let previousSlot = selectedSlot
            tokens = scan.tokens
            let nextSlot: UInt?
            if let previousSlot, scan.tokens.contains(where: { $0.slot == previousSlot }) {
                nextSlot = previousSlot
            } else {
                nextSlot = scan.tokens.first?.slot
            }
            selectedSlot = nextSlot
            loadCertificates(slot: nextSlot)

            if scan.unavailableSlots > 0 {
                status = "\(scan.tokens.count) dispositivi pronti; \(scan.unavailableSlots) in inizializzazione."
                if allowRetry {
                    // The card reader can temporarily return CKR_TOKEN_NOT_RECOGNIZED (0xE1).
                    // Only one automatic retry; never retry PIN authentication.
                    DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(450)) {
                        guard !self.busy, self.activeModulePath == path else { return }
                        self.load(allowRetry: false)
                    }
                }
            } else if scan.tokens.isEmpty {
                status = "Nessun dispositivo riconosciuto."
            }
        } catch {
            status = "Caricamento non riuscito: \(error.localizedDescription)"
            // Keep the successfully initialized module for a manual refresh.
        }
    }

    private func loadCertificates(slot: UInt?) {
        selectedCertificateID = nil
        certificates = []
        certificateIdentities = [:]
        guard let module, let slot else { return }
        do {
            let found = try module.certificates(slot: slot)
            var identities: [String: SignumCertificateIdentity] = [:]
            for certificate in found {
                if let identity = try? module.certificateIdentity(slot: slot, certificate: certificate) {
                    identities[certificate.id] = identity
                }
            }
            certificates = found
            certificateIdentities = identities
            selectedCertificateID = found.first?.id
            status = "\(found.count) certificati · \(identities.count) identità lette."
        } catch {
            status = "Lettura certificati non riuscita: \(error.localizedDescription)"
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

        // Keep module alive and disable all UI operations using this PKCS#11
        // provider while the signature is running.
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
                try SignumFileOutput.writeNew(cms, to: destination)
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


}
#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
