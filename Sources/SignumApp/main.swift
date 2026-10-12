#if os(macOS)
import SwiftUI
import SignumCore

@main
struct SignumApp: App {
    var body: some Scene {
        WindowGroup("Signum") { SignumWindow() }
            .defaultSize(width: 760, height: 580)
    }
}

struct SignumWindow: View {
    @State private var modulePath = "/Library/bit4id/pkcs11/libbit4xpki.dylib"
    @State private var module: PKCS11Module?
    @State private var activeModulePath: String?
    @State private var tokens: [SignumToken] = []
    @State private var certificates: [SignumCertificate] = []
    @State private var selectedSlot: UInt?
    @State private var selectedCertificateID: String?
    @State private var pin = ""
    @State private var status = "Carica un modulo PKCS#11 per iniziare."
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "signature").font(.largeTitle)
                VStack(alignment: .leading) {
                    Text("Signum").font(.title.bold())
                    Text("Firma digitale per macOS — prototipo tecnico")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text("0.1.0 · PoC").foregroundStyle(.secondary)
            }
            Divider()
            Text("Libreria PKCS#11").font(.headline)
            HStack {
                TextField("Percorso completo del modulo", text: $modulePath)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Percorso modulo PKCS#11")
                    .disabled(busy)
                Button("Carica") { load() }
                    .disabled(busy)
            }
            HStack(alignment: .top, spacing: 16) {
                GroupBox("Token collegati") {
                    List(tokens, selection: Binding(
                        get: { selectedSlot },
                        set: { slot in
                            selectedSlot = slot
                            loadCertificates(slot: slot)
                        }
                    )) { token in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(token.label).fontWeight(.medium)
                            Text("Slot \(token.slot) · \(token.model)").font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(token.slot)
                    }
                    .frame(minHeight: 190)
                    .disabled(busy)
                }
                GroupBox("Certificati X.509") {
                    List(certificates, selection: $selectedCertificateID) { cert in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(cert.label).fontWeight(.medium)
                            Text("ID: \(cert.id)").font(.caption).monospaced().foregroundStyle(.secondary)
                        }
                        .tag(cert.id)
                    }
                    .frame(minHeight: 190)
                    .disabled(busy)
                }
            }
            GroupBox("Test crittografico — NON genera PAdES/CAdES") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Firma soltanto un messaggio fittizio, mai un documento. Il PIN è utilizzato per l'autenticazione USER e, se richiesto dal token, CONTEXT_SPECIFIC.")
                        .font(.callout).foregroundStyle(.secondary)
                    if let token = tokens.first(where: { $0.slot == selectedSlot }),
                       let cert = certificates.first(where: { $0.id == selectedCertificateID }) {
                        Text("Dispositivo: \(token.label)  ·  Certificato: \(cert.label)")
                            .font(.callout.weight(.medium))
                    }
                    HStack {
                        SecureField("PIN del token", text: $pin)
                            .textFieldStyle(.roundedBorder)
                            .privacySensitive()
                            .disabled(busy)
                        if busy {
                            ProgressView().controlSize(.small)
                                .accessibilityLabel("Firma in corso")
                        }
                        Button(busy ? "Firma in corso…" : "Firma e verifica") { signTest() }
                            .disabled(selectedSlot == nil || selectedCertificateID == nil || pin.isEmpty || busy)
                    }
                    Text("Prototipo: non inserire PIN in un modulo PKCS#11 non attendibile. Un PIN errato può bloccare la carta.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(6)
            }
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: "info.circle")
                Text(status).textSelection(.enabled)
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .padding(22)
    }

    private func load() {
        // PKCS#11 initialization is process-wide. Recreating a provider while
        // the previous instance is still alive can result in C_Finalize()
        // shutting down the new instance (CKR_CRYPTOKI_NOT_INITIALIZED = 0x190).
        // Reuse the same provider for a refresh; close it before switching paths.
        let path = modulePath.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let loaded: PKCS11Module
            if let existing = module, activeModulePath == path {
                loaded = existing
            } else {
                selectedSlot = nil
                selectedCertificateID = nil
                certificates = []
                tokens = []
                module = nil  // Releases old provider before the next C_Initialize.
                activeModulePath = nil
                loaded = try PKCS11Module(path: path)
                module = loaded
                activeModulePath = path
            }

            let found = try loaded.tokens()
            let previousSlot = selectedSlot
            tokens = found
            let nextSlot: UInt?
            if let previousSlot, found.contains(where: { $0.slot == previousSlot }) {
                nextSlot = previousSlot
            } else {
                nextSlot = found.first?.slot
            }
            selectedSlot = nextSlot
            // Refresh explicitly even when the slot has not changed.
            loadCertificates(slot: nextSlot)
            if found.isEmpty { status = "Nessun token trovato." }
        } catch {
            module = nil
            activeModulePath = nil
            tokens = []
            certificates = []
            selectedSlot = nil
            selectedCertificateID = nil
            status = error.localizedDescription
        }
    }

    private func loadCertificates(slot: UInt?) {
        selectedCertificateID = nil
        guard let module, let slot else { certificates = []; return }
        do {
            certificates = try module.certificates(slot: slot)
            selectedCertificateID = certificates.first?.id
            status = "Trovati \(certificates.count) certificati."
        } catch {
            certificates = []
            status = error.localizedDescription
        }
    }

    private func signTest() {
        guard !busy, let module, let slot = selectedSlot,
              let certificate = certificates.first(where: { $0.id == selectedCertificateID }),
              !pin.isEmpty else { return }
        let suppliedPIN = pin
        pin = "" // Remove PIN from the visible SwiftUI field immediately.
        busy = true
        status = "Firma di prova in corso sul dispositivo selezionato…"

        // Keep the provider alive. Disable all other PKCS#11 controls while
        // this operation executes so calls are not made concurrently.
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<Bool, Error>
            do {
                result = .success(try module.signAndVerifyTest(
                    slot: slot, certificate: certificate, pin: suppliedPIN
                ))
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                busy = false
                switch result {
                case .success(true):
                    status = "Verified OK — firma RSA/SHA-256 verificata. Nessun PDF firmato."
                case .success(false):
                    status = "La verifica crittografica non è riuscita."
                case .failure(let error):
                    status = "Test non riuscito: \(error.localizedDescription)"
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
