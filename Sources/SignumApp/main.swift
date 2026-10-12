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
                Button("Carica") { load() }
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
                }
            }
            GroupBox("Test crittografico — NON genera PAdES/CAdES") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Firma un messaggio di prova e ne verifica la firma con Security.framework. Non produce un documento firmato.")
                        .font(.callout).foregroundStyle(.secondary)
                    HStack {
                        SecureField("PIN del token", text: $pin)
                            .textFieldStyle(.roundedBorder)
                            .privacySensitive()
                        Button("Firma e verifica") { signTest() }
                            .disabled(selectedSlot == nil || selectedCertificateID == nil || pin.isEmpty || busy)
                    }
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
        guard let module, let slot = selectedSlot,
              let certificate = certificates.first(where: { $0.id == selectedCertificateID }) else { return }
        busy = true
        defer { pin = ""; busy = false }
        do {
            _ = try module.signAndVerifyTest(slot: slot, certificate: certificate, pin: pin)
            status = "Verified OK: prova RSA/SHA-256 completata. Nessun PDF firmato."
        } catch {
            status = "Test non riuscito: \(error.localizedDescription)"
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
