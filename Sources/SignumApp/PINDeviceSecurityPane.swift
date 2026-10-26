#if os(macOS)
import SwiftUI
import AppKit
import SignumCore

struct PINDeviceSecurityPane: View {
    let group: DevicePresentation
    let discoveryID: UUID
    let locked: Bool
    @State private var accessID = ""
    @State private var snapshot: PINStatusSnapshot?
    @State private var reading = false
    @State private var message = "Scegli esplicitamente il dispositivo e il software da consultare."
    @State private var readID = UUID()
    @State private var cancellation: PINPublicReadCancellation?
    @State private var form: FormOperation?
    private struct FormOperation: Identifiable {
        let operation: PINManagementOperation
        var id: String { operation.rawValue }
    }
    private var context: PINManagementContext? {
        guard let access = group.accesses.first(where: { $0.id == accessID }), let inspection = access.provider.inspection else { return nil }
        let value = PINManagementContext(provider: inspection.canonicalPath, inspection: inspection,
            automatic: access.provider.origin == .known, token: access.observed.token, discoveryID: discoveryID)
        return value.valid ? value : nil
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Sicurezza del dispositivo").font(.headline)
            Picker("Accesso da consultare", selection: $accessID) {
                Text("Scegli dispositivo e software…").tag("")
                ForEach(group.accesses) { access in
                    Text("\(access.observed.token.label) · \(access.provider.definition.name) · slot \(access.observed.token.slot)").tag(access.id)
                }
            }.disabled(locked || reading)
            Text("Questa scelta è indipendente dal certificato usato per firmare.").font(.callout).foregroundStyle(.secondary)
            if let context {
                Text("\(context.provider) · slot \(context.token.slot) · seriale \(context.token.serial.isEmpty ? "non comunicato" : context.token.serial)")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            if let snapshot {
                Label(snapshot.statusDescription, systemImage: snapshot.userPINLocked || snapshot.userPINFinalTry ? "exclamationmark.triangle" : "info.circle")
                    .foregroundStyle(snapshot.userPINLocked || snapshot.userPINFinalTry ? Color.orange : Color.secondary)
                Text("Ultima lettura pubblica: " + snapshot.readAt.formatted(date: .abbreviated, time: .standard)).font(.callout)
                if snapshot.userPINFinalTry && snapshot.userPINLocked {
                    Text("Il middleware segnala anche l’ultimo tentativo disponibile.").foregroundStyle(.orange)
                }
                if snapshot.userPINMustChange && (snapshot.userPINLocked || snapshot.userPINFinalTry || snapshot.userPINCountLow) {
                    Text("È segnalata anche la necessità di modificare il PIN.").foregroundStyle(.secondary)
                }
                if snapshot.userPINCountLow && !snapshot.userPINFinalTry && snapshot.userPINLocked {
                    Text("Sono segnalati anche pochi tentativi disponibili.").foregroundStyle(.orange)
                }
                Text("Tentativi residui: numero non comunicato dal dispositivo.").font(.callout).foregroundStyle(.secondary)
                Text("Lunghezza dichiarata: minimo \(snapshot.minimumBytes.map { String($0) } ?? "non comunicato"), massimo \(snapshot.maximumBytes.map { String($0) } ?? "non comunicato") byte.")
                    .font(.callout).foregroundStyle(.secondary)
                if !snapshot.limitsConsistent { Text("Limiti incompleti o incoerenti: non utilizzabili per autorizzare operazioni.").font(.callout).foregroundStyle(.orange) }
                if snapshot.protectedAuthenticationPath { Text("Il middleware dichiara un percorso di autenticazione protetto.").font(.callout) }
                Text("Dominio PIN, applet e procedura PUK non identificati. Le segnalazioni non provano l’utilizzabilità del PIN.")
                    .font(.callout).foregroundStyle(.secondary)
                DisclosureGroup("Dati pubblici della lettura") {
                    Text("Flag PKCS#11: 0x\(String(snapshot.flags, radix: 16))\nVersione comunicata dal modulo: \(snapshot.moduleVersion ?? "non disponibile")\nPIN utente inizializzato, secondo il middleware: \(snapshot.userPINInitialized ? "sì" : "non segnalato")")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            } else { Text(message).font(.callout).foregroundStyle(.secondary) }
            HStack {
                Button("Leggi stato PIN") { readPublicStatus() }.disabled(locked || reading || context == nil)
                if reading { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cambia PIN…") { form = .init(operation: .changePIN) }.disabled(true)
                    .help("Compatibilità non ancora verificata: operazione non disponibile.")
                Button("Sblocca PIN con PUK…") { form = .init(operation: .unblockPIN) }.disabled(true)
                    .help("Compatibilità non ancora verificata: operazione non disponibile.")
            }
            Text("Cambio PIN e sblocco con PUK non disponibili: compatibilità non ancora verificata.")
                .font(.callout).foregroundStyle(.secondary)
        }
        .onChange(of: accessID) { _ in invalidate() }
        .onChange(of: locked) { isLocked in if isLocked { invalidate() } }
        .onDisappear { invalidate() }
        .sheet(item: $form) { selection in PINManagementForm(operation: selection.operation, deviceName: group.name) }
    }
    private func invalidate() {
        cancellation?.cancel(); cancellation = nil
        readID = UUID(); reading = false; snapshot = nil
        message = "Stato PIN non letto per questo accesso. Nessun codice richiesto."
    }
    private func readPublicStatus() {
        guard !locked, !reading, let context else { return }
        let id = UUID(); readID = id; reading = true; snapshot = nil
        let cancellation = PINPublicReadCancellation(); self.cancellation = cancellation
        message = "Lettura pubblica in corso… Nessun PIN o PUK richiesto."
        Task { @MainActor in
            let result = await Task.detached(priority: .utility) { () -> Result<PINStatusSnapshot, Error> in
                Result { try PINManagementCoordinator.readStatus(context: context, isCancelled: { cancellation.isCancelled }) }
            }.value
            guard readID == id, self.context?.fingerprint == context.fingerprint, !locked else { return }
            reading = false
            self.cancellation = nil
            switch result {
            case .success(let value): snapshot = value
            case .failure(let failure): message = (failure as? PINManagementFailure)?.localizedDescription ?? "Lettura pubblica non completata. Nessun codice inviato."
            }
        }
    }
}

private final class PINPublicReadCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

/// Native form foundation. In 12A these controls are disabled and the form is
/// unreachable through enabled application actions. No secret String bindings,
/// preference storage, clipboard or administrative dispatch exists here.
struct PINManagementForm: View {
    let operation: PINManagementOperation
    let deviceName: String
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(operation == .changePIN ? "Cambia PIN" : "Sblocca PIN con PUK").font(.title2)
            Text(deviceName).font(.headline)
            Text("Compatibilità non ancora verificata. Nessun codice può essere inviato al dispositivo.").foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 12) {
                GridRow { Text(operation == .changePIN ? "PIN attuale" : "PUK"); InactiveAdministrativeSecretField() }
                GridRow { Text("Nuovo PIN"); InactiveAdministrativeSecretField() }
                GridRow { Text("Conferma nuovo PIN"); InactiveAdministrativeSecretField() }
            }
            Text("La futura conferma varrà per una sola operazione sul dispositivo e software indicati.").font(.callout).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Chiudi") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Conferma operazione") {}.disabled(true)
            }
        }.padding(24).frame(width: 520)
    }
}
private struct InactiveAdministrativeSecretField: NSViewRepresentable {
    func makeNSView(context: Context) -> NSSecureTextField {
        let field = NSSecureTextField(frame: .zero)
        field.isEnabled = false; field.placeholderString = "Operazione non disponibile"
        return field
    }
    func updateNSView(_ nsView: NSSecureTextField, context: Context) { nsView.stringValue = ""; nsView.isEnabled = false }
    static func dismantleNSView(_ nsView: NSSecureTextField, coordinator: ()) { nsView.stringValue = "" }
}
#endif
