#if os(macOS)
import SwiftUI
import SignumCore

struct DeviceConfigurationView: View {
    @Environment(\.dismiss) private var dismiss
    let providers: [DiscoveredMiddleware]
    let savedPaths: [String]
    let routes: [DeviceCertificateRoute]
    let selectedRouteID: String?
    @Binding var manualPath: String
    let locked: Bool
    let manualLocked: Bool
    let browse: () -> Void, loadManual: () -> Void
    let remove: (String) -> Void, selectRoute: (String) -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Configura dispositivo").font(.title2)
            ManualModulePicker(manualPath: $manualPath, locked: manualLocked, browse: browse, loadManual: loadManual)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Collega il dispositivo. Se il software non è rilevato, potrebbe essere necessario installare quello del produttore. Signum non scarica né installa driver.")
                    ForEach(MiddlewareRegistry.known) { definition in
                        VStack(alignment: .leading) {
                            Text(definition.name).font(.headline)
                            let matches = providers.filter { $0.definition.id == definition.id }
                            if matches.isEmpty { Text("Non ancora verificato in questa ricerca.").font(.caption) }
                            ForEach(matches) { result in
                                Text(result.diagnostic).font(.caption)
                            }
                        }
                    }
                    DisclosureGroup("Impostazioni avanzate") {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(savedPaths, id: \.self) { path in
                                HStack {
                                    Button(path) { manualPath = path }.lineLimit(2).textSelection(.enabled)
                                    Spacer()
                                    Button("Rimuovi") { remove(path) }
                                }
                            }
                            if !routes.isEmpty {
                                Text("Via di accesso al certificato selezionato").font(.headline)
                                ForEach(routes) { route in
                                    Button { selectRoute(route.id) } label: {
                                        HStack(alignment: .top) {
                                            Image(systemName: selectedRouteID == route.id ? "largecircle.fill.circle" : "circle")
                                            VStack(alignment: .leading) {
                                                Text("\(route.providerName) · \(route.deviceDescription)")
                                                Text("\(route.providerPath)\nSlot \(route.token.slot) · seriale \(route.token.serial) · ID \(route.certificate.id)")
                                                    .font(.caption).textSelection(.enabled)
                                            }
                                        }
                                    }.buttonStyle(.plain)
                                }
                            }
                            ForEach(providers) { result in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("\(result.definition.name) · \(result.origin == .known ? "candidato noto" : "scelta manuale")").font(.headline)
                                    Text("\(result.candidatePath)\n\(result.inspection?.canonicalPath ?? "Percorso non convalidato")").textSelection(.enabled)
                                    Text("Versione: \(result.version ?? "non disponibile") · \(result.diagnostic)")
                                    if let identity = result.inspection?.identity { Text("File: \(identity.moduleKey), \(identity.size) byte") }
                                    ForEach(result.tokens, id: \.token.slot) { entry in
                                        Text("\(entry.token.label) · slot \(entry.token.slot) · seriale \(entry.token.serial)\n\(entry.message)")
                                        Text("Produttore: \(entry.token.manufacturer) · modello: \(entry.token.model)\nLettore: \(entry.token.reader)")
                                    }
                                }.font(.caption)
                            }
                            Text("La ricerca non invia PIN. Le vie di accesso non dimostrano identità fisica comune; non viene effettuato fallback automatico.").font(.caption)
                        }.padding(.top, 6).disabled(locked)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack { Spacer(); Button("Chiudi") { dismiss() } }
        }.padding(20).frame(width: 660, height: 560)
    }
}

/// Always available independently of discovery results. Only an explicit load
/// executes a module; configured paths continue to be managed by the existing pane.
struct ManualModulePicker: View {
    @Binding var manualPath: String
    let locked: Bool
    let browse: () -> Void
    let loadManual: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Modulo PKCS#11 manuale").font(.headline)
            Text("Scegli il modulo del produttore e premi Carica manuale. I percorsi salvati non vengono caricati all’apertura.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("Percorso assoluto .dylib / .so", text: $manualPath)
                    .textFieldStyle(.roundedBorder).accessibilityIdentifier("signum.manual-module-path")
                Button("Scegli…", action: browse).accessibilityIdentifier("signum.choose-manual-module")
            }
            Button("Carica manuale", action: loadManual)
                .disabled(!MiddlewarePreferences.valid(manualPath))
                .accessibilityIdentifier("signum.load-manual-module")
        }.disabled(locked)
    }
}
#endif
