#if os(macOS)
import SwiftUI
import SignumCore

struct DevicesExperiencePane: View {
    let selection: DeviceSelection
    let locked: Bool
    let status: String
    let configure: () -> Void
    let selectRoute: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme
    @State private var viewedDevice: String?
    @State private var inspectedRoute: String?
    @State private var extensions = ""
    private var groups: [DevicePresentation] { DevicePresentation.collect(selection) }
    private var current: DevicePresentation? {
        groups.first { $0.id == viewedDevice } ?? groups.first { $0.routes.contains { $0.id == selection.selectedRouteID } } ?? groups.first
    }
    private var technicalRoute: DeviceCertificateRoute? {
        current?.routes.first { $0.id == inspectedRoute } ?? current?.routes.first { $0.id == selection.selectedRouteID } ?? current?.routes.first
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Dispositivi").font(.title2.weight(.semibold))
                        Text("Scegli il dispositivo e il certificato da usare per la firma.").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Configura dispositivo…", action: configure).disabled(locked)
                }
                if selection.isSearching { ProgressView("Ricerca pubblica in corso… Nessun PIN richiesto.") }
                else if !selection.discoveryComplete && !selection.completenessIssues.isEmpty {
                    Label("Ricerca incompleta: disponibilità e unicità non sono accertate. Controlla i dettagli o aggiorna i dispositivi.", systemImage: "exclamationmark.triangle").font(.callout)
                }
                if groups.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Nessun dispositivo disponibile", systemImage: "externaldrive.badge.questionmark").font(.headline)
                        Text(selection.message).foregroundStyle(.secondary)
                        Text("Collega il dispositivo e usa Aggiorna dispositivi nella toolbar. Se manca il software del produttore, apri Configura dispositivo; il caricamento manuale resta disponibile.").font(.callout).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text("Dispositivi rilevati").font(.headline)
                    ForEach(groups) { group in
                        deviceCard(group)
                        Divider()
                    }
                    if let group = current {
                        Text("Certificati · " + group.name).font(.headline)
                        if group.certificateGroups.isEmpty {
                            Text("Nessun certificato pubblico leggibile. La disponibilità per la firma non è determinabile senza una nuova ricerca.").foregroundStyle(.secondary)
                        }
                        ForEach(Array(group.certificateGroups.enumerated()), id: \.offset) { _, routes in
                            certificate(routes)
                            Divider()
                        }
                    }
                }
                Text("L’idoneità locale non è una verifica di qualificazione eIDAS. La ricerca non invia PIN e non avvia firme.")
                    .font(.callout).foregroundStyle(.secondary)
                DisclosureGroup("Dettagli tecnici") { technicalDetails.padding(.top, 12) }
            }.frame(maxWidth: 900, alignment: .leading).padding(28).frame(maxWidth: .infinity, alignment: .center)
        }
        .onChange(of: selection.selectedRouteID) { id in
            if let group = groups.first(where: { $0.routes.contains { $0.id == id } }) { viewedDevice = group.id; inspectedRoute = id }
        }
        .task(id: technicalRoute?.id) {
            extensions = ""
            guard let route = technicalRoute else { return }
            let bytes = route.der
            let text = await Task.detached(priority: .utility) { DevicePresentation.extensionDetails(bytes) }.value
            guard !Task.isCancelled else { return }
            extensions = text
        }
    }
    private func deviceCard(_ group: DevicePresentation) -> some View {
                        Button {
                            viewedDevice = group.id; inspectedRoute = nil
                        } label: {
                            HStack(alignment: .top, spacing: 14) {
                                Image(systemName: group.symbol).font(.title2).foregroundStyle(colorScheme == .dark ? SignumAppearance.burgundyForeground : SignumAppearance.burgundy).frame(width: 30)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(group.name).font(.headline)
                                    Text(group.availability).font(.callout)
                                    Text(group.countLabel).font(.callout).foregroundStyle(.secondary)
                                    if group.accesses.count > 1 {
                                        Text("\(group.accesses.count) accessi correlati · identità fisica comune non accertata").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                Image(systemName: current?.id == group.id ? "checkmark.circle.fill" : "circle").foregroundStyle(.secondary)
                            }.padding(12).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                            .background((current?.id == group.id ? Color(nsColor: .selectedContentBackgroundColor).opacity(0.08) : Color.clear), in: RoundedRectangle(cornerRadius: 8))
                            .accessibilityLabel(group.name + ", " + group.availability + ", " + group.countLabel)
    }
    @ViewBuilder private func certificate(_ routes: [DeviceCertificateRoute]) -> some View {
        let route = routes.first { $0.id == selection.selectedRouteID } ?? routes[0]
        let selected = routes.contains { $0.id == selection.selectedRouteID }
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: route.assessment.permitsSigning ? "checkmark.seal" : "exclamationmark.circle")
                    .foregroundStyle(route.assessment.permitsSigning ? Color.green : Color.secondary)
                VStack(alignment: .leading, spacing: 5) {
                    Text(route.identity?.personalName ?? route.title).font(.headline)
                    Text(DevicePresentation.purpose(route)).font(.callout)
                    Text("Scadenza: " + (route.assessment.notAfter?.formatted(date: .abbreviated, time: .omitted) ?? "non disponibile"))
                        .font(.callout).foregroundStyle(.secondary)
                    Text(DevicePresentation.certificateState(route)).font(.callout).fontWeight(.medium)
                    if !route.assessment.permitsSigning { Text(route.assessment.explanation).font(.caption).foregroundStyle(.secondary) }
                }
                Spacer()
                if selected { Label("Selezionato", systemImage: "checkmark.circle.fill").font(.callout) }
            }
            HStack {
                if routes.count == 1 {
                    Button(selected ? "Certificato selezionato" : "Usa per firmare") { selectRoute(route.id) }
                        .disabled(locked || selection.isSearching || !route.assessment.permitsSigning || selected)
                } else {
                    Menu(selected ? "Accesso selezionato…" : "Scegli accesso per firmare…") {
                        ForEach(routes) { access in
                            Button("\(access.providerName) · slot \(access.token.slot) · \(access.providerPath)") { selectRoute(access.id) }
                                .disabled(!access.assessment.permitsSigning)
                        }
                    }.disabled(locked || selection.isSearching)
                    Text("\(routes.count) vie di accesso: scelta esplicita, senza fallback.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
        }.padding(.vertical, 4)
    }
    @ViewBuilder private var technicalDetails: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(selection.message).font(.callout)
            if !status.isEmpty, status != selection.message { Text(status).font(.callout) }
            ForEach(Array(selection.completenessIssues.enumerated()), id: \.offset) { _, issue in Text(issue).font(.callout) }
            if let group = current {
                ForEach(group.accesses) { access in
                    Text("\(access.provider.definition.name) · \(access.provider.status.message)\n\(access.provider.inspection?.canonicalPath ?? access.provider.candidatePath)\nSlot: \(access.observed.token.slot) · Token/seriale: \(access.observed.token.serial)\nEtichetta: \(access.observed.token.label) · modello: \(access.observed.token.model)\nProduttore: \(access.observed.token.manufacturer) · lettore: \(access.observed.token.reader)\n\(access.observed.message)")
                }
                if !group.routes.isEmpty {
                    Picker("Certificato e route da consultare", selection: Binding(get: { technicalRoute?.id ?? "" }, set: { inspectedRoute = $0 })) {
                        ForEach(group.routes) { route in Text("\(route.title) · \(route.certificateFingerprint.prefix(12)) · \(route.providerName) · slot \(route.token.slot)").tag(route.id) }
                    }
                    Text("Questa consultazione non cambia il firmatario selezionato.").foregroundStyle(.secondary)
                }
            }
            if let route = technicalRoute {
                Text("Provider PKCS#11: \(route.providerName)\nPercorso: \(route.providerPath)\nSlot: \(route.token.slot) · Token ID/seriale: \(route.token.serial) · CKA_ID: \(route.certificate.id)\nRoute: \(route.id)\nSHA-256: \(route.certificateFingerprint)\n\(route.assessment.usageDescription)\n\(route.assessment.explanation)")
                Text(extensions.isEmpty ? "Lettura estensioni…" : extensions)
                Text("Certificato pubblico DER · Base64").fontWeight(.medium)
                Text(route.der.base64EncodedString()).font(.caption.monospaced()).lineLimit(nil)
            }
            Text("Diagnostica middleware").fontWeight(.medium)
            ForEach(selection.providers) { provider in
                Text("\(provider.definition.name) · \(provider.diagnostic)\n\(provider.candidatePath)\nVersione: \(provider.version ?? "non disponibile") · slot non disponibili: \(provider.unavailableSlots)")
            }
        }.font(.caption).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
    }
}
#endif
