import SwiftUI
import SignumTrustIntegration

struct TrustedListsPane: View {
    @ObservedObject var model: TrustedListsModel
    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in
            let expired = model.expiresAt.map { $0 <= context.date } ?? false
            VStack(alignment: .leading, spacing: 22) {
                SignumSettingsSection(title: "Stato degli elenchi") {
                    HStack {
                        Label(expired ? "Elenchi scaduti" : model.status.rawValue,
                              systemImage: expired ? "exclamationmark.triangle" : "list.bullet.rectangle")
                        if model.isRefreshing { ProgressView().controlSize(.small) }
                        Spacer()
                        Button("Verifica aggiornamenti") { model.checkForUpdates() }.disabled(model.isRefreshing)
                    }
                    LabeledContent("Ultimo aggiornamento verificato", value: model.lastVerifiedUpdate.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "Non disponibile")
                    LabeledContent("Scadenza", value: model.expiresAt.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "Non disponibile")
                    if model.isEuropean {
                        Toggle("Usa solo la cache (offline)", isOn: Binding(get: { model.offline }, set: { model.setOffline($0) }))
                        Text(model.offline ? "Modalità offline: vengono usati solo gli elenchi autenticati già disponibili." : "Modalità online: Signum può acquisire gli elenchi necessari alla verifica.")
                            .font(.callout).foregroundStyle(.secondary)
                    } else { Text("Modalità: catalogo Italia").foregroundStyle(.secondary) }
                    if expired { Label("Gli elenchi sono scaduti: la qualificazione può rimanere indeterminata.", systemImage: "exclamationmark.triangle").font(.callout) }
                    // Important per-country warnings remain visible when details are closed.
                    ForEach(model.acquiredCountries, id: \.self) { country in
                        if let date = model.countryExpiries[country], date <= context.date {
                            Label("\(country): cache scaduta il \(date.formatted(date: .abbreviated, time: .shortened))", systemImage: "exclamationmark.triangle").font(.callout)
                        } else if model.countryExpiries[country] == nil {
                            Label("\(country): cache presente, non disponibile per la verifica", systemImage: "exclamationmark.triangle").font(.callout)
                        }
                    }
                    if let message = model.message { Label(message, systemImage: "info.circle").font(.callout).textSelection(.enabled) }
                }
                Divider()
                DisclosureGroup("Dettagli del catalogo") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("\(model.isEuropean ? "Catalogo acquisito" : "Italia"): \(model.providerCount) prestatori · \(model.serviceCount) servizi")
                        if model.isEuropean {
                            Text("Paesi disponibili: " + (model.availableCountries.isEmpty ? "nessuno" : model.availableCountries.joined(separator: ", ")))
                            Text("Cache nazionali: " + (model.acquiredCountries.isEmpty ? "nessuna" : model.acquiredCountries.joined(separator: ", ")))
                            Picker("Paese da aggiornare", selection: $model.selectedCountry) {
                                ForEach(Array(Set(model.availableCountries + [model.selectedCountry])).sorted(), id: \.self) { Text($0).tag($0) }
                            }.frame(maxWidth: .infinity)
                            ForEach(model.acquiredCountries, id: \.self) { country in
                                if let date = model.countryExpiries[country], date > context.date {
                                    Text("\(country): verificato · scadenza \(date.formatted(date: .abbreviated, time: .shortened))")
                                }
                            }
                            Text("Qualificazione positiva limitata ai profili verificati di IT, AT, DE, BE, FR, ES. Alcuni servizi o periodi storici possono restare esclusi.")
                        }
                        Text("L’autenticazione degli elenchi, da sola, non determina attendibilità o qualificazione delle firme personali.")
                    }.font(.callout).foregroundStyle(.secondary).textSelection(.enabled).padding(.top, 12)
                }
            }
        }
    }
}
