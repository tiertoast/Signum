import SwiftUI
import SignumTrustIntegration

struct TrustedListsPane: View {
    @ObservedObject var model: TrustedListsModel
    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in
            GroupBox("Elenchi fiduciari") {
                VStack(alignment: .leading, spacing: 10) {
                    let expired = model.expiresAt.map { $0 <= context.date } ?? false
                    HStack {
                        Text("Stato: \(expired ? "Obsoleti" : model.status.rawValue)")
                        if model.isRefreshing { ProgressView().controlSize(.small) }
                        Spacer()
                        Button("Verifica aggiornamenti") { model.checkForUpdates() }.disabled(model.isRefreshing)
                    }
                    if let date = model.lastVerifiedUpdate { Text("Ultimo aggiornamento verificato: \(date.formatted(date: .abbreviated, time: .shortened))") }
                    else { Text("Ultimo aggiornamento verificato: non disponibile") }
                    if let date = model.expiresAt { Text("Prossima scadenza: \(date.formatted(date: .abbreviated, time: .shortened))") }
                    Text("\(model.isEuropean ? "Catalogo acquisito" : "Italia"): \(model.providerCount) prestatori · \(model.serviceCount) servizi\(expired ? " (elenco obsoleto)" : "")")
                    if model.isEuropean {
                        Text("Paesi disponibili: " + (model.availableCountries.isEmpty ? "non disponibili" : model.availableCountries.joined(separator: ", ")))
                        Text("Cache nazionali presenti: " + (model.acquiredCountries.isEmpty ? "nessuna" : model.acquiredCountries.joined(separator: ", ")))
                        HStack {
                            Picker("Paese da aggiornare", selection: $model.selectedCountry) {
                                ForEach(Array(Set(model.availableCountries + [model.selectedCountry])).sorted(), id: \.self) { Text($0).tag($0) }
                            }.frame(maxWidth: 300)
                            Toggle("Usa solo la cache (offline)", isOn: Binding(get: { model.offline }, set: { model.setOffline($0) }))
                        }
                        ForEach(model.acquiredCountries, id: \.self) { country in
                            if let date = model.countryExpiries[country] {
                                Text("\(country): \(date <= context.date ? "obsoleto" : "verificato") · scadenza \(date.formatted(date: .abbreviated, time: .shortened))")
                            } else { Text("\(country): cache presente, non disponibile per la verifica") }
                        }
                        Text("Qualificazione positiva limitata ai profili verificati di IT, AT, DE, BE, FR, ES. Alcuni servizi o periodi storici possono restare esclusi.").font(.caption).foregroundStyle(.secondary)
                    }
                    if let message = model.message { Text(message).foregroundStyle(.secondary) }
                    Text("L’autenticazione degli elenchi, da sola, non determina l’attendibilità o la qualificazione delle firme personali.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(6)
            }
        }
    }
}
