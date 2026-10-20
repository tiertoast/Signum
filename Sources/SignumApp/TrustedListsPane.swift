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
                    Text("Italia: \(model.providerCount) prestatori · \(model.serviceCount) servizi\(expired ? " (elenco obsoleto)" : "")")
                    if let message = model.message { Text(message).foregroundStyle(.secondary) }
                    Text("L’autenticazione degli elenchi non determina ancora l’attendibilità o la qualificazione delle firme personali.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(6)
            }
        }
    }
}
