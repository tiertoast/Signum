#if os(macOS)
import SwiftUI
struct SignumGraphicSettingsPane: View {
    @AppStorage("signum.appearance.signer") private var showSigner = true
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            SignumSettingsSection(title: "Firma grafica PDF") {
                Toggle("Usa il nome del certificato come valore iniziale", isOn: $showSigner)
                Text("Il nome viene proposto nell’anteprima e può essere modificato per ciascun PDF.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Divider()
            SignumSettingsSection(title: "Aspetto e posizione") {
                Label("Configura ogni PDF nella schermata Firma", systemImage: "doc.richtext")
                Text("Nell’anteprima scegli pagina, posizione, dimensioni, testo, data locale, immagine PNG/JPEG e allineamento. Le opzioni sono congelate all’approvazione.")
                    .font(.callout).foregroundStyle(.secondary)
                Text("L’anteprima del documento mostra la posizione effettiva. La rappresentazione grafica non dimostra integrità o qualificazione della firma.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}
#endif
