#if os(macOS)
import SwiftUI
struct SignumGraphicSettingsPane: View {
    @AppStorage("signum.appearance.signer") private var showSigner = true
    var body: some View {
        GroupBox("Firma grafica PAdES") {
            VStack(alignment:.leading,spacing:8) {
                Toggle("Nome dal certificato come impostazione iniziale",isOn:$showSigner)
                Text("Nell'anteprima di ciascun PDF puoi scegliere pagina, posizione, dimensioni, testo, data locale, PNG/JPEG e allineamento. Le opzioni sono congelate al consenso.")
                Text("La rappresentazione grafica non dimostra l'integrità crittografica o la qualificazione della firma.").font(.caption).foregroundStyle(.secondary)
            }.padding(8)
        }
    }
}
#endif
