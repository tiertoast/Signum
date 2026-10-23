#if os(macOS)
import SwiftUI
import SignumCore

extension SignumWindow {
    // These bindings and device configuration are owned by the signing window.
    // Native back navigation preserves that context and its existing locks on 13+.
    var settingsScreen: some View {
        TabView {
            ScrollView {
                Form {
                    Section("Apertura documenti") {
                        Button("Imposta Signum come app predefinita…") { showDefaultApplications = true }
                    }
                    Section("Firma") {
                        Toggle("Includi data e ora della firma", isOn: $includeSigningTime)
                            .help("Data dichiarata, non una marca temporale certificata")
                        Toggle("Conferma aggiuntiva prima della firma", isOn: $additionalConfirmation)
                            .help("Aggiunge una finestra di conferma dopo Firma…")
                    }
                    Section("Firma multipla") {
                        Picker("Autenticazione", selection: $authenticationModeRaw) {
                            ForEach(BatchAuthenticationMode.allCases, id: \.rawValue) { mode in
                                Text(mode.title).tag(mode.rawValue)
                            }
                        }
                        SignumContextHelp(title: "Informazioni sull’autenticazione", text: authenticationMode.explanation)
                    }
                }.formStyle(.columns).frame(maxWidth: 720).padding(24)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }.tabItem { Label("Generali", systemImage: "gearshape") }
            ScrollView { SignumGraphicSettingsPane().padding(20) }
                .tabItem { Label("Firma grafica", systemImage: "signature") }
            ScrollView {
                if let trustedLists { TrustedListsPane(model: trustedLists).padding(20) }
                else { Text("Trusted Lists non disponibili in questa finestra.").foregroundStyle(.secondary).padding(24) }
            }.tabItem { Label("Trusted Lists", systemImage: "checkmark.shield") }
            VStack(alignment: .leading, spacing: 14) {
                Button("Configura dispositivo…") { showDeviceConfiguration = true }
                    .disabled(devices.isSearching)
                Text("Software e certificati sono consultabili in Dispositivi.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
            }.padding(24).tabItem { Label("Dispositivi", systemImage: "externaldrive") }
        }
        .padding(16)
        .disabled(interfaceLocked || batch.isFrozen)
    }
}
#endif
