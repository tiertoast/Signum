#if os(macOS)
import SwiftUI
import SignumCore

/// Flat sections share spacing without adding another boxed surface.
struct SignumSettingsSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            content
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension SignumWindow {
    var settingsScreen: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Impostazioni").font(.title2.weight(.semibold)).padding(.horizontal, 24).padding(.top, 20)
            TabView {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        SignumSettingsSection(title: "Apertura documenti") {
                            Text("Scegli quali documenti aprire con Signum. PDF e XML restano facoltativi.")
                                .foregroundStyle(.secondary)
                            Button("Imposta Signum come app predefinita…") { showDefaultApplications = true }
                        }
                        Divider()
                        SignumSettingsSection(title: "Preferenze di firma") {
                            Toggle("Includi data e ora della firma", isOn: $includeSigningTime)
                                .help("Data dichiarata, non una marca temporale certificata")
                            Toggle("Conferma aggiuntiva prima della firma", isOn: $additionalConfirmation)
                            Text("Documenti e destinazioni richiedono sempre l’approvazione. La conferma aggiuntiva è un passaggio ulteriore.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        Divider()
                        SignumSettingsSection(title: "Firma multipla e autenticazione") {
                            Picker("Autenticazione", selection: $authenticationModeRaw) {
                                ForEach(BatchAuthenticationMode.allCases, id: \.rawValue) { mode in
                                    Text(mode.title).tag(mode.rawValue)
                                }
                            }.frame(maxWidth: .infinity)
                            Text(authenticationMode.explanation).font(.callout).foregroundStyle(.secondary)
                            Text("Per documento: un nuovo PIN a ogni firma. PIN temporaneo: rimane in memoria per il batch e ne aumenta l’esposizione. Automatica: prova il riutilizzo della sessione del dispositivo senza conservare il PIN. La condivisione è disponibile solo per CAdES.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: 720, alignment: .leading).padding(24).frame(maxWidth: .infinity, alignment: .center)
                }.tabItem { Label("Generali", systemImage: "gearshape") }
                ScrollView {
                    SignumGraphicSettingsPane().frame(maxWidth: 720, alignment: .leading).padding(24)
                        .frame(maxWidth: .infinity, alignment: .center)
                }.tabItem { Label("Firma grafica", systemImage: "signature") }
                ScrollView {
                    if let trustedLists {
                        TrustedListsPane(model: trustedLists).frame(maxWidth: 720, alignment: .leading).padding(24)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else { Text("Trusted Lists non disponibili in questa finestra.").foregroundStyle(.secondary).padding(24) }
                }.tabItem { Label("Trusted Lists", systemImage: "checkmark.shield") }
                ScrollView {
                    deviceSettingsPane.frame(maxWidth: 720, alignment: .leading).padding(24)
                        .frame(maxWidth: .infinity, alignment: .center)
                }.tabItem { Label("Dispositivi", systemImage: "externaldrive") }
            }.padding(.horizontal, 16).padding(.bottom, 16)
        }
        .disabled(interfaceLocked || batch.isFrozen)
    }

    var deviceSettingsPane: some View {
        VStack(alignment: .leading, spacing: 22) {
            SignumSettingsSection(title: "Moduli configurati") {
                if manualPaths.isEmpty {
                    Text("Nessun modulo manuale salvato.").foregroundStyle(.secondary)
                }
                ForEach(manualPaths, id: \.self) { path in
                    Label { Text(path).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
                        icon: { Image(systemName: "shippingbox") }.font(.callout)
                }
                Button("Configura dispositivo…") { showDeviceConfiguration = true }
                    .accessibilityIdentifier("signum.configure-device")
            }
            Divider()
            SignumSettingsSection(title: "Software e middleware") {
                if devices.providers.isEmpty { Text("Nessun software rilevato nell’ultima ricerca.").foregroundStyle(.secondary) }
                ForEach(devices.providers) { provider in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(provider.definition.name).fontWeight(.medium)
                        Text(provider.diagnostic).font(.callout).foregroundStyle(.secondary)
                    }
                }
                Text("Token, certificati e dettagli tecnici sono nella schermata Dispositivi. Configura dispositivo gestisce i percorsi salvati e le vie di accesso.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Divider()
            ManualModulePicker(manualPath: $manualPath, locked: interfaceLocked || batch.isFrozen,
                browse: chooseManualModule, loadManual: { discover(manual: manualPath) })
        }
    }
}
#endif
