#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers

enum GraphicStyle: String, CaseIterable, Identifiable {
    case textOnly = "Solo testo"
    case imageAndText = "Immagine e testo"
    case imageOnly = "Solo immagine"
    var id: String { rawValue }
}

/// User-specific local settings for the OPTIONAL visible appearance of a PAdES signature.
/// They are NOT certificate metadata, nor cryptographic signature contents.
struct SignumGraphicSettingsPane: View {
    @AppStorage("signum.appearance.style") private var style = GraphicStyle.imageAndText.rawValue
    @AppStorage("signum.appearance.title") private var profileName = "Firma personale"
    @AppStorage("signum.appearance.image") private var imagePath = ""
    @AppStorage("signum.appearance.date") private var showDate = true

    var body: some View {
        GroupBox("Firma grafica PAdES — configurazione locale") {
            VStack(alignment: .leading, spacing: 12) {
                Text("L'aspetto grafico è facoltativo: il valore legale della firma non dipende dall'immagine mostrata nel PDF.")
                    .font(.callout).foregroundStyle(.secondary)

                HStack {
                    TextField("Nome del profilo", text: $profileName)
                        .textFieldStyle(.roundedBorder)
                    Picker("Composizione", selection: $style) {
                        ForEach(GraphicStyle.allCases) { option in
                            Text(option.rawValue).tag(option.rawValue)
                        }
                    }
                    .frame(width: 230)
                }
                Toggle("Visualizza data e ora locali", isOn: $showDate)
                HStack {
                    Button("Seleziona immagine…") { selectImage() }
                    if !imagePath.isEmpty {
                        Button("Rimuovi immagine") { imagePath = "" }
                    }
                    Spacer()
                }
                if !imagePath.isEmpty {
                    Text(URL(fileURLWithPath: imagePath).lastPathComponent)
                        .font(.caption).foregroundStyle(.secondary)
                    if let image = NSImage(contentsOfFile: imagePath) {
                        Image(nsImage: image)
                            .resizable()
                            .scaledToFit()
                            .frame(height: 75)
                    } else {
                        Text("Immagine non disponibile: seleziona un nuovo file.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }

                Divider()
                Text("Anteprima del profilo").font(.headline)
                SignumGraphicAppearancePreview(
                    fullName: "Nome Cognome",
                    style: style,
                    imagePath: imagePath,
                    showDate: showDate
                )
                .frame(height: 90)
                .frame(maxWidth: .infinity, alignment: .leading)

                Text("L'immagine rimane sul Mac e non viene copiata nella repository. I profili saranno incorporati nei PDF solo dopo l'integrazione del motore PAdES.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
        }
    }

    private func selectImage() {
        let chooser = NSOpenPanel()
        chooser.title = "Scegli l'immagine della firma"
        chooser.canChooseFiles = true
        chooser.canChooseDirectories = false
        chooser.allowsMultipleSelection = false
        chooser.allowedContentTypes = [.png, .jpeg]
        guard chooser.runModal() == .OK, let url = chooser.url else { return }
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
        guard size > 0, size <= 5 * 1024 * 1024 else { return }
        imagePath = url.path
    }
}

struct SignumGraphicAppearancePreview: View {
    let fullName: String
    let style: String
    let imagePath: String
    let showDate: Bool

    var body: some View {
        HStack(spacing: 12) {
            if style != GraphicStyle.textOnly.rawValue,
               let image = NSImage(contentsOfFile: imagePath) {
                Image(nsImage: image).resizable().scaledToFit()
                    .frame(width: 115, height: 72)
            }
            if style != GraphicStyle.imageOnly.rawValue {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Firmato digitalmente da")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                    Text(fullName).font(.system(size: 13, weight: .medium))
                    if showDate {
                        Text(Date.now.formatted(date: .numeric, time: .shortened))
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(10)
        .frame(minWidth: 190, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.25)))
    }
}
#endif
