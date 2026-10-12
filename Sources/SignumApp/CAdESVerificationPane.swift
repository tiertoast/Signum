#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore

/// Independent, PIN-free cryptographic verification of attached CAdES envelopes.
struct CAdESVerificationPane: View {
    @State private var selectedFile: URL?
    @State private var result: CAdESVerificationResult?
    @State private var extractedFile: URL?
    @State private var busy = false
    @State private var isTargeted = false
    @State private var status = "Seleziona una busta .p7m da verificare."

    var body: some View {
        GroupBox("Verifica locale CAdES (.p7m)") {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(selectedFile?.lastPathComponent ?? "Trascina qui un file .p7m")
                            .lineLimit(1)
                        Text("Verifica matematica CMS · fino a 5 livelli annidati")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Scegli .p7m…") { chooseFile() }.disabled(busy)
                    Button("Verifica") { verify() }
                        .disabled(busy || selectedFile == nil)
                }
                .padding(9)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(isTargeted ? Color.accentColor : Color.secondary.opacity(0.3),
                                      style: StrokeStyle(lineWidth: isTargeted ? 2 : 1, dash: [5, 4]))
                )
                .onDrop(of: [UTType.fileURL.identifier],
                        isTargeted: $isTargeted, perform: receiveDrop)

                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text(status)
                        .font(.callout)
                        .lineLimit(2)
                    Spacer()
                    if result != nil {
                        Button("Estrai originale…") { extract() }
                            .disabled(busy)
                    }
                    if let extractedFile {
                        Button("Mostra nel Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([extractedFile])
                        }
                    }
                }

                if let result {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(result.verifiedLayerCount) livelli verificati · \(result.verifiedSignatureCount) firme")
                                .font(.subheadline.weight(.semibold))
                            ForEach(result.levels) { level in
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.green)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Livello \(level.level) · \(level.signers.count) firmatari")
                                            .font(.caption.weight(.semibold))
                                        ForEach(Array(level.signers.enumerated()), id: \.offset) { item in
                                            Text(item.element)
                                                .font(.caption)
                                                .textSelection(.enabled)
                                        }
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 115)
                }

                Text("ATTENZIONE: OpenSSL verifica l'integrità, NON la catena di fiducia, le revoche, le marche temporali o la qualifica eIDAS.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(4)
        }
    }

    private func chooseFile() {
        guard !busy else { return }
        let panel = NSOpenPanel()
        panel.title = "Verifica una firma CAdES"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let file = panel.url { select(file) }
    }

    private func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !busy,
              let provider = providers.first(where: {
                  $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
              }) else { return false }
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
            let url: URL?
            if let file = value as? URL { url = file }
            else if let raw = value as? Data { url = URL(dataRepresentation: raw, relativeTo: nil) }
            else { url = nil }
            DispatchQueue.main.async {
                guard let url, url.isFileURL, !self.busy else { return }
                self.select(url)
            }
        }
        return true
    }

    private func select(_ url: URL) {
        selectedFile = url
        result = nil
        extractedFile = nil
        status = "Pronto per la verifica: \(url.lastPathComponent)"
    }

    private func verify() {
        guard let input = selectedFile, !busy else { return }
        busy = true
        result = nil
        extractedFile = nil
        status = "Controllo delle firme CMS in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = Result { try CAdESVerifier.verify(file: input) }
            DispatchQueue.main.async {
                self.busy = false
                switch outcome {
                case .success(let verified):
                    self.result = verified
                    self.status = "Integrità CMS verificata. Fiducia e qualificazione NON valutate."
                case .failure(let error):
                    self.status = "Verifica non riuscita: \(error.localizedDescription)"
                }
            }
        }
    }

    private func extract() {
        guard let result, !busy else { return }
        let panel = NSSavePanel()
        panel.title = "Estrai il documento originale verificato"
        panel.nameFieldStringValue = result.suggestedFilename
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        if FileManager.default.fileExists(atPath: destination.path) {
            status = "Il file esiste già: scegli un nome diverso."
            return
        }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = Result { try SignumFileOutput.writeNew(result.originalDocument, to: destination) }
            DispatchQueue.main.async {
                self.busy = false
                switch outcome {
                case .success:
                    self.extractedFile = destination
                    self.status = "Documento estratto: \(destination.lastPathComponent)"
                case .failure(let error):
                    self.status = "Estrazione non riuscita: \(error.localizedDescription)"
                }
            }
        }
    }
}
#endif
