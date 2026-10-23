#if os(macOS)
import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct SignumDocumentAssociation: Identifiable {
    let id: String
    let title: String
    let importedIdentifier: String
    let optional: Bool
    // Resolve the system's preferred type for the extension (other installed apps
    // may already declare it); fall back to the imported Signum declaration.
    var contentType: UTType { UTType(filenameExtension: id) ?? UTType(importedAs: importedIdentifier) }
    static let formats: [Self] = [
        .init(id: "p7m", title: "Documento firmato CAdES", importedIdentifier: "io.github.tiertoast.signum.p7m", optional: false),
        .init(id: "p7s", title: "Firma separata", importedIdentifier: "io.github.tiertoast.signum.p7s", optional: false),
        .init(id: "asics", title: "Contenitore ASiC-S", importedIdentifier: "io.github.tiertoast.signum.asics", optional: false),
        .init(id: "asice", title: "Contenitore ASiC-E", importedIdentifier: "io.github.tiertoast.signum.asice", optional: false),
        .init(id: "pdf", title: "Documento PDF", importedIdentifier: UTType.pdf.identifier, optional: true),
        .init(id: "xml", title: "Documento XML", importedIdentifier: UTType.xml.identifier, optional: true)
    ]
}

@MainActor protocol DefaultApplicationAccess {
    func currentApplication(for type: UTType) -> URL?
    func setApplication(_ application: URL, for type: UTType) async throws
}

@MainActor struct WorkspaceDefaultApplicationAccess: DefaultApplicationAccess {
    func currentApplication(for type: UTType) -> URL? { NSWorkspace.shared.urlForApplication(toOpen: type) }
    func setApplication(_ application: URL, for type: UTType) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // macOS owns any consent dialog. Never use a Launch Services write API.
            NSWorkspace.shared.setDefaultApplication(at: application, toOpen: type) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }
}

@MainActor final class DefaultApplicationsModel: ObservableObject {
    @Published var selected = Set<String>()
    @Published private(set) var applications: [String: URL] = [:]
    @Published private(set) var outcomes: [String: String] = [:]
    @Published private(set) var failures = Set<String>()
    @Published private(set) var applying = false
    @Published private(set) var bundleError: String?
    private let access: any DefaultApplicationAccess
    private let validateBundle: @MainActor () throws -> URL

    init(access: (any DefaultApplicationAccess)? = nil,
         validateBundle: (@MainActor () throws -> URL)? = nil) {
        self.access = access ?? WorkspaceDefaultApplicationAccess()
        self.validateBundle = validateBundle ?? { try DefaultApplicationsModel.applicationBundle() }
        refresh()
        do {
            let app = try self.validateBundle()
            selected = Set(SignumDocumentAssociation.formats.filter { !$0.optional && !Self.sameApplication(applications[$0.id], app) }.map(\.id))
        } catch { bundleError = error.localizedDescription }
    }
    static func applicationBundle(_ bundle: Bundle = .main) throws -> URL {
        guard bundle.bundleURL.isFileURL, bundle.bundleURL.pathExtension == "app",
              bundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "APPL",
              bundle.bundleIdentifier?.hasPrefix("io.github.tiertoast.Signum") == true,
              let executable = bundle.executableURL, FileManager.default.isExecutableFile(atPath: executable.path),
              bundle.object(forInfoDictionaryKey: "CFBundleDocumentTypes") is [[String: Any]] else {
            throw NSError(domain: "Signum.DefaultApplications", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Installa e apri Signum come applicazione .app prima di modificare le associazioni."])
        }
        return bundle.bundleURL
    }
    static func sameApplication(_ actual: URL?, _ target: URL) -> Bool {
        guard let actual else { return false }
        if actual.standardizedFileURL.resolvingSymlinksInPath() == target.standardizedFileURL.resolvingSymlinksInPath() { return true }
        guard let identifier = Bundle(url: target)?.bundleIdentifier else { return false }
        return Bundle(url: actual)?.bundleIdentifier == identifier
    }
    func refresh() {
        applications = Dictionary(uniqueKeysWithValues: SignumDocumentAssociation.formats.compactMap { format in
            access.currentApplication(for: format.contentType).map { (format.id, $0) }
        })
    }
    func applicationName(for id: String) -> String {
        applications[id].map { FileManager.default.displayName(atPath: $0.path) } ?? "Nessuna app predefinita"
    }
    func apply() async {
        guard !applying, !selected.isEmpty else { return }
        let app: URL
        do { app = try validateBundle(); bundleError = nil }
        catch { bundleError = error.localizedDescription; return }
        let requested = selected
        applying = true
        defer { applying = false; refresh() }
        for format in SignumDocumentAssociation.formats where requested.contains(format.id) {
            outcomes[format.id] = "In attesa della conferma di macOS…"; failures.remove(format.id)
            do {
                try await access.setApplication(app, for: format.contentType)
                refresh()
                if Self.sameApplication(applications[format.id], app) {
                    outcomes[format.id] = "Signum impostata come app predefinita."
                    selected.remove(format.id)
                } else {
                    failures.insert(format.id)
                    outcomes[format.id] = "Associazione non modificata: macOS non ha confermato Signum."
                }
            } catch {
                refresh(); failures.insert(format.id)
                outcomes[format.id] = "Associazione non confermata: \(error.localizedDescription)"
            }
        }
    }
}

@MainActor struct DefaultApplicationsSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model: DefaultApplicationsModel
    init(model: DefaultApplicationsModel? = nil) { _model = StateObject(wrappedValue: model ?? DefaultApplicationsModel()) }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("App predefinita").font(.title2.weight(.semibold))
            Text("Scegli i formati da aprire con questa versione di Signum. macOS può chiedere una conferma per ciascun formato.")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 12) {
                ForEach(SignumDocumentAssociation.formats) { format in
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(isOn: Binding(get: { model.selected.contains(format.id) }, set: { value in
                            if value { model.selected.insert(format.id) } else { model.selected.remove(format.id) }
                        })) {
                            Text(".\(format.id) — \(format.title)" + (format.optional ? " (opzionale)" : ""))
                        }
                        .toggleStyle(.checkbox)
                        Text("Attuale: \(model.applicationName(for: format.id))")
                            .font(.caption).foregroundStyle(.secondary).padding(.leading, 20)
                            .lineLimit(1).truncationMode(.middle).help(model.applications[format.id]?.path ?? "")
                        if let outcome = model.outcomes[format.id] {
                            Text(outcome).font(.caption).foregroundStyle(model.failures.contains(format.id) ? .red : .secondary)
                                .padding(.leading, 20).textSelection(.enabled)
                        }
                    }
                }
            }.disabled(model.applying)
            if let error = model.bundleError { Text(error).foregroundStyle(.red).font(.callout) }
            HStack {
                if model.applying { ProgressView().controlSize(.small); Text("Conferma le richieste di macOS…").font(.caption) }
                Spacer()
                Button(model.outcomes.isEmpty ? "Annulla" : "Chiudi") { dismiss() }
                    .keyboardShortcut(.cancelAction).disabled(model.applying)
                Button("Applica") { Task { await model.apply() } }
                    .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).tint(SignumAppearance.burgundy)
                    .disabled(model.applying || model.selected.isEmpty || model.bundleError != nil)
            }
        }.padding(24).frame(width: 560).fixedSize(horizontal: false, vertical: true)
            .interactiveDismissDisabled(model.applying)
    }
}
#endif
