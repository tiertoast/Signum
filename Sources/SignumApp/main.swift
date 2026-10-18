#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore

private extension Result {
    var isSuccess: Bool { if case .success = self { return true }; return false }
}

func signingApprovalMessage(holder: String, job: SigningJob) -> String {
    "Firmatario: \(holder)\n" + job.approvalDescription
}


@main
struct SignumApp: App {
    var body: some Scene {
        WindowGroup("Signum") {
            SignumWindow()
                .frame(minWidth: 980, minHeight: 650)
        }
        .defaultSize(width: 1320, height: 830)
        // No contentSize restriction: the user can freely resize the window.
    }
}

private enum SignumOperation: String, Hashable {
    case sign, verify, settings
}

private enum SignumFormat: String, Hashable {
    case cades, pades, xades
}

@MainActor struct SignumWindow: View {
    @StateObject private var batch: BatchSigningCoordinator
    @StateObject private var interaction = SigningInteraction()
    @FocusState private var pinFocused: Bool
    @AppStorage(SigningExperiencePreferences.Keys.showExcluded) private var showExcludedCertificates = false
    @AppStorage(SigningExperiencePreferences.Keys.alongsideOriginal) private var saveAlongsideOriginal = true
    @State private var customDirectory: URL?
    @State private var placements: [UUID: PAdESPlacement] = [:]
    @State private var readyPreviews = Set<UUID>()
    @State private var approvedFields: [UUID: SignumPAdESHelper.Field] = [:]
    @State private var approvedHolder = ""
    @State private var approvedRoute: DeviceCertificateRoute?
    @State private var provider: ProviderSelection
    @State private var devices: DeviceSelection
    @State private var discoveryStarted = false
    @State private var showDeviceConfiguration = false
    @State private var manualPath = ""
    @State private var manualPaths: [String]
    @State private var work: SigningOperation?
    @State private var workPhase: SigningOperationPhase = .idle
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @State private var documentSnapshot: DocumentSnapshot?
    @State private var showingPDFPreview = false
    @State private var previewSnapshotID: UUID?
    @State private var selectionRequestID = UUID()
    @State private var inputFile: URL?
    @State private var lastSignedFile: URL?
    @State private var dropTargeted = false
    @State private var status = "Ricerca dei dispositivi di firma…"
    @State private var busy = false

    private let automaticallyDiscover: Bool
    private let preferences: SigningExperiencePreferences

    // Internal dependency injection for native layout tests; no production flag,
    // environment override or automatic loading of user-owned test modules.
    init(batch: BatchSigningCoordinator? = nil, initialDevices: DeviceSelection = .init(),
         initialProvider: ProviderSelection = .init(), selectedSnapshot: DocumentSnapshot? = nil,
         automaticallyDiscover: Bool = true, defaults: UserDefaults = .standard) {
        self.automaticallyDiscover = automaticallyDiscover
        preferences = SigningExperiencePreferences(defaults: defaults)
        _batch = StateObject(wrappedValue: batch ?? BatchSigningCoordinator())
        _devices = State(initialValue: initialDevices); _provider = State(initialValue: initialProvider)
        _manualPaths = State(initialValue: MiddlewarePreferences(defaults: defaults).paths)
        _customDirectory = State(initialValue: SigningExperiencePreferences(defaults: defaults).customDirectory)
        _showExcludedCertificates = AppStorage(wrappedValue: false, SigningExperiencePreferences.Keys.showExcluded, store: defaults)
        _saveAlongsideOriginal = AppStorage(wrappedValue: true, SigningExperiencePreferences.Keys.alongsideOriginal, store: defaults)
        _documentSnapshot = State(initialValue: selectedSnapshot)
        _showingPDFPreview = State(initialValue: selectedSnapshot?.format == .pades)
        _inputFile = State(initialValue: selectedSnapshot?.originalURL)
        _status = State(initialValue: initialDevices.providers.isEmpty ? "Ricerca dei dispositivi di firma…" : initialDevices.message)
    }

    private var interfaceLocked: Bool { busy || batch.isPreparing || batch.isRunning || interaction.isRequestingApproval || interaction.isSubmittingPIN }
    private var destinationPolicy: BatchOutputDestination? {
        SigningDestinationSelection(alongsideOriginal: saveAlongsideOriginal, customDirectory: customDirectory).policy
    }
    private var canApproveBatch: Bool {
        guard !interfaceLocked, !batch.isFrozen, !batch.documents.isEmpty, destinationPolicy != nil,
              provider.signingProvider != nil, provider.selectedSlot != nil,
              let id = provider.selectedCertificateID, provider.certificateAssessments[id]?.permitsSigning == true else { return false }
        return batch.documents.allSatisfy { entry in
            !entry.state.isTerminal && (entry.snapshot.format != .pades ||
                (readyPreviews.contains(entry.id) && SignumPAdESHelper.available))
        }
    }
    private var canAuthorizeNext: Bool {
        !interfaceLocked && interaction.canSubmitPIN(provider.pin, batch: batch)
    }

    private var presentation: SigningPresentation {
        .init(batch: batch, interaction: interaction, destinationReady: destinationPolicy != nil, canApprove: canApproveBatch)
    }

    private var selectedHolder: String {
        guard let certificate = provider.certificates.first(where: { $0.id == provider.selectedCertificateID }) else {
            return "Firmatario"
        }
        return provider.certificateIdentities[certificate.id]?.fullName ?? certificate.label
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: "signature").font(.largeTitle)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Signum").font(.title2.bold())
                    Text("Firma digitale per macOS · sviluppo sperimentale")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(AppVersion.label).font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)
            .padding(.bottom, 12)

            Picker("Sezione", selection: $operation) {
                Text("Firma documento").tag(SignumOperation.sign)
                Text("Verifica .p7m").tag(SignumOperation.verify)
                Text("Impostazioni").tag(SignumOperation.settings)
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .disabled(interfaceLocked || batch.isFrozen)
            .padding(.horizontal, 20)
            .padding(.bottom, 12)

            Divider()

            if operation == .sign {
                HSplitView {
                    VStack(spacing: 0) {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 14) {
                                tokenControls
                                certificateControls
                                formatPicker
                                destinationControls
                            }.padding(16).frame(maxWidth: .infinity, alignment: .topLeading)
                        }.frame(minHeight: 100)
                        Divider()
                        signingControls.padding(.horizontal, 16).padding(.vertical, 10)
                        statusFooter.padding(.horizontal, 16).padding(.bottom, 12)
                    }.frame(minWidth: 350, idealWidth: 420, maxWidth: 500)

                    sessionWorkspace
                        .frame(minWidth: 440, maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        if operation == .verify {
                            CAdESVerificationPane()
                        } else {
                            Button("Configura dispositivo…") { showDeviceConfiguration = true }
                            SignumGraphicSettingsPane()
                        }
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
        }
        .onAppear {
            guard automaticallyDiscover, !discoveryStarted else { return }
            discoveryStarted = true
            discover()
        }
        .sheet(isPresented: $showDeviceConfiguration) {
            DeviceConfigurationView(providers: devices.providers, savedPaths: manualPaths,
                routes: selectedCertificateRoutes, selectedRouteID: devices.selectedRouteID,
                manualPath: $manualPath, locked: interfaceLocked || batch.isFrozen,
                search: { discover() }, browse: chooseManualModule,
                loadManual: { discover(manual: manualPath) }, remove: removeManualModule,
                selectRoute: selectRoute)
        }
        .onChange(of: showExcludedCertificates) { show in
            guard !batch.isFrozen, let route = devices.selectedRoute,
                  !CertificateVisibility(devices.certificates).includes(route: route, showExcluded: show) else { return }
            provider.beginDiscovery(); devices.select(routeID: nil)
            status = "Il certificato escluso è stato nascosto. Scegli un certificato localmente idoneo."
        }
        .onChange(of: format) { _ in provider.pin = "" }
        .onChange(of: saveAlongsideOriginal) { _ in if !batch.isFrozen { provider.pin = "" } }
        .onDisappear {
            work?.requestCancellation()
            batch.cancelAll()
            selectionRequestID = UUID()
            devices.beginDiscovery(); provider.beginDiscovery()
            documentSnapshot = nil
        }
    }

    private var formatPicker: some View {
        GroupBox("Tipologia di firma") {
            Picker("Formato", selection: $format) {
                Text("CAdES — documento .p7m").tag(SignumFormat.cades)
                Text("PAdES — PDF firmato").tag(SignumFormat.pades)
                Text("XAdES — prossimamente").tag(SignumFormat.xades).disabled(true)
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .frame(maxWidth: .infinity, alignment: .leading)
            .disabled(interfaceLocked || batch.isFrozen)
            .padding(5)
        }
    }

    @ViewBuilder private var sessionWorkspace: some View {
        if documentSnapshot?.format == .pades {
            VStack(spacing: 0) {
                Picker("Visualizzazione", selection: $showingPDFPreview) {
                    Text("Documenti ed esiti").tag(false)
                    Text("Anteprima PDF").tag(true)
                }.pickerStyle(.segmented).labelsHidden().padding(12)
                if showingPDFPreview {
                    ScrollView { pdfWorkspace.frame(minHeight: 560) }
                } else { documentSession }
            }
        } else { documentSession }
    }

    private var documentSession: some View {
        GroupBox("Documenti della sessione") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("\(batch.documents.count) documenti · nuovi file in \(format.rawValue.uppercased())").font(.callout)
                    Spacer()
                    Button("Aggiungi…") { chooseFile() }.disabled(interfaceLocked || batch.isFrozen)
                    if !batch.documents.isEmpty {
                        Button("Nuova sessione") { resetSession() }.disabled(interfaceLocked)
                    }
                }
                Text("Trascina qui i documenti. Le copie firmate usano i byte selezionati, anche se l'originale cambia.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 28)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.3)))
                    .onDrop(of: [UTType.fileURL.identifier], isTargeted: $dropTargeted, perform: receiveDrop)
                if !batch.documents.isEmpty {
                    ProgressView(value: Double(batch.finishedCount), total: Double(max(1, batch.documents.count)))
                    Text("\(batch.finishedCount) di \(batch.documents.count) conclusi · \(presentation.resultSummary)").font(.caption)
                }
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if batch.documents.isEmpty { Text("Aggiungi uno o più documenti per preparare la firma.").foregroundStyle(.secondary).padding() }
                        ForEach(batch.documents) { entry in documentRow(entry) }
                        ForEach(Array(batch.selectionIssues.enumerated()), id: \.offset) { _, message in Text(message).font(.caption) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("Massimo 32 documenti e 128 MiB per sessione.").font(.caption2).foregroundStyle(.secondary)
                if !batch.selectionTechnicalDetails.isEmpty {
                    DisclosureGroup("Dettagli tecnici acquisizione") {
                        Text(batch.selectionTechnicalDetails.joined(separator: "\n")).font(.caption2).textSelection(.enabled)
                    }
                }
                if !batch.documents.isEmpty {
                    DisclosureGroup("Resoconto e dettagli tecnici") {
                        ScrollView { Text(batch.sessionReport).font(.caption2).textSelection(.enabled) }.frame(maxHeight: 100)
                    }
                }
            }.padding(7)
        }.padding(12)
    }

    private func documentRow(_ entry: BatchDocument) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Button(entry.snapshot.originalURL.lastPathComponent) { showDocument(entry.id) }
                    .font(.headline).lineLimit(2).disabled(batch.isRunning || interaction.isSubmittingPIN)
                Text(entry.snapshot.format.rawValue.uppercased()).font(.caption)
                Spacer()
                Text(entry.state.message).font(.caption)
                if !batch.isFrozen {
                    Button("Rimuovi") {
                        let selected = documentSnapshot?.identity.id == entry.id
                        batch.remove(entry.id); placements[entry.id] = nil; readyPreviews.remove(entry.id)
                        if selected { showDocument(batch.documents.first?.id) }
                    }.disabled(interfaceLocked)
                } else if batch.isApproved && !entry.state.isTerminal {
                    Button("Annulla") { batch.cancelDocument(entry.id); provider.pin = "" }
                        .disabled((batch.isRunning || interaction.isSubmittingPIN) && batch.nextDocument?.id == entry.id)
                }
            }
            Text("Origine: " + BatchDisplay.sourceLabel(entry.snapshot.originalURL, among: batch.documents.map { $0.snapshot.originalURL }))
                .font(.caption).foregroundStyle(.secondary)
            let proposed = entry.destination ?? destinationPolicy?.proposedURL(for: entry.snapshot)
            if let proposed {
                Text((entry.destination == nil ? "Destinazione prevista: " : "Destinazione: ") +
                     BatchDisplay.destinationLabel(proposed, among: batch.documents.compactMap { $0.destination ?? destinationPolicy?.proposedURL(for: $0.snapshot) }))
                    .font(.caption).textSelection(.enabled)
            } else { Text("Destinazione da scegliere").font(.caption) }
            if !entry.result.isEmpty { Text(entry.result).font(.caption) }
            DisclosureGroup("Dettagli tecnici del documento") {
                Text("Origine: \(entry.snapshot.originalURL.path)\nDestinazione: \(proposed?.path ?? "Da scegliere")\n\(entry.snapshot.identity.byteCount) byte · SHA-256 \(entry.snapshot.identity.sha256)\nSnapshot: \(entry.id)")
                    .font(.caption2).textSelection(.enabled)
            }
            Divider()
        }.padding(.vertical, 4)
    }

    private func resetSession() {
        guard !interfaceLocked else { return }
        batch.reset(); placements = [:]; readyPreviews = []; approvedFields = [:]; approvedRoute = nil
        showDocument(nil); provider.pin = ""; lastSignedFile = nil
        status = "Nuova sessione. Scegli i documenti da firmare."
    }

    private var destinationControls: some View {
        GroupBox("Destinazione") {
            VStack(alignment: .leading, spacing: 8) {
                if batch.isFrozen {
                    Text("Destinazioni fissate nel riepilogo. Per cambiarle prepara e conferma una nuova sessione.").font(.caption)
                } else {
                    Toggle("Salva nella cartella dell'originale", isOn: $saveAlongsideOriginal)
                    if saveAlongsideOriginal {
                        Text("Ogni copia firmata va accanto al proprio originale, anche per documenti in cartelle diverse.").font(.caption)
                    } else {
                        HStack {
                            Text(customDirectory?.lastPathComponent ?? "Scegli una cartella comune").font(.caption)
                            Spacer()
                            Button("Sfoglia…") { chooseDestination() }
                        }
                        if let customDirectory {
                            DisclosureGroup("Dettagli della cartella") { Text(customDirectory.path).font(.caption2).textSelection(.enabled) }
                        }
                    }
                    Text("I nomi liberi saranno fissati nel riepilogo. Nessun file esistente verrà sovrascritto.").font(.caption2).foregroundStyle(.secondary)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(5).disabled(interfaceLocked)
        }
    }

    private func chooseDestination() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Cartella comune delle copie firmate"
        picker.canChooseFiles = false; picker.canChooseDirectories = true
        picker.allowsMultipleSelection = false; picker.canCreateDirectories = false
        picker.directoryURL = customDirectory
        if picker.runModal() == .OK, let directory = picker.url {
            customDirectory = directory; preferences.customDirectory = directory
            provider.pin = ""
        }
    }

    private var tokenControls: some View {
        GroupBox("Dispositivi di firma") {
            VStack(alignment: .leading, spacing: 8) {
                Text(devices.message).font(.caption)
                HStack {
                    Button("Cerca nuovamente") { discover() }
                    Button("Configura dispositivo…") { showDeviceConfiguration = true }
                }.disabled(interfaceLocked || batch.isFrozen)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(5)
        }
    }

    private var selectedCertificateRoutes: [DeviceCertificateRoute] {
        guard let selected = devices.selectedRoute else { return [] }
        return devices.certificates.first(where: { $0.id == selected.certificateFingerprint })?.routes ?? []
    }

    private var certificateControls: some View {
        GroupBox("Scegli il certificato") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Mostra certificati non idonei", isOn: $showExcludedCertificates)
                    .disabled(interfaceLocked || batch.isFrozen)
                if CertificateVisibility(devices.certificates).eligible.isEmpty && !devices.isSearching {
                    Text("Nessun certificato localmente idoneo alla firma.").font(.caption)
                }
                ForEach(CertificateVisibility(devices.certificates).visible(showExcluded: showExcludedCertificates)) { group in
                    if let route = group.routes.first(where: { $0.id == devices.selectedRouteID }) ?? group.routes.first {
                        Button {
                            if devices.selectedRoute?.certificateFingerprint != group.id {
                                let preferred = MiddlewarePreferences(defaults: preferences.defaults).preferredPath
                                selectRoute(group.routes.first(where: { $0.providerPath == preferred })?.id ?? route.id)
                            }
                        } label: {
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: devices.selectedRoute?.certificateFingerprint == group.id ? "largecircle.fill.circle" : "circle")
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(route.title).font(.subheadline.weight(.semibold))
                                    if let organization = route.identity?.organization { Text(organization).font(.caption) }
                                    Text("Emittente: \(route.identity?.issuer ?? "non disponibile")").font(.caption)
                                    Text("Scadenza: \(route.assessment.notAfter?.formatted(date: .numeric, time: .omitted) ?? "non disponibile")").font(.caption)
                                    Text(route.purpose).font(.caption)
                                    if !route.assessment.permitsSigning { Text(route.assessment.explanation).font(.caption2) }
                                    Text(route.deviceDescription).font(.caption).foregroundStyle(.secondary)
                                    if group.routes.count > 1 {
                                        Text("Disponibile tramite \(group.routes.count) vie di accesso · scelta in Configura dispositivo").font(.caption2)
                                    }
                                }
                                Spacer(minLength: 0)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                        }.buttonStyle(.plain).disabled(interfaceLocked || batch.isFrozen)
                    }
                }
                if !showExcludedCertificates {
                    let filtered = CertificateVisibility(devices.certificates)
                    if !filtered.ineligible.isEmpty { Text("\(filtered.ineligible.count) certificati non idonei nascosti.").font(.caption2) }
                    if !filtered.indeterminate.isEmpty {
                        DisclosureGroup("Idoneità non determinabile: \(filtered.indeterminate.count) certificati · dettagli avanzati") {
                            ForEach(filtered.indeterminate) { group in
                                if let route = group.routes.first {
                                    Text(route.title).font(.caption.weight(.semibold))
                                    Text(route.assessment.explanation).font(.caption2)
                                }
                            }
                            Text("Questi certificati non possono autorizzare una firma. Attiva il filtro per consultarne tutti i dettagli.").font(.caption2)
                        }
                    }
                }
                if let selected = devices.selectedRoute {
                    Text("Software selezionato: \(selected.providerName)").font(.caption)
                    Text(selected.assessment.explanation).font(.caption)
                    DisclosureGroup("Dettagli tecnici del certificato") {
                        Text("Provider: \(selected.providerPath)\nSlot: \(selected.token.slot) · ID: \(selected.certificate.id)\nSHA-256: \(selected.certificateFingerprint)\n\(selected.assessment.usageDescription)")
                            .font(.caption2).textSelection(.enabled)
                        DisclosureGroup("Certificato pubblico DER (Base64)") {
                            ScrollView { Text(selected.der.base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled) }
                                .frame(maxHeight: 100)
                        }
                    }
                }
                Text(CertificateEligibility.scope).font(.caption2).foregroundStyle(.secondary)
            }.padding(5)
        }
    }

    private var signingControls: some View {
        GroupBox("Firma") {
            VStack(alignment: .leading, spacing: 10) {
                if !batch.isApproved {
                    Button(presentation.signButtonTitle) { prepareBatch() }.disabled(!canApproveBatch)
                    Text("Il riepilogo include tutti i documenti. Per ogni PDF apri prima l'anteprima dall'elenco.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    if let prompt = presentation.pinPrompt, let next = batch.nextDocument {
                        Text(prompt).font(.headline)
                        Text(next.snapshot.originalURL.lastPathComponent).font(.caption).lineLimit(2)
                        SecureField("PIN del dispositivo", text: $provider.pin)
                            .textFieldStyle(.roundedBorder).privacySensitive().focused($pinFocused)
                            .onSubmit { authorizeNextDocument() }.onAppear { pinFocused = true }
                            .disabled(interfaceLocked)
                        Button("Firma") { authorizeNextDocument() }.disabled(!canAuthorizeNext)
                    }
                    if presentation.stage == .completed { Text("Sessione conclusa. Consulta gli esiti a destra.").font(.caption) }
                    if batch.needsOutcomeReview {
                        Text("Esito incerto: controlla dispositivo ed eventuale output prima di continuare. La firma non verrà ripetuta.").font(.caption)
                        Button("Ho verificato l'esito: consenti il prossimo documento") { batch.acknowledgeUncertainOutcome(); provider.pin = "" }
                            .disabled(batch.isRunning)
                    }
                    Button("Annulla documenti in attesa") { batch.cancelPending(); provider.pin = "" }
                        .disabled(batch.nextDocument == nil)
                    if batch.isRunning {
                        ProgressView().controlSize(.small)
                        Button("Interrompi firma corrente") { batch.activeOperation?.requestCancellation() }
                    }
                }
                if batch.isPreparing { ProgressView("Preparazione documenti…").controlSize(.small) }
                if batch.isPreparing {
                    Button("Annulla selezione in preparazione") { batch.cancelAll() }
                }
                if busy, work == nil, !batch.isPreparing {
                    Button("Annulla caricamento") { selectionRequestID = UUID(); busy = false }
                }
                if busy, let work {
                    ProgressView(workPhase.message).controlSize(.small)
                    Button("Annulla lettura") { work.requestCancellation() }
                }
                Text("La conferma fissa i documenti da firmare. Il PIN autorizza una firma alla volta e non viene conservato per il documento successivo. Nessun tentativo automatico aggiuntivo.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
    }

    private var statusFooter: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text(status).font(.caption).textSelection(.enabled)
            Spacer(minLength: 0)
            if let file = lastSignedFile {
                Button("Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([file])
                }
            }
        }
    }

    @ViewBuilder
    private var pdfWorkspace: some View {
        if let snapshot = documentSnapshot, snapshot.format == .pades {
            PAdESPlacementPane(
                snapshot: snapshot,
                previewReady: { id, ready in
                    guard documentSnapshot?.identity.id == id else { return }
                    if ready { previewSnapshotID = id; readyPreviews.insert(id) }
                    if !ready {
                        batch.remove(id); showDocument(batch.documents.first?.id); provider.pin = ""
                        status = "Anteprima non disponibile: seleziona un PDF valido e non protetto."
                    }
                },
                holder: selectedHolder,
                placement: Binding(get: { pdfPlacement }, set: { value in
                    guard !interfaceLocked, !batch.isFrozen, documentSnapshot?.identity.id == snapshot.identity.id else { return }
                    pdfPlacement = value; placements[snapshot.identity.id] = value
                })
            )
            .id(snapshot.identity.id)
            .disabled(interfaceLocked || batch.isFrozen)
            .allowsHitTesting(!busy)
            .padding(14)
        } else {
            VStack(spacing: 14) {
                Image(systemName: format == .pades ? "doc.text.magnifyingglass" : "doc.text")
                    .font(.system(size: 52))
                    .foregroundStyle(.tertiary)
                Text(format == .pades ? "Anteprima PDF" : "Firma documento")
                    .font(.title3.weight(.medium))
                Text(format == .pades
                     ? "Seleziona un PDF per visualizzarlo e posizionare la firma."
                     : "Con CAdES il documento viene incorporato in una busta .p7m.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func beginWork() -> SigningOperation {
        let id = UUID()
        let operation = SigningOperation(id: id) { phase in
            DispatchQueue.main.async { if self.work?.id == id { self.workPhase = phase } }
        }
        work = operation; workPhase = .preparing
        operation.transition(to: .preparing)
        return operation
    }

    private func discover(manual: String? = nil) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let paths = manual.map { [$0.trimmingCharacters(in: .whitespacesAndNewlines)] } ?? []
        if let path = paths.first {
            guard MiddlewarePreferences.valid(path) else { status = "Scegli un percorso assoluto valido."; return }
            MiddlewarePreferences(defaults: preferences.defaults).remember(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        }
        provider.beginDiscovery()
        let request = devices.beginDiscovery(), operation = beginWork()
        busy = true; status = "Ricerca dei dispositivi in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let results = MiddlewareDiscovery().discover(registry: paths.isEmpty ? MiddlewareRegistry.known : [],
                manualPaths: paths, isCancelled: { operation.isCancellationRequested })
            let prepared = DeviceDiscoveryResult(providers: operation.isCancellationRequested ? [] : results)
            DispatchQueue.main.async {
                guard self.devices.requestID == request else { return }
                self.busy = false; self.work = nil
                if operation.isCancellationRequested {
                    self.devices.cancelDiscovery(); self.provider.beginDiscovery()
                    self.status = "Ricerca annullata. Cerca nuovamente."; return
                }
                guard self.devices.accept(prepared, request: request) else { return }
                self.status = self.devices.message
            }
        }
    }

    private func selectRoute(_ id: String) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        provider.beginDiscovery() // Clears certificate caches and PIN atomically.
        guard devices.select(routeID: id), let route = devices.selectedRoute else { return }
        provider.select(route: route)
        MiddlewarePreferences(defaults: preferences.defaults).prefer(route.providerPath)
        status = "Certificato selezionato: \(route.title). \(route.assessment.status.description)."
    }

    private func chooseManualModule() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona il software del dispositivo"
        picker.canChooseFiles = true; picker.canChooseDirectories = false; picker.allowsMultipleSelection = false
        if picker.runModal() == .OK, let path = picker.url?.path { manualPath = path }
    }

    private func removeManualModule(_ path: String) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        MiddlewarePreferences(defaults: preferences.defaults).remove(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        if manualPath == path { manualPath = "" }
        devices.beginDiscovery(); provider.beginDiscovery()
        status = "Configurazione manuale rimossa. Cerca nuovamente per scegliere un certificato."
    }

    private func chooseFile() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona i documenti da firmare"
        picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if format == .pades { picker.allowedContentTypes = [.pdf] }
        if picker.runModal() == .OK { addDocuments(picker.urls) }
    }

    private func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !interfaceLocked, !batch.isFrozen else { return false }
        let items = Array(providers.filter { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }.prefix(BatchSigningCoordinator.maximumDocuments))
        guard !items.isEmpty else { return false }
        busy = true
        let request = UUID(); selectionRequestID = request
        Task { @MainActor in
            let urls = await FileDropResolution.resolve(items)
            guard selectionRequestID == request else { return }
            busy = false
            addDocuments(urls)
        }
        return true
    }

    private func addDocuments(_ urls: [URL]) {
        guard !interfaceLocked, !batch.isFrozen, let kind = SigningFormat(rawValue: format.rawValue) else { return }
        provider.pin = ""
        Task { @MainActor in
            await batch.addDocuments(urls, format: kind)
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(batch.documents.count) documenti nella selezione. Controllali prima della conferma."
        }
    }

    private func showDocument(_ id: UUID?) {
        if let old = documentSnapshot, batch.documents.contains(where: { $0.id == old.identity.id }) { placements[old.identity.id] = pdfPlacement }
        documentSnapshot = batch.documents.first(where: { $0.id == id })?.snapshot
        showingPDFPreview = documentSnapshot?.format == .pades
        inputFile = documentSnapshot?.originalURL
        pdfPlacement = id.flatMap { placements[$0] }
        previewSnapshotID = nil
    }

    private func prepareBatch() {
        guard canApproveBatch, let selectedProvider = provider.signingProvider, let slot = provider.selectedSlot,
              let certificate = provider.certificates.first(where: { $0.id == provider.selectedCertificateID }),
              let der = provider.certificateDERs[certificate.id], let selectedRoute = devices.selectedRoute,
              let destination = destinationPolicy else { return }
        provider.pin = ""; busy = true
        let holder = selectedHolder, selectionGeneration = devices.requestID
        if let snapshot = documentSnapshot { placements[snapshot.identity.id] = pdfPlacement }
        let fields = placements.mapValues { value in SignumPAdESHelper.Field(pageIndex: value.pageIndex,
            x: Double(value.rectangle.minX), y: Double(value.rectangle.minY), width: Double(value.rectangle.width), height: Double(value.rectangle.height)) }
        Task { @MainActor in
            defer { busy = false }
            do {
                let approved = try await interaction.prepareAndConfirm(batch: batch, prepare: {
                    try await Task.detached(priority: .userInitiated) { try selectedRoute.requireCurrentModule() }.value
                    guard devices.requestID == selectionGeneration, devices.selectedRouteID == selectedRoute.id else { throw SupervisedProcess.Failure.cancelled }
                    return try await batch.prepareApproval(provider: selectedProvider, slot: slot, certificate: certificate, der: der, destination: destination)
                }, present: { approval in
                    let alert = NSAlert()
                    alert.messageText = "Conferma firma"
                    alert.informativeText = "Firmatario: \(holder)\nCertificato: \(selectedRoute.title) · \(selectedRoute.identity?.issuer ?? "Emittente non disponibile")\n\(approval.jobs.count) documenti. Seguirà il PIN per ogni firma."
                    let content = NSHostingView(rootView: BatchConsentView(approval: approval))
                    content.frame = NSRect(x: 0, y: 0, width: 560, height: 320)
                    alert.accessoryView = content
                    alert.addButton(withTitle: "Conferma e prosegui"); alert.addButton(withTitle: "Annulla")
                    return alert.runModal() == .alertFirstButtonReturn
                })
                if approved != nil {
                    approvedFields = fields; approvedHolder = holder; approvedRoute = selectedRoute
                    status = "Documenti confermati. Inserisci il PIN per la firma corrente."
                } else { status = "Conferma annullata. Nessuna firma avviata." }
            } catch { status = error.localizedDescription }
        }
    }

    private func authorizeNextDocument() {
        guard canAuthorizeNext else { return }
        let fields = approvedFields, holder = approvedHolder
        guard let route = approvedRoute else { return }
        showingPDFPreview = false
        interaction.submitPIN(&provider.pin, batch: batch, execute: { job, pin, operation in
            try route.requireCurrentModule()
            if job.format == .cades { try job.signCAdES(using: IsolatedPKCS11Client(), pin: pin, operation: operation) }
            else { try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: holder,
                field: fields[job.snapshotIdentity.id], operation: operation) }
        }, completion: { result in
            lastSignedFile = batch.documents.last(where: { $0.state == .completed })?.destination
            switch result {
            case .success:
                status = batch.nextDocument == nil ? "Sessione conclusa. Consulta gli esiti." : "Inserisci il PIN per la firma successiva."
            case .failure(let error): status = error.localizedDescription
            }
        })
    }

}
#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
