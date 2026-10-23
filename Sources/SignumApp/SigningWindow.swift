#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration

enum SignumFormat: String, Hashable {
    case cades, cadesDetached, cadesCoSign, cadesCounterSign, pades, xades, asics, asice
}

@MainActor struct SignumWindow: View {
    let trustedLists: TrustedListsModel?
    @StateObject var batch: BatchSigningCoordinator
    @StateObject var interaction = SigningInteraction()
    @StateObject var review = SigningReview()
    @StateObject var results: SigningSessionResults
    @Environment(\.colorScheme) var colorScheme
    @Environment(\.accessibilityReduceTransparency) var reduceTransparency
    @State var refresh = DeviceRefreshLifecycle()
    @State var discoveryOperation: SigningOperation?
    @AppStorage(SigningExperiencePreferences.Keys.batchAuthentication) var authenticationModeRaw = BatchAuthenticationMode.automatic.rawValue
    @AppStorage(SigningExperiencePreferences.Keys.includeSigningTime) var includeSigningTime = true
    @State var approvedAuthenticationMode: BatchAuthenticationMode = .perSignature
    @State var authenticationSession: BatchCAdESSession?
    @State var authenticationAttempted = false
    @State var authenticationStatus = ""
    @AppStorage(SigningExperiencePreferences.Keys.additionalConfirmation) var additionalConfirmation = false
    @FocusState var pinFocused: Bool
    @AppStorage(SigningExperiencePreferences.Keys.showExcluded) var showExcludedCertificates = false
    @AppStorage(SigningExperiencePreferences.Keys.alongsideOriginal) var saveAlongsideOriginal = true
    @State var customDirectory: URL?
    @State var placements: [UUID: PAdESPlacement] = [:]
    @State var readyPreviews = Set<UUID>()
    @State var approvedHolder = ""
    @State var approvedRoute: DeviceCertificateRoute?
    @State var provider: ProviderSelection
    @State var devices: DeviceSelection
    @State var discoveryStarted = false
    @State var showDeviceConfiguration = false
    @State var manualPath = ""
    @State var manualPaths: [String]
    @State var authorizedManualPaths: [String] = []
    @State var work: SigningOperation?
    @State var workPhase: SigningOperationPhase = .idle
    @State var sidebarVisibility: NavigationSplitViewVisibility
    @State var navigation = SignumNavigation()
    var operation: SignumSection? {
        get { navigation.section }
        nonmutating set { navigation.select(newValue ?? .sign) }
    }
    @State var showSigningOptions = false
    @State var format: SignumFormat = .cades
    @State var pdfPlacement: PAdESPlacement?
    @StateObject var workspace: SigningWorkspaceSelection
    var documentSnapshot: DocumentSnapshot? { workspace.snapshot }
    var selectedDocument: BatchDocument? { batch.documents.first { $0.id == documentSnapshot?.identity.id } }
    @State var previewSnapshotID: UUID?
    @State var selectionRequestID = UUID()
    @State var inputFile: URL?
    @State var lastSignedFile: URL?
    @State var dropTargeted = false
    @State var status = "Ricerca dei dispositivi di firma…"
    @State var busy = false

    let automaticallyDiscover: Bool
    let preferences: SigningExperiencePreferences

    // Internal dependency injection for native layout tests; no production flag,
    // environment override or automatic loading of user-owned test modules.
    init(batch: BatchSigningCoordinator? = nil, initialDevices: DeviceSelection = .init(),
         initialProvider: ProviderSelection = .init(), selectedSnapshot: DocumentSnapshot? = nil,
         automaticallyDiscover: Bool = true, defaults: UserDefaults = .standard,
         workspace: SigningWorkspaceSelection? = nil, trustedLists: TrustedListsModel? = nil,
         initialSection: SignumSection = .sign, initiallyExpandedDetails: Bool = false,
         sessionResults: SigningSessionResults? = nil,
         initialSidebarVisibility: NavigationSplitViewVisibility = .all) {
        _sidebarVisibility = State(initialValue: initialSidebarVisibility)
        _results = StateObject(wrappedValue: sessionResults ?? SigningSessionResults())
        _navigation = State(initialValue: SignumNavigation(section: initialSection))
        _showSigningOptions = State(initialValue: initiallyExpandedDetails)
        self.trustedLists = trustedLists
        self.automaticallyDiscover = automaticallyDiscover
        preferences = SigningExperiencePreferences(defaults: defaults)
        _batch = StateObject(wrappedValue: batch ?? BatchSigningCoordinator())
        _devices = State(initialValue: initialDevices); _provider = State(initialValue: initialProvider)
        _manualPaths = State(initialValue: MiddlewarePreferences(defaults: defaults).paths)
        _customDirectory = State(initialValue: SigningExperiencePreferences(defaults: defaults).customDirectory)
        _authenticationModeRaw = AppStorage(wrappedValue: BatchAuthenticationMode.automatic.rawValue, SigningExperiencePreferences.Keys.batchAuthentication, store: defaults)
        _includeSigningTime = AppStorage(wrappedValue: true, SigningExperiencePreferences.Keys.includeSigningTime, store: defaults)
        _additionalConfirmation = AppStorage(wrappedValue: false, SigningExperiencePreferences.Keys.additionalConfirmation, store: defaults)
        _showExcludedCertificates = AppStorage(wrappedValue: false, SigningExperiencePreferences.Keys.showExcluded, store: defaults)
        _saveAlongsideOriginal = AppStorage(wrappedValue: true, SigningExperiencePreferences.Keys.alongsideOriginal, store: defaults)
        _workspace = StateObject(wrappedValue: workspace ?? SigningWorkspaceSelection(snapshot:selectedSnapshot,format:batch?.documents.first { $0.id == selectedSnapshot?.identity.id }?.format))
        _inputFile = State(initialValue: selectedSnapshot?.originalURL)
        _status = State(initialValue: initialDevices.providers.isEmpty ? "Ricerca dei dispositivi di firma…" : initialDevices.message)
    }

    var interfaceLocked: Bool { busy || batch.isPreparing || batch.isRunning || batch.isContinuingAuthenticated || (authenticationSession?.canContinue ?? false) || interaction.isRequestingApproval || interaction.isSubmittingPIN }
    var authenticationMode: BatchAuthenticationMode { BatchAuthenticationMode(rawValue: authenticationModeRaw) ?? .perSignature }
    var authenticationExplanation: String {
        BatchAuthenticationPolicy.explanation(formats: batch.documents.map(\.format),
            serial: devices.selectedRoute?.token.serial ?? "", mode: batch.isApproved ? approvedAuthenticationMode : authenticationMode)
    }
    var destinationPolicy: BatchOutputDestination? {
        SigningDestinationSelection(alongsideOriginal: saveAlongsideOriginal, customDirectory: customDirectory).policy
    }
    var reviewContext: SigningReviewContext? {
        guard !batch.isPreparing, !batch.documents.isEmpty, let destination = destinationPolicy,
              let path = provider.signingProvider, let slot = provider.selectedSlot,
              let id = provider.selectedCertificateID, let route = devices.selectedRoute,
              let certificate = provider.certificates.first(where: { $0.id == id }),
              let der = provider.certificateDERs[id], provider.certificateAssessments[id]?.permitsSigning == true,
              batch.documents.allSatisfy({ !$0.state.isTerminal && ($0.format != .pades ||
                (readyPreviews.contains($0.id) && placements[$0.id]?.appearance?.certificateSHA256 == route.certificateFingerprint && SignumPAdESHelper.available)) }) else { return nil }
        return .init(revision: batch.revision, provider: path, slot: slot, certificate: certificate,
                     der: der, destination: destination, routeID: route.id, discoveryID: devices.requestID, appearanceHashes: placements.compactMapValues { $0.appearance?.approvalIdentity },
                     providerContext: route.signingContext(discoveryID: devices.requestID), includeSigningTime: includeSigningTime)
    }
    var canApproveBatch: Bool {
        !interfaceLocked && !batch.isFrozen && !workspace.showingPDFPreview && review.matches(reviewContext, batch: batch)
    }
    var canAuthorizeNext: Bool {
        !interfaceLocked && interaction.canSubmitPIN(provider.pin, batch: batch)
    }

    var presentation: SigningPresentation {
        .init(batch: batch, interaction: interaction, destinationReady: destinationPolicy != nil, canApprove: canApproveBatch)
    }

    var selectedHolder: String {
        guard let certificate = provider.certificates.first(where: { $0.id == provider.selectedCertificateID }) else {
            return "Firmatario"
        }
        return provider.certificateIdentities[certificate.id]?.fullName ?? certificate.label
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $sidebarVisibility) {
            List(selection: Binding(get: { operation }, set: { if !interfaceLocked && !batch.isFrozen { operation = $0 } })) {
                Label("Firma", systemImage: SignumSection.sign.symbol)
                    .tag(SignumSection.sign)
                Label("Verifica", systemImage: SignumSection.verify.symbol)
                    .tag(SignumSection.verify)
                Label("Dispositivi", systemImage: SignumSection.devices.symbol)
                    .tag(SignumSection.devices)

            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
            .disabled(interfaceLocked || batch.isFrozen)
        } detail: {
            VStack(spacing: 0) {
                switch operation ?? .sign {
                case .sign:
                    signingScreen
                case .verify:
                    ScrollView {
                        UnifiedVerificationPane(catalog: trustedLists?.catalogProvider)
                            .padding(20)
                    }
                case .devices:
                    devicesScreen
                case .settings:
                    settingsScreen
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background {
                Color(nsColor: .windowBackgroundColor)
                    .modifier(SignumChromeExtension(enabled: !reduceTransparency))
            }
        }
        .navigationSplitViewStyle(.automatic)
        .toolbarBackground(.automatic, for: .windowToolbar)
        .navigationTitle("Signum")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                if navigation.section == .settings {
                    Button { navigation.back() } label: { Label("Indietro", systemImage: "chevron.backward") }
                        .help("Torna a " + navigation.settingsOrigin.title)
                        .accessibilityIdentifier("signum.settings-back")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                if (operation ?? .sign) == .sign {
                    Button(action: chooseFile) {
                        Label("Aggiungi documenti", systemImage: "plus")
                    }
                    .disabled(interfaceLocked || batch.isFrozen)
                    .help("Aggiungi documenti alla sessione di firma")
                }
            }
            ToolbarItem(placement: .automatic) {
                Button(action: { discover() }) {
                    Label("Aggiorna dispositivi", systemImage: "arrow.clockwise")
                }
                .disabled(interfaceLocked || batch.isFrozen || devices.isSearching)
                .help(batch.isFrozen ? "Disponibile dopo la conclusione della sessione approvata" : "Aggiorna dispositivi, token e certificati senza PIN")
            }
            ToolbarItem(placement: .automatic) {
                if devices.isSearching { ProgressView().controlSize(.small).accessibilityLabel("Ricerca dispositivi in corso") }
            }
            ToolbarItem(placement: .automatic) {
                Button { navigation.openSettings(blocked: interfaceLocked || batch.isFrozen) } label: { Label("Impostazioni", systemImage: "gearshape") }
                    .disabled(interfaceLocked || batch.isFrozen)
            }
        }
        .tint(colorScheme == .dark ? SignumAppearance.burgundyForeground : SignumAppearance.burgundy)
        .onReceive(NotificationCenter.default.publisher(for: .signumShowSettings)) { _ in
            navigation.openSettings(blocked: interfaceLocked || batch.isFrozen)
        }
        .task(id: sessionCompletionKey) { releaseFinishedSession() }
        .onAppear {
            guard automaticallyDiscover, !discoveryStarted else { return }
            discoveryStarted = true
            discover()
        }
        .sheet(isPresented: $showDeviceConfiguration) {
            DeviceConfigurationView(providers: devices.providers, savedPaths: manualPaths,
                routes: selectedCertificateRoutes, selectedRouteID: devices.selectedRouteID,
                manualPath: $manualPath, locked: interfaceLocked || batch.isFrozen || devices.isSearching,
                browse: chooseManualModule,
                loadManual: { discover(manual: manualPath) }, remove: removeManualModule,
                selectRoute: selectRoute)
        }
        .task(id: batch.isFrozen ? nil : reviewContext) {
            let context = reviewContext, route = devices.selectedRoute
            await review.prepare(context, batch: batch, appearances: placements.compactMapValues { $0.appearance }, validateCancellable: { control in try route?.requireCurrentCredential(isCancelled: { control.isCancellationRequested }) })
            if review.credentialUnavailable, review.context == context, !batch.isFrozen {
                devices.select(routeID:nil); provider.beginDiscovery(); batch.invalidateReview()
                status = DeviceCertificateRoute.AvailabilityFailure.unavailable.localizedDescription
            }
        }
        .onChange(of: showExcludedCertificates) { show in
            guard !batch.isFrozen, let route = devices.selectedRoute,
                  !CertificateVisibility(devices.certificates).includes(route: route, showExcluded: show) else { return }
            provider.beginDiscovery(); devices.select(routeID: nil)
            status = "Il certificato escluso è stato nascosto. Scegli un certificato localmente idoneo."
        }
        .onChange(of: format) { _ in provider.pin = "" }
        .onChange(of: batch.revision) { _ in
            if let entry = selectedDocument { workspace.updateFormat(entry.format) }
            else if documentSnapshot != nil { showDocument(batch.documents.first?.id) }
        }
        .onChange(of: saveAlongsideOriginal) { _ in if !batch.isFrozen { provider.pin = "" } }
        .onDisappear {
            review.cancel()
            authenticationSession?.requestStop()
            work?.requestCancellation()
            discoveryOperation?.requestCancellation()
            batch.cancelAll()
            selectionRequestID = UUID()
            devices.beginDiscovery(); provider.beginDiscovery()
            workspace.select(nil)
        }
    }

    var devicesScreen: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Dispositivi e certificati")
                    .font(.headline)
                Text("Visualizza i dispositivi collegati e scegli il certificato da usare per la firma.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                tokenControls
                certificateControls
            }
            .padding(22)
            .frame(maxWidth: 760, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }

    var formatBinding: Binding<SignumFormat> {
        Binding(get: { selectedDocument.flatMap { SignumFormat(rawValue:$0.format.rawValue) } ?? format },
                set: { value in
                    guard let kind=SigningFormat(rawValue:value.rawValue) else { return }
                    if let current=selectedDocument { setDocumentFormat(kind,for:current.id) }
                    else { format=value }
                })
    }
    func setDocumentFormat(_ kind:SigningFormat,for id:UUID) {
        guard !interfaceLocked, !batch.isFrozen,
              let entry=batch.documents.first(where:{$0.id == id}), entry.format != kind else { return }
        do {
            try batch.setFormat(kind,for:id)
            placements[id]=nil; readyPreviews.remove(id); provider.pin=""
            if documentSnapshot?.identity.id == id { pdfPlacement=nil; workspace.updateFormat(kind) }
            status="Formato aggiornato a \(kind.rawValue.uppercased()). Controlla la nuova destinazione prima di approvare."
        } catch { status=error.localizedDescription }
    }


    func documentRow(_ entry: BatchDocument) -> some View {
        let job = (batch.approval ?? review.approval)?.jobs.first { $0.snapshotIdentity.id == entry.id }
        let destination = entry.destination ?? (review.matches(reviewContext, batch: batch) ? job?.destination : nil)
        let rowStatus = !batch.isApproved && destination != nil && entry.state == .pending ? "Pronto" : BatchWorkspaceSummary.status(entry.state)
        return VStack(alignment: .leading, spacing: 3) {
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 5) {
                    Text(entry.snapshot.originalURL.lastPathComponent).font(.callout)
                    Text("Origine: \(entry.snapshot.originalURL.path)\nDestinazione: \(destination?.path ?? "Da preparare")\n\(entry.snapshot.identity.byteCount) byte · SHA-256 \(entry.snapshot.identity.sha256)")
                    Text("Certificato: " + (batch.isApproved ? approvedHolder : selectedHolder))
                    if let job { Text("Certificato SHA-256: \(job.certificateSHA256)\nProvider: \(job.providerPath) · slot \(job.slot)\nJob: \(job.id) · snapshot: \(entry.id)") }
                    if entry.format.isASiC {
                        Text("Contenuti: " + entry.snapshot.containerPayloadNames.joined(separator: ", "))
                    }
                    Text(entry.state == .completed ? "Verifica crittografica completata prima della pubblicazione." : "Esito: " + entry.state.message)
                    if !entry.result.isEmpty { Text(entry.result) }
                    HStack {
                        if !batch.isFrozen {
                            Button("Rimuovi") {
                                let selected = documentSnapshot?.identity.id == entry.id
                                batch.remove(entry.id); placements[entry.id] = nil; readyPreviews.remove(entry.id)
                                if selected { showDocument(batch.documents.first?.id) }
                            }.disabled(interfaceLocked)
                        } else if batch.isApproved && !entry.state.isTerminal {
                            Button("Annulla documento") { batch.cancelDocument(entry.id); provider.pin = "" }
                                .disabled((batch.isRunning || interaction.isSubmittingPIN) && batch.nextDocument?.id == entry.id)
                        }
                    }
                }.font(.caption2).textSelection(.enabled).padding(.vertical, 5)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: BatchWorkspaceSummary.symbol(entry.state))
                        .foregroundStyle(entry.state == .completed ? Color.green : (entry.state == .failed || entry.state == .uncertain ? Color.orange : Color.secondary))
                        .accessibilityLabel(rowStatus)
                    Button(entry.snapshot.originalURL.lastPathComponent) { showDocument(entry.id) }
                        .buttonStyle(.plain).lineLimit(1).truncationMode(.middle)
                        .help(entry.snapshot.originalURL.lastPathComponent).disabled(batch.isRunning || interaction.isSubmittingPIN)
                    if !batch.isFrozen {
                        Menu(SignumFormat(rawValue: entry.format.rawValue)?.displayTitle ?? entry.format.shortTitle) {
                            Button("CAdES — Firma P7M") { setDocumentFormat(.cades,for:entry.id) }
                            Button("XAdES — Firma XML") { setDocumentFormat(.xades,for:entry.id) }
                                .disabled(!DocumentSigningConfiguration.canSelectXAdES(for:entry.snapshot))
                            Button("PAdES — Firma PDF") { setDocumentFormat(.pades,for:entry.id) }
                                .disabled(!DocumentSigningConfiguration.canSelectPAdES(for:entry.snapshot))
                        }.font(.caption.bold()).disabled(interfaceLocked || entry.format.isASiC)
                    } else { Text(SignumFormat(rawValue: entry.format.rawValue)?.displayTitle ?? entry.format.shortTitle).font(.caption.bold()) }
                    Spacer(minLength: 8)
                    Text(rowStatus).font(.caption).lineLimit(1)
                }.padding(.vertical, 3)
            }
            if !batch.isApproved {
                if let destination {
                    Text("Destinazione: " + BatchDisplay.destinationLabel(destination, among: review.approval?.jobs.map(\.destination) ?? []))
                        .font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(destination.path)
                } else if let policy=destinationPolicy {
                    Text("Nome previsto: " + policy.proposedURL(for:entry.snapshot,format:entry.format).lastPathComponent + " · collisioni controllate prima dell’approvazione")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            Divider()
        }.padding(.vertical, 2)
    }

    var sessionCompletionKey: String {
        [String(batch.isRunning), String(batch.isPreparing), String(batch.isContinuingAuthenticated),
         String(batch.needsOutcomeReview), String(interaction.isSubmittingPIN), String(interfaceLocked),
         String(authenticationSession != nil), batch.documents.map { $0.id.uuidString + $0.state.rawValue }.joined()].joined(separator: "|")
    }
    func releaseFinishedSession() {
        if results.releaseIfFinished(batch, interactionBusy: interaction.isSubmittingPIN || interaction.isRequestingApproval,
            hasAuthenticationContext: authenticationSession != nil, otherWork: busy) {
            review.cancel(); provider.pin = ""; approvedRoute = nil; approvedHolder = ""
            authenticationAttempted = false; authenticationStatus = ""
            placements = [:]; readyPreviews = []; workspace.select(nil); pdfPlacement = nil
            status = "Sessione conclusa. Gli esiti sono conservati; puoi firmare altri documenti o aprire Verifica."
        }
    }

    func resetSession() {
        guard !interfaceLocked else { return }
        authenticationSession?.requestStop(); authenticationSession = nil
        authenticationAttempted = false; authenticationStatus = ""
        batch.reset(); placements = [:]; readyPreviews = []; approvedRoute = nil
        showDocument(nil); provider.pin = ""; lastSignedFile = nil
        status = "Nuova sessione. Scegli i documenti da firmare."
    }



    func chooseDestination() {
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

    var tokenControls: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(devices.message).font(.callout)
            if (!devices.completenessIssues.isEmpty || status != devices.message) && !devices.isSearching {
                DisclosureGroup("Dettagli") {
                    if !status.isEmpty && status != devices.message {
                        Text(status).font(.caption).textSelection(.enabled)
                    }
                    ForEach(Array(devices.completenessIssues.enumerated()), id: \.offset) { _, issue in
                        Text(issue).font(.caption).textSelection(.enabled)
                    }
                }
            }
            Button("Configura dispositivo…") { showDeviceConfiguration = true }
                .disabled(interfaceLocked || batch.isFrozen || devices.isSearching)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    var selectedCertificateRoutes: [DeviceCertificateRoute] {
        guard let selected = devices.selectedRoute else { return [] }
        return devices.certificates.first(where: { $0.id == selected.certificateFingerprint })?.routes ?? []
    }









    func beginWork() -> SigningOperation {
        let id = UUID()
        let operation = SigningOperation(id: id) { phase in
            DispatchQueue.main.async { if self.work?.id == id { self.workPhase = phase } }
        }
        work = operation; workPhase = .preparing
        operation.transition(to: .preparing)
        return operation
    }

    func discover(manual: String? = nil) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let paths = manual.map { [$0.trimmingCharacters(in: .whitespacesAndNewlines)] } ?? []
        if let path = paths.first {
            guard MiddlewarePreferences.valid(path) else { status = "Scegli un percorso assoluto valido."; return }
            MiddlewarePreferences(defaults: preferences.defaults).remember(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        }
        guard let request = refresh.begin(selection: &devices, blocked: interfaceLocked || batch.isFrozen) else { return }
        provider.beginDiscovery()
        batch.invalidateReview()
        let configuredPaths = MiddlewarePreferences(defaults: preferences.defaults)
            .discoveryPaths(explicitPath: paths.first, authorizedPaths: authorizedManualPaths)
        authorizedManualPaths = configuredPaths
        let expectedPaths = Set(MiddlewareRegistry.known.flatMap(\.candidatePaths) + configuredPaths)
        // Public discovery owns cancellation separately from document/signing work.
        // It clears credentials/review, but does not lock sidebar or document input.
        let operation = SigningOperation()
        discoveryOperation = operation
        status = "Ricerca dei dispositivi in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let results = MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known,
                manualPaths: configuredPaths, isCancelled: { operation.isCancellationRequested })
            let prepared = DeviceDiscoveryResult(providers: operation.isCancellationRequested ? [] : results, expectedPaths:expectedPaths)
            DispatchQueue.main.async {
                guard self.devices.requestID == request else { return }
                self.discoveryOperation = nil
                if operation.isCancellationRequested {
                    self.refresh.cancel(); self.devices.cancelDiscovery(); self.provider.beginDiscovery()
                    self.status = "Ricerca annullata. Cerca nuovamente."; return
                }
                guard self.refresh.accept(prepared, request: request, selection: &self.devices) else { return }
                if let route=self.devices.selectedRoute { self.provider.select(route:route) }
                self.status = self.devices.message
            }
        }
    }

    func selectRoute(_ id: String) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        provider.beginDiscovery() // Clears certificate caches and PIN atomically.
        guard devices.select(routeID: id), let route = devices.selectedRoute else { return }
        provider.select(route: route)
        MiddlewarePreferences(defaults: preferences.defaults).prefer(route.providerPath)
        status = "Certificato selezionato: \(route.title). \(route.assessment.status.description)."
    }

    func chooseManualModule() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona il software del dispositivo"
        picker.canChooseFiles = true; picker.canChooseDirectories = false; picker.allowsMultipleSelection = false
        if picker.runModal() == .OK, let path = picker.url?.path { manualPath = path }
    }

    func removeManualModule(_ path: String) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        MiddlewarePreferences(defaults: preferences.defaults).remove(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        authorizedManualPaths.removeAll { $0 == path }
        if manualPath == path { manualPath = "" }
        devices.beginDiscovery(); provider.beginDiscovery(); batch.invalidateReview()
        status = "Configurazione manuale rimossa. Cerca nuovamente per scegliere un certificato."
    }

    func chooseFile() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona i documenti da firmare"
        picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if format == .pades { picker.allowedContentTypes = [.pdf] }
        else if format == .xades { picker.allowedContentTypes = [.xml] }
        if picker.runModal() == .OK { addDocuments(picker.urls) }
    }

    func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
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

    func addDocuments(_ urls: [URL]) {
        guard !interfaceLocked, !batch.isFrozen, let kind = SigningFormat(rawValue: format.rawValue) else { return }
        provider.pin = ""
        guard let acquisition = batch.enqueueDocuments(urls, format: kind) else { return }
        Task { @MainActor in
            await acquisition.value
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(batch.documents.count) documenti nella selezione. Controlla il riepilogo prima di firmare."
        }
    }

    func showDocument(_ id: UUID?) {
        if let old = documentSnapshot, batch.documents.contains(where: { $0.id == old.identity.id }) { placements[old.identity.id] = pdfPlacement }
        let entry = batch.documents.first(where: { $0.id == id })
        workspace.select(entry?.snapshot,format:entry?.format)
        inputFile = documentSnapshot?.originalURL
        pdfPlacement = id.flatMap { placements[$0] }
        previewSnapshotID = nil
    }

    func prepareBatch() {
        guard canApproveBatch, let plan = review.approval, let context = reviewContext,
              let route = devices.selectedRoute, let binding = context.providerContext,
              binding.valid, plan.jobs.allSatisfy({ $0.providerContext == binding }) else { return }
        provider.pin = ""
        let holder = selectedHolder, requestedAuthenticationMode = authenticationMode
        if let snapshot = documentSnapshot { placements[snapshot.identity.id] = pdfPlacement }
        do {
            let approved = try interaction.approveDisplayed(batch: batch, approval: plan,
                additionalConfirmation: additionalConfirmation, isCurrent: { reviewContext == context }, present: { approval in
                    let alert = NSAlert()
                    alert.messageText = "Conferma firma"
                    alert.informativeText = "Firmatario: \(holder)\nCertificato: \(route.title) · \(route.identity?.issuer ?? "Emittente non disponibile")\n\(approval.jobs.count) documenti. \(authenticationExplanation)"
                    let content = NSHostingView(rootView: BatchConsentView(approval: approval))
                    content.frame = NSRect(x: 0, y: 0, width: 560, height: 320)
                    alert.accessoryView = content
                    alert.addButton(withTitle: "Conferma e prosegui"); alert.addButton(withTitle: "Annulla")
                    return alert.runModal() == .alertFirstButtonReturn
                })
            if approved {
                approvedHolder = holder; approvedRoute = route
                approvedAuthenticationMode = requestedAuthenticationMode
                authenticationAttempted = false
                authenticationStatus = BatchAuthenticationPolicy.explanation(formats: plan.jobs.map(\.format), serial: route.token.serial, mode: requestedAuthenticationMode)
                status = "Documenti approvati. Inserisci il PIN per la firma corrente."
            } else { status = "Conferma annullata. Nessuna firma avviata." }
        } catch { status = error.localizedDescription }
    }

    func authorizeNextDocument() {
        guard canAuthorizeNext, let route = approvedRoute else { return }
        let holder = approvedHolder
        if !authenticationAttempted, let plan = batch.approval,
           BatchAuthenticationPolicy.canAttempt(jobs: plan.jobs, serial: route.token.serial, mode: approvedAuthenticationMode) {
            authenticationAttempted = true
            do {
                authenticationSession = try BatchCAdESSession(approval: plan, serial: route.token.serial,
                    moduleIdentity: route.moduleIdentity, automaticModule: route.origin == .known,
                    temporaryPIN: approvedAuthenticationMode == .temporaryPIN,
                    startingAt: batch.nextDocument?.id, remainingSnapshotIDs: Set(batch.documents.filter { !$0.state.isTerminal }.map(\.id)))
            } catch { provider.pin = ""; status = error.localizedDescription; return }
        }
        let session = authenticationSession
        workspace.showingPDFPreview = false
        interaction.submitPIN(&provider.pin, batch: batch, execute: { job, pin, operation in
            guard job.providerContext != nil else { throw SignumError.module("Contesto dispositivo approvato mancante.") }
            try route.requireCurrentModule()
            if let session { try session.signCAdES(job: job, pin: pin, operation: operation) }
            else if job.format == .cades { try job.signCAdES(using: IsolatedPKCS11Client(), pin: pin, operation: operation) }
            else if job.format.isAdvancedCAdES { try job.signAdvancedCAdES(using:IsolatedPKCS11Client(),pin:pin,operation:operation) }
            else if job.format == .xades || job.format.isASiC { try job.signXAdES(using:IsolatedPKCS11Client(),pin:pin,operation:operation) }
            else { try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: holder,
                field: nil, operation: operation, appearance: job.padesAppearance) }
        }, completion: { result in
            lastSignedFile = batch.documents.last(where: { $0.state == .completed })?.destination
            if let session {
                if session.canContinue {
                    authenticationStatus = approvedAuthenticationMode == .temporaryPIN
                        ? "PIN temporaneo attivo soltanto per questo batch approvato."
                        : "Sessione autenticata per questo batch. Nessun PIN riutilizzato."
                    Task { @MainActor in
                        await batch.continueAuthenticatedBatch(using: session)
                        lastSignedFile = batch.documents.last(where: { $0.state == .completed })?.destination
                        authenticationSession = nil
                        authenticationStatus = batch.authenticationNotice.isEmpty ? "Sessione autenticata conclusa." : batch.authenticationNotice
                        status = presentation.resultSummary
                    }
                } else {
                    let retirement = batch.retireAuthenticatedSession(using: session)
                    Task { @MainActor in
                        await retirement.value
                        authenticationSession = nil
                        authenticationStatus = batch.authenticationNotice.isEmpty
                            ? (batch.documents.contains(where: { $0.state == .failed || $0.state == .uncertain })
                                ? "Batch interrotto. Consulta i dettagli; nessun tentativo viene ripetuto."
                                : "Riuso non verificabile per questa chiave o sessione: PIN esplicito per le firme restanti.")
                            : batch.authenticationNotice
                        status = presentation.resultSummary
                    }
                }
            } else {
                switch result {
                case .success: status = batch.nextDocument == nil ? "Sessione conclusa. Consulta gli esiti." : "Consulta l'esito e inserisci il PIN per la firma successiva."
                case .failure(let error): status = error.localizedDescription
                }
            }
        })
    }

}
#endif
