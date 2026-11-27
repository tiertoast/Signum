#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration

enum SignumFormat: String, Hashable, CaseIterable {
    case cades, cadesDetached, cadesCoSign, cadesCounterSign, pades, xades, asics, asice
}

@MainActor struct SignumWindow: View {
    @ObservedObject var systemDocuments = SystemDocuments.shared
    @State var routingSystemDocuments = false
    @StateObject var verificationWorkspace: VerificationWorkspace
    let trustedLists: TrustedListsModel?
    let signingWorker: IsolatedPKCS11Client
    @StateObject var batch: BatchSigningCoordinator
    @StateObject var interaction = SigningInteraction()
    @StateObject var review = SigningReview()
    @StateObject var session: SigningWindowSession
    @StateObject var appearanceRenderer = PAdESRenderCoordinator()
    @StateObject var results: SigningSessionResults
    @Environment(\.colorScheme) var colorScheme
    @Environment(\.accessibilityReduceTransparency) var reduceTransparency
    @State var refresh = DeviceRefreshLifecycle()
    @State var discoveryOperation: SigningOperation?
    @AppStorage(SigningExperiencePreferences.Keys.batchAuthentication) var authenticationModeRaw = BatchAuthenticationMode.automatic.rawValue
    @AppStorage(SigningExperiencePreferences.Keys.includeSigningTime) var includeSigningTime = true
    /// Consent and PIN flow; see SigningAuthorization.
    @StateObject var authorization = SigningAuthorization()
    var approvedAuthenticationMode: BatchAuthenticationMode { authorization.approvedMode }
    var authenticationSession: BatchCAdESSession? { authorization.session }
    var authenticationStatus: String { authorization.notice }
    var approvedHolder: String {
        get { authorization.approvedHolder } nonmutating set { authorization.approvedHolder = newValue }
    }
    var approvedRoute: DeviceCertificateRoute? {
        get { authorization.approvedRoute } nonmutating set { authorization.approvedRoute = newValue }
    }
    @AppStorage(SigningExperiencePreferences.Keys.additionalConfirmation) var additionalConfirmation = false
    @FocusState var pinFocused: Bool
    @AppStorage(SigningExperiencePreferences.Keys.showExcluded) var showExcludedCertificates = false
    @AppStorage(SigningExperiencePreferences.Keys.alongsideOriginal) var saveAlongsideOriginal = true
    @State var customDirectory: URL?
    /// Every visible PAdES stamp of the session; see PDFStampBoard for the rules.
    @StateObject var stamps = PDFStampBoard()
    @State var provider: ProviderSelection
    @State var devices: DeviceSelection
    @State var discoveryStarted = false
    @State var showDeviceConfiguration = false
    @State var showDefaultApplications = false
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
    @State var format: SignumFormat = .cades
    @State var subsequentFormat: SignumFormat?
    @AppStorage("signum.format.applyToAll") var applyFormatToAll = true
    @State var showingDocumentDetails = false
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
    var sessionReady: ((SignumWindow) -> Void)?
    let discoveryLoader: @Sendable ([String], @Sendable () -> Bool) -> DeviceDiscoveryResult

    // Internal dependency injection for native layout tests; no production flag,
    // environment override or automatic loading of user-owned test modules.
    init(batch: BatchSigningCoordinator? = nil, initialDevices: DeviceSelection = .init(),
         initialProvider: ProviderSelection = .init(), selectedSnapshot: DocumentSnapshot? = nil,
         automaticallyDiscover: Bool = true, defaults: UserDefaults = .standard,
         workspace: SigningWorkspaceSelection? = nil, trustedLists: TrustedListsModel? = nil,
         initialSection: SignumSection = .sign,
         sessionResults: SigningSessionResults? = nil,
         initialSidebarVisibility: NavigationSplitViewVisibility = .all,
         session: SigningWindowSession? = nil, sessionReady: ((SignumWindow) -> Void)? = nil,
         discoveryLoader: (@Sendable ([String], @Sendable () -> Bool) -> DeviceDiscoveryResult)? = nil,
         appearanceRenderer: PAdESRenderCoordinator? = nil, worker: IsolatedPKCS11Client? = nil) {
        signingWorker = worker ?? IsolatedPKCS11Client()
        _appearanceRenderer = StateObject(wrappedValue: appearanceRenderer ?? PAdESRenderCoordinator())
        _session = StateObject(wrappedValue: session ?? SigningWindowSession())
        self.sessionReady = sessionReady
        self.discoveryLoader = discoveryLoader ?? { paths, cancelled in
            let expected = Set(MiddlewareRegistry.known.flatMap(\.candidatePaths) + paths)
            return DeviceDiscoveryResult(providers: MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known, manualPaths: paths, isCancelled: cancelled), expectedPaths: expected)
        }
        _sidebarVisibility = State(initialValue: initialSidebarVisibility)
        _results = StateObject(wrappedValue: sessionResults ?? SigningSessionResults())
        _navigation = State(initialValue: SignumNavigation(section: initialSection))
        _verificationWorkspace = StateObject(wrappedValue: VerificationWorkspace(catalog: trustedLists?.catalogProvider))
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

    var interfaceLocked: Bool { !session.isActive || busy || batch.isPreparing || batch.isRunning || batch.isContinuingAuthenticated || authorization.isContinuing || interaction.isRequestingApproval || interaction.isSubmittingPIN }
    var authenticationMode: BatchAuthenticationMode { BatchAuthenticationMode(rawValue: authenticationModeRaw) ?? .perSignature }
    var authenticationExplanation: String {
        BatchAuthenticationPolicy.explanation(formats: batch.documents.map(\.format),
            serial: devices.selectedRoute?.token.serial ?? "", mode: batch.isApproved ? approvedAuthenticationMode : authenticationMode)
    }
    var destinationPolicy: BatchOutputDestination? {
        SigningDestinationSelection(alongsideOriginal: saveAlongsideOriginal, customDirectory: customDirectory).policy
    }
    var reviewContext: SigningReviewContext? {
        guard session.isActive, !batch.isPreparing, !batch.isRunning, !batch.isContinuingAuthenticated, !batch.needsOutcomeReview, batch.nextDocument != nil, let destination = destinationPolicy,
              let path = provider.signingProvider, let slot = provider.selectedSlot,
              let id = provider.selectedCertificateID, let route = devices.selectedRoute,
              let certificate = provider.certificates.first(where: { $0.id == id }),
              let der = provider.certificateDERs[id], provider.certificateAssessments[id]?.permitsSigning == true,
              batch.documents.filter({ !$0.state.isTerminal }).allSatisfy({ ($0.format != .pades ||
                (stamps.confirmedAppearance($0.id)?.certificateSHA256 == route.certificateFingerprint && SignumPAdESHelper.available)) }) else { return nil }
        return .init(revision: batch.revision, provider: path, slot: slot, certificate: certificate,
                     der: der, destination: destination, routeID: route.id, discoveryID: devices.requestID, appearanceHashes: stamps.appearances.mapValues(\.approvalIdentity),
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
        SignumNativeWorkspace(sidebar: AnyView(
            List(selection: Binding(get: { operation }, set: { if !interfaceLocked && !batch.isFrozen { operation = $0 } })) {
                sidebarLabel(.sign).tag(SignumSection.sign)
                    .listRowSeparator(.visible, edges: .bottom)
                    .listRowSeparatorTint(Color(nsColor: .separatorColor).opacity(0.4))
                sidebarLabel(.verify).tag(SignumSection.verify)
                    .listRowSeparator(.visible, edges: .bottom)
                    .listRowSeparatorTint(Color(nsColor: .separatorColor).opacity(0.4))
                sidebarLabel(.devices).tag(SignumSection.devices)

            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Text("Digital signatures. Simply native.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .accessibilityIdentifier("signum.motto")
            }
            .scrollContentBackground(.hidden)
            .disabled(interfaceLocked || batch.isFrozen)
        ), detail: AnyView(
            VStack(spacing: 0) {
                switch operation ?? .sign {
                case .sign:
                    signingScreen
                case .verify:
                    UnifiedVerificationPane(catalog: trustedLists?.catalogProvider, workspace: verificationWorkspace)
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
        ), controls: .init(showAdd: (operation ?? .sign) == .sign, showBack: navigation.section == .settings,
                          locked: interfaceLocked || batch.isFrozen, searching: devices.isSearching,
                          initiallyCollapsed: sidebarVisibility == .detailOnly,
                          add: chooseFile, refresh: { discover() },
                          settings: { navigation.openSettings(blocked: interfaceLocked || batch.isFrozen) },
                          back: { navigation.back() }, close: { session.revoke() }, opened: activateSession))
        .ignoresSafeArea(.container, edges: .top)
        .onChange(of: batch.isFrozen) { frozen in if !frozen { scheduleSystemDocuments() } }
        .onChange(of: navigation.section) { section in
            if section != .verify { verificationWorkspace.cancel() }
        }
        .onReceive(systemDocuments.$revision) { _ in scheduleSystemDocuments() }
        .onChange(of: interfaceLocked) { locked in if !locked { scheduleSystemDocuments() } }
        .onReceive(NotificationCenter.default.publisher(for: .signumShowSettings)) { _ in
            navigation.openSettings(blocked: interfaceLocked || batch.isFrozen)
        }
        // Same rules as the toolbar button: signing screen only, never while locked or approved.
        .onReceive(NotificationCenter.default.publisher(for: .signumAddDocuments)) { _ in
            guard (operation ?? .sign) == .sign, !interfaceLocked, !batch.isFrozen else { return }
            chooseFile()
        }
        .task(id: sessionCompletionKey) { releaseFinishedSession() }
        .onAppear {
            activateSession()
            guard automaticallyDiscover, !discoveryStarted else { return }
            discoveryStarted = true
            discover()
        }
        .sheet(isPresented: $showDefaultApplications) { DefaultApplicationsSheet() }
        .sheet(isPresented: $showDeviceConfiguration) {
            DeviceConfigurationView(providers: devices.providers, savedPaths: manualPaths,
                routes: selectedCertificateRoutes, selectedRouteID: devices.selectedRouteID,
                manualPath: $manualPath, locked: interfaceLocked || batch.isFrozen || devices.isSearching,
                manualLocked: interfaceLocked || batch.isFrozen,
                browse: chooseManualModule,
                loadManual: { discover(manual: manualPath) }, remove: removeManualModule,
                selectRoute: selectRoute)
        }
        .task(id: batch.isFrozen ? nil : reviewContext) {
            guard session.isActive else { return }
            let activity = session.beginActivity(); defer { session.endActivity(activity) }
            let generation = session.generation
            let context = reviewContext, route = devices.selectedRoute, worker = signingWorker
            await review.prepare(context, batch: batch, appearances: stamps.appearances, validateCancellable: { control in try route?.requireCurrentCredential(client: worker, isCancelled: { control.isCancellationRequested }) })
            guard session.accepts(generation) else { return }
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
            if let entry = selectedDocument { updateSelectedFormat(entry.format) }
            else if documentSnapshot != nil { showDocument(batch.documents.first?.id) }
        }
        .onChange(of: stampSyncKey) { _ in syncStamps() }
        .onChange(of: stampEditingID) { id in stamps.setEditing(id, in: batch.documents) }
        .onChange(of: saveAlongsideOriginal) { _ in if !batch.isFrozen { provider.pin = "" } }
        .onDisappear { session.revoke() }
    }

    func activateSession() {
        guard !session.isTerminating else { return }
        if !session.isActive && !session.isDrained {
            session.reopen { activateSession() }; return
        }
        if !session.isActive {
            _ = results.releaseIfFinished(batch, interactionBusy: interaction.isSubmittingPIN || interaction.isRequestingApproval,
                hasAuthenticationContext: authenticationSession != nil, allowRevokedSelection: true)
        }
        appearanceRenderer.resume()
        guard session.activate(batch: batch, cleanup: revokeSessionState) else { return }
        if let sessionReady { var value = self; value.sessionReady = nil; sessionReady(value) }
    }
    private func revokeSessionState() {
        systemDocuments.discardPending()
        review.cancel(); verificationWorkspace.cancel(); appearanceRenderer.suspend()
        if !appearanceRenderer.isIdle {
            let activity = session.beginActivity()
            appearanceRenderer.whenIdle { session.endActivity(activity) }
        }
        work?.requestCancellation(preservingPrivateOutcome: true); work = nil
        discoveryOperation?.requestCancellation(); discoveryOperation = nil
        batch.revokeForWindowClosure(); refresh.cancel(); devices.cancelDiscovery(); provider.beginDiscovery()
        selectionRequestID = UUID(); workspace.select(nil); inputFile = nil
        stamps.reset(); previewSnapshotID = nil
        approvedRoute = nil; approvedHolder = ""; authorizedManualPaths = []; manualPath = ""
        busy = false; pinFocused = false
        showDeviceConfiguration = false; showDefaultApplications = false
        authorization.revoke(batch: batch, own: { session.own($0) })
    }
    func scheduleSystemDocuments() {
        guard session.isActive else { return }
        session.own(Task { await routeSystemDocuments() })
    }

    var devicesScreen: some View {
        DevicesExperiencePane(selection: devices, locked: interfaceLocked || batch.isFrozen,
            status: status, configure: { showDeviceConfiguration = true }, selectRoute: selectRoute)
    }

    func routeSystemDocuments() async {
        let generation = session.generation
        guard session.isActive, !routingSystemDocuments, !interfaceLocked, !batch.isFrozen else { return }
        routingSystemDocuments = true
        await Task.yield() // Coalesce URLs delivered by one Finder selection.
        defer { routingSystemDocuments = false }
        while session.accepts(generation), !Task.isCancelled, !interfaceLocked, !batch.isFrozen, let request = systemDocuments.next() {
            let scoped = request.urls.filter { $0.startAccessingSecurityScopedResource() }
            defer { scoped.forEach { $0.stopAccessingSecurityScopedResource() } }
            if request.action == .sign {
                operation = .sign
                addDocuments(request.urls) // Acquisition only: approval/PIN remain mandatory.
                while batch.isPreparing && session.accepts(generation) && !Task.isCancelled { try? await Task.sleep(nanoseconds: 10_000_000) }
            } else {
                operation = .verify
                var originals: [URL: URL] = [:]
                var files: [URL] = []
                for url in request.urls {
                    if url.pathExtension.lowercased() == "p7s" {
                        let chooser = NSOpenPanel()
                        chooser.title = "Seleziona l’originale per " + url.lastPathComponent
                        chooser.canChooseDirectories = false; chooser.allowsMultipleSelection = false
                        if chooser.runModal() == .OK, let original = chooser.url { originals[url] = original; files.append(url) }
                    } else { files.append(url) }
                }
                let extraScopes = originals.values.filter { $0.startAccessingSecurityScopedResource() }
                defer { extraScopes.forEach { $0.stopAccessingSecurityScopedResource() } }
                let detached = originals
                guard session.accepts(generation), !Task.isCancelled else { return }
                if !files.isEmpty {
                    await verificationWorkspace.verify(files, using: { file, control in
                        if let original = detached[file] {
                            return try SignumVerificationService.verifyDetached(signature: file, content: original, isCancelled: { control.isCancellationRequested })
                        }
                        return try SignumVerificationService.verify(file: file, isCancelled: { control.isCancellationRequested })
                    })
                }
            }
        }
    }

    func sidebarLabel(_ section: SignumSection) -> some View {
        Label {
            Text(section.title).font(.system(size: 14))
        } icon: {
            Image(systemName: section.symbol)
                .foregroundStyle(colorScheme == .dark ? SignumAppearance.burgundyForeground : SignumAppearance.burgundy)
        }
    }

    var incomingFormat: SignumFormat {
        SigningIncomingFormat.resolve(override: subsequentFormat, selected: selectedDocument?.format, fallback: format)
    }

    func displayedDestination(for entry: BatchDocument) -> (url: URL?, final: Bool) {
        let job = (batch.approval ?? review.approval)?.jobs.first { $0.snapshotIdentity.id == entry.id }
        if let url = entry.destination { return (url, true) }
        if review.matches(reviewContext, batch: batch), let url = job?.destination { return (url, true) }
        return (destinationPolicy?.proposedURL(for: entry.snapshot, format: entry.format), false)
    }

    var formatBinding: Binding<SignumFormat> {
        Binding(get: { selectedDocument.flatMap { SignumFormat(rawValue:$0.format.rawValue) } ?? format },
                set: { value in
                    guard let kind=SigningFormat(rawValue:value.rawValue) else { return }
                    if applyFormatToAll {
                        format=value; subsequentFormat=value
                        if selectedDocument != nil { setFormatForAllDocuments(kind) }
                    } else if let current=selectedDocument { setDocumentFormat(kind,for:current.id) }
                    else { format=value }
                })
    }
    func setDocumentFormat(_ kind:SigningFormat,for id:UUID) {
        guard !interfaceLocked, !batch.isFrozen,
              let entry=batch.documents.first(where:{$0.id == id}), entry.format != kind else { return }
        do {
            try batch.setFormat(kind,for:id)
            stamps.forget(id); provider.pin=""
            if documentSnapshot?.identity.id == id { updateSelectedFormat(kind) }
            status="Formato aggiornato a \(kind.rawValue.uppercased()). Controlla la nuova destinazione prima di approvare."
        } catch { status=error.localizedDescription }
    }


    /// Batch-wide choice: every compatible pending document gets the format;
    /// incompatible ones keep theirs and are counted in the status.
    func setFormatForAllDocuments(_ kind: SigningFormat) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let names = Dictionary(uniqueKeysWithValues: batch.documents.map { ($0.id, $0.snapshot.originalURL.lastPathComponent) })
        let result = batch.setFormatForAll(kind)
        for id in result.changed {
            stamps.forget(id)
            if documentSnapshot?.identity.id == id { updateSelectedFormat(kind) }
        }
        provider.pin = ""
        let title = SignumFormat(rawValue: kind.rawValue)?.displayTitle ?? kind.rawValue
        let kept = result.kept.compactMap { names[$0] }
        status = kept.isEmpty
            ? "Formato \(title) applicato a tutti i documenti."
            : "Formato \(title) applicato a \(result.changed.count) documenti. Mantengono il formato attuale perché non compatibili: \(kept.joined(separator: ", "))."
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
                            Button("Rimuovi") { removeSessionDocument(entry.id) }
                                .disabled(!canRemoveSessionDocuments || !batch.canRemove(entry.id))
                        } else if batch.isApproved && !entry.state.isTerminal {
                            Button("Annulla documento") { batch.cancelDocument(entry.id); provider.pin = "" }
                                .disabled((batch.isRunning || interaction.isSubmittingPIN) && batch.nextDocument?.id == entry.id)
                        }
                    }
                }.font(.caption2).textSelection(.enabled).padding(.vertical, 5)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: BatchWorkspaceSummary.symbol(entry.state))
                        .foregroundStyle(entry.state == .completed ? Color.green : entry.state == .uncertain ? Color.red : entry.state == .failed ? Color.orange : Color.secondary)
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
         String(batch.needsOutcomeReview), String(batch.isApproved), String(interaction.isSubmittingPIN), String(interfaceLocked),
         String(authenticationSession != nil), batch.documents.map { $0.id.uuidString + $0.state.rawValue }.joined()].joined(separator: "|")
    }
    func releaseFinishedSession() {
        guard session.isActive else { return }
        if results.releaseIfFinished(batch, interactionBusy: interaction.isSubmittingPIN || interaction.isRequestingApproval,
            hasAuthenticationContext: authenticationSession != nil, otherWork: busy) {
            review.cancel(); provider.pin = ""; authorization.clear()
            stamps.reset(); workspace.select(nil)
            status = "Sessione conclusa. Gli esiti sono conservati; puoi firmare altri documenti o aprire Verifica."
        }
    }

    func resetSession() {
        guard !interfaceLocked else { return }
        authorization.reset()
        batch.reset(); stamps.reset(); approvedRoute = nil
        showDocument(nil); provider.pin = ""; lastSignedFile = nil
        status = "Nuova sessione. Scegli i documenti da firmare."
    }



    func chooseDestination() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let generation = session.generation
        let picker = NSOpenPanel()
        picker.title = "Cartella comune delle copie firmate"
        picker.canChooseFiles = false; picker.canChooseDirectories = true
        picker.allowsMultipleSelection = false; picker.canCreateDirectories = false
        picker.directoryURL = customDirectory
        let response = picker.runModal()
        guard session.accepts(generation) else { return }
        if response == .OK, let directory = picker.url {
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
                .disabled(interfaceLocked || batch.isFrozen)
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
        let generation = session.generation
        let paths = manual.map { [$0.trimmingCharacters(in: .whitespacesAndNewlines)] } ?? []
        if let path = paths.first {
            guard MiddlewarePreferences.valid(path) else { status = "Scegli un percorso assoluto valido."; return }
            MiddlewarePreferences(defaults: preferences.defaults).remember(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        }
        guard let request = refresh.begin(selection: &devices, blocked: interfaceLocked || batch.isFrozen,
                                          replacingCurrent: !paths.isEmpty) else { return }
        if !paths.isEmpty { discoveryOperation?.requestCancellation() }
        provider.beginDiscovery()
        batch.invalidateReview()
        let configuredPaths = MiddlewarePreferences(defaults: preferences.defaults)
            .discoveryPaths(explicitPath: paths.first, authorizedPaths: authorizedManualPaths)
        authorizedManualPaths = configuredPaths
        let operation = SigningOperation()
        discoveryOperation = operation
        status = "Ricerca dei dispositivi in corso…"
        let loader = discoveryLoader
        session.own(Task { @MainActor in
            let worker = Task.detached(priority: .userInitiated) { loader(configuredPaths, { operation.isCancellationRequested }) }
            let prepared = await withTaskCancellationHandler(operation: { await worker.value }, onCancel: { operation.requestCancellation(); worker.cancel() })
            guard self.session.accepts(generation), self.devices.requestID == request else { return }
            self.discoveryOperation = nil
            if operation.isCancellationRequested {
                self.refresh.cancel(); self.devices.cancelDiscovery(); self.provider.beginDiscovery()
                self.status = "Ricerca annullata. Cerca nuovamente."; return
            }
            guard self.refresh.accept(prepared, request: request, selection: &self.devices) else { return }
            if let route = self.devices.selectedRoute { self.provider.select(route: route) }
            self.status = self.devices.message
        })
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
        let generation = session.generation
        let picker = NSOpenPanel()
        picker.title = "Seleziona il software del dispositivo"
        picker.canChooseFiles = true; picker.canChooseDirectories = false; picker.allowsMultipleSelection = false
        let response = picker.runModal()
        guard session.accepts(generation) else { return }
        if response == .OK, let path = picker.url?.path { manualPath = path }
    }

    func removeManualModule(_ path: String) {
        guard !interfaceLocked, !batch.isFrozen else { return }
        MiddlewarePreferences(defaults: preferences.defaults).remove(path); manualPaths = MiddlewarePreferences(defaults: preferences.defaults).paths
        authorizedManualPaths.removeAll { $0 == path }
        if manualPath == path { manualPath = "" }
        discoveryOperation?.requestCancellation(); discoveryOperation = nil
        refresh.cancel(); devices.cancelDiscovery(); provider.beginDiscovery()
        review.cancel(); batch.invalidateReview()
        authorization.withdrawApproval()
        status = "Configurazione manuale rimossa. Cerca nuovamente per scegliere un certificato."
    }

    func chooseFile() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let generation = session.generation
        let picker = NSOpenPanel()
        picker.title = "Seleziona i documenti da firmare"
        picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if incomingFormat == .pades { picker.allowedContentTypes = [.pdf] }
        else if incomingFormat == .xades { picker.allowedContentTypes = [.xml] }
        let response = picker.runModal()
        guard session.accepts(generation) else { return }
        if response == .OK { addDocuments(picker.urls) }
    }

    func receiveDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !interfaceLocked, !batch.isFrozen else { return false }
        let items = Array(providers.filter { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }.prefix(BatchSigningCoordinator.maximumDocuments))
        guard !items.isEmpty else { return false }
        busy = true
        let request = UUID(); selectionRequestID = request
        let generation = session.generation
        session.own(Task { @MainActor in
            let urls = await FileDropResolution.resolve(items)
            guard session.accepts(generation), selectionRequestID == request else { return }
            busy = false
            addDocuments(urls)
        })
        return true
    }

    func addDocuments(_ urls: [URL]) {
        guard !interfaceLocked, !batch.isFrozen, let kind = SigningFormat(rawValue: incomingFormat.rawValue) else { return }
        provider.pin = ""
        guard let acquisition = batch.enqueueDocuments(urls, format: kind) else { return }
        let generation = session.generation
        session.own(Task { @MainActor in
            await acquisition.value
            guard session.accepts(generation) else { return }
            // A batch-wide PDF/XML choice never forces an incompatible file:
            // e.g. a .docx dropped into a PAdES batch is signed as CAdES .p7m.
            for entry in batch.documents where !entry.state.isTerminal && [.pades, .xades].contains(entry.format)
                && !DocumentSigningConfiguration.canApply(entry.format, to: entry.snapshot) {
                try? batch.setFormat(.cades, for: entry.id)
            }
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(batch.documents.count) documenti nella selezione. Controlla il riepilogo prima di firmare."
        })
    }

    var canRetryCancelled: Bool {
        session.isActive && !interfaceLocked && !busy && !batch.isFrozen && !batch.isPreparing && !batch.isRunning
    }
    /// "Riprova": read cancelled documents again from disk, as if chosen anew.
    /// A fresh snapshot, review, PIN and (for PDFs) stamp confirmation follow;
    /// nothing is signed or retried automatically.
    func retryCancelled(_ ids: Set<UUID>) {
        guard canRetryCancelled else { return }
        let receipts = results.takeRetryable(ids)
        guard !receipts.isEmpty else { return }
        provider.pin = ""
        let generation = session.generation
        let groups = Dictionary(grouping: receipts) { $0.signingFormat! }
        session.own(Task { @MainActor in
            for format in groups.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
                guard session.accepts(generation), let acquisition = batch.enqueueDocuments(groups[format]!.compactMap(\.source), format: format) else { break }
                await acquisition.value
            }
            guard session.accepts(generation) else { return }
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(receipts.count == 1 ? "Documento riaggiunto" : "\(receipts.count) documenti riaggiunti"). Controlla il riepilogo prima di firmare."
        })
    }

    var canRemoveSessionDocuments: Bool {
        session.isActive && !busy && !batch.isPreparing && !interaction.isRequestingApproval
    }
    func removeSessionDocument(_ id: UUID) {
        guard canRemoveSessionDocuments, batch.canRemove(id), let index = batch.documents.firstIndex(where: { $0.id == id }) else { return }
        let selected = documentSnapshot?.identity.id == id
        review.cancel()
        batch.remove(id)
        provider.pin = ""
        if !batch.isApproved {
            approvedRoute = nil; authorization.attempted = false
            status = "Rimozione richiesta. L’eventuale firma corrente conserva il proprio esito; i documenti rimasti richiedono una nuova approvazione."
        }
        guard !batch.documents.contains(where: { $0.id == id }) else { return }
        stamps.forget(id); provider.pin = ""
        showingDocumentDetails = false
        if selected {
            showDocument(batch.documents.isEmpty ? nil : batch.documents[min(index, batch.documents.count - 1)].id)
        }
    }

    /// Everything the stamp board depends on; any change triggers a sync.
    var stampSyncKey: String {
        batch.documents.map { "\($0.id)\($0.format.rawValue)\($0.state.rawValue)" }.joined() +
            "|\(batch.isFrozen)|" + (devices.selectedRoute?.certificateFingerprint ?? "")
    }
    var stampEditingID: UUID? { workspace.showingPDFPreview ? documentSnapshot?.identity.id : nil }
    func syncStamps() {
        stamps.sync(documents: batch.documents, frozen: batch.isFrozen, certificateDER: devices.selectedRoute?.der)
    }
    /// A PDF that already has a stamp, or will receive the template's copy,
    /// opens in the read-only preview; the editor stays one click away.
    func wantsStampEditor(_ id: UUID) -> Bool { !stamps.isConfirmed(id) && !stamps.followsTemplate }
    func updateSelectedFormat(_ kind: SigningFormat) {
        workspace.updateFormat(kind)
        if kind == .pades, let id = documentSnapshot?.identity.id, !wantsStampEditor(id) { workspace.showingPDFPreview = false }
    }

    func showDocument(_ id: UUID?) {
        guard session.isActive else { return }
        let entry = batch.documents.first(where: { $0.id == id })
        // The stamp editor opens by itself only on a PDF without a confirmed stamp.
        workspace.select(entry?.snapshot, format: entry?.format, openEditor: entry.map { wantsStampEditor($0.id) } ?? true)
        inputFile = documentSnapshot?.originalURL
        previewSnapshotID = nil
    }

    func prepareBatch() {
        guard canApproveBatch, let plan = review.approval, let context = reviewContext,
              let route = devices.selectedRoute, let binding = context.providerContext,
              binding.valid, plan.jobs.allSatisfy({ $0.providerContext == binding }) else { return }
        provider.pin = ""
        let generation = session.generation
        let holder = selectedHolder, requestedAuthenticationMode = authenticationMode
        do {
            let approved = try interaction.approveDisplayed(batch: batch, approval: plan,
                additionalConfirmation: additionalConfirmation, isCurrent: { session.accepts(generation) && reviewContext == context }, present: { approval in
                    let alert = NSAlert()
                    alert.messageText = "Conferma firma"
                    alert.informativeText = "Firmatario: \(holder)\nCertificato: \(route.title) · \(route.identity?.issuer ?? "Emittente non disponibile")\n\(approval.jobs.count) documenti. \(authenticationExplanation)"
                    let content = NSHostingView(rootView: BatchConsentView(approval: approval))
                    content.frame = NSRect(x: 0, y: 0, width: 560, height: 320)
                    alert.accessoryView = content
                    alert.addButton(withTitle: "Conferma e prosegui"); alert.addButton(withTitle: "Annulla")
                    return alert.runModal() == .alertFirstButtonReturn && session.accepts(generation)
                })
            guard session.accepts(generation) else { return }
            if approved {
                authorization.approved(holder: holder, route: route, mode: requestedAuthenticationMode, formats: plan.jobs.map(\.format))
                status = "Documenti approvati. Inserisci il PIN per la firma corrente."
            } else { status = "Conferma annullata. Nessuna firma avviata." }
        } catch { if session.accepts(generation) { status = error.localizedDescription } }
    }

    func authorizeNextDocument() {
        guard canAuthorizeNext, approvedRoute != nil else { return }
        let generation = session.generation
        workspace.showingPDFPreview = false
        authorization.authorizeNext(pin: &provider.pin, batch: batch, interaction: interaction, worker: signingWorker, hooks: .init(
            accepts: { session.accepts(generation) },
            own: { session.own($0) },
            status: { status = $0 },
            signed: { lastSignedFile = batch.documents.last(where: { $0.state == .completed })?.destination }))
    }


}
#endif
