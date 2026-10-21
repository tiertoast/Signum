#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SignumCore
import SignumTrustIntegration

private extension Result {
    var isSuccess: Bool { if case .success = self { return true }; return false }
}

func signingApprovalMessage(holder: String, job: SigningJob) -> String {
    "Firmatario: \(holder)\n" + job.approvalDescription
}


@MainActor final class SignumLifecycle: NSObject, NSApplicationDelegate {
    let trustedLists = try? TrustedListsModel.developmentPreview()
    func applicationDidFinishLaunching(_ notification: Notification) { trustedLists?.start() }
    func applicationWillTerminate(_ notification: Notification) { trustedLists?.stop() }
}

@main
struct SignumApp: App {
    @NSApplicationDelegateAdaptor(SignumLifecycle.self) private var lifecycle
    var body: some Scene {
        WindowGroup("Signum") {
            SignumWindow(trustedLists: lifecycle.trustedLists)
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
    private let trustedLists: TrustedListsModel?
    @StateObject private var batch: BatchSigningCoordinator
    @StateObject private var interaction = SigningInteraction()
    @StateObject private var review = SigningReview()
    @AppStorage(SigningExperiencePreferences.Keys.batchAuthentication) private var authenticationModeRaw = BatchAuthenticationMode.automatic.rawValue
    @AppStorage(SigningExperiencePreferences.Keys.includeSigningTime) private var includeSigningTime = true
    @State private var approvedAuthenticationMode: BatchAuthenticationMode = .perSignature
    @State private var authenticationSession: BatchCAdESSession?
    @State private var authenticationAttempted = false
    @State private var authenticationStatus = ""
    @AppStorage(SigningExperiencePreferences.Keys.additionalConfirmation) private var additionalConfirmation = false
    @FocusState private var pinFocused: Bool
    @AppStorage(SigningExperiencePreferences.Keys.showExcluded) private var showExcludedCertificates = false
    @AppStorage(SigningExperiencePreferences.Keys.alongsideOriginal) private var saveAlongsideOriginal = true
    @State private var customDirectory: URL?
    @State private var placements: [UUID: PAdESPlacement] = [:]
    @State private var readyPreviews = Set<UUID>()
    @State private var approvedHolder = ""
    @State private var approvedRoute: DeviceCertificateRoute?
    @State private var provider: ProviderSelection
    @State private var devices: DeviceSelection
    @State private var discoveryStarted = false
    @State private var showDeviceConfiguration = false
    @State private var manualPath = ""
    @State private var manualPaths: [String]
    @State private var authorizedManualPaths: [String] = []
    @State private var work: SigningOperation?
    @State private var workPhase: SigningOperationPhase = .idle
    @State private var operation: SignumOperation = .sign
    @State private var format: SignumFormat = .cades
    @State private var pdfPlacement: PAdESPlacement?
    @StateObject private var workspace: SigningWorkspaceSelection
    private var documentSnapshot: DocumentSnapshot? { workspace.snapshot }
    private var selectedDocument: BatchDocument? { batch.documents.first { $0.id == documentSnapshot?.identity.id } }
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
         automaticallyDiscover: Bool = true, defaults: UserDefaults = .standard,
         workspace: SigningWorkspaceSelection? = nil, trustedLists: TrustedListsModel? = nil) {
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

    private var interfaceLocked: Bool { busy || batch.isPreparing || batch.isRunning || batch.isContinuingAuthenticated || (authenticationSession?.canContinue ?? false) || interaction.isRequestingApproval || interaction.isSubmittingPIN }
    private var authenticationMode: BatchAuthenticationMode { BatchAuthenticationMode(rawValue: authenticationModeRaw) ?? .perSignature }
    private var authenticationExplanation: String {
        BatchAuthenticationPolicy.explanation(formats: batch.documents.map(\.format),
            serial: devices.selectedRoute?.token.serial ?? "", mode: batch.isApproved ? approvedAuthenticationMode : authenticationMode)
    }
    private var destinationPolicy: BatchOutputDestination? {
        SigningDestinationSelection(alongsideOriginal: saveAlongsideOriginal, customDirectory: customDirectory).policy
    }
    private var reviewContext: SigningReviewContext? {
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
    private var canApproveBatch: Bool {
        !interfaceLocked && !batch.isFrozen && !workspace.showingPDFPreview && review.matches(reviewContext, batch: batch)
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
                Text("Firma").tag(SignumOperation.sign)
                Text("Verifica").tag(SignumOperation.verify)
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
                            UnifiedVerificationPane(catalog: trustedLists?.catalogProvider)
                        } else {
                            Button("Configura dispositivo…") { showDeviceConfiguration = true }
                            Picker("Autenticazione nella firma multipla", selection: $authenticationModeRaw) {
                                ForEach(BatchAuthenticationMode.allCases, id: \.rawValue) { mode in Text(mode.title).tag(mode.rawValue) }
                            }
                            Text(authenticationMode.explanation).font(.caption).foregroundStyle(.secondary)
                            GroupBox("Firma digitale") {
                                VStack(alignment: .leading, spacing: 6) {
                                    Toggle("Includi data e ora della firma", isOn: $includeSigningTime).disabled(batch.isFrozen || interfaceLocked)
                                    Text("La data e ora dichiarate della firma non costituiscono una marca temporale certificata.").font(.caption).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                            Toggle("Richiedi conferma aggiuntiva prima della firma", isOn: $additionalConfirmation)
                            Text("Il pulsante Firma approva il riepilogo visibile. Questa opzione aggiunge una finestra di conferma.").font(.caption).foregroundStyle(.secondary)
                            SignumGraphicSettingsPane()
                            if let trustedLists { TrustedListsPane(model: trustedLists) }
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
            batch.cancelAll()
            selectionRequestID = UUID()
            devices.beginDiscovery(); provider.beginDiscovery()
            workspace.select(nil)
        }
    }

    private var formatBinding: Binding<SignumFormat> {
        Binding(get: { selectedDocument.flatMap { SignumFormat(rawValue:$0.format.rawValue) } ?? format },
                set: { value in
                    guard let kind=SigningFormat(rawValue:value.rawValue) else { return }
                    if let current=selectedDocument { setDocumentFormat(kind,for:current.id) }
                    else { format=value }
                })
    }
    private func setDocumentFormat(_ kind:SigningFormat,for id:UUID) {
        guard !interfaceLocked, !batch.isFrozen,
              let entry=batch.documents.first(where:{$0.id == id}), entry.format != kind else { return }
        do {
            try batch.setFormat(kind,for:id)
            placements[id]=nil; readyPreviews.remove(id); provider.pin=""
            if documentSnapshot?.identity.id == id { pdfPlacement=nil; workspace.updateFormat(kind) }
            status="Formato aggiornato a \(kind.rawValue.uppercased()). Controlla la nuova destinazione prima di approvare."
        } catch { status=error.localizedDescription }
    }
    private var formatPicker: some View {
        GroupBox(selectedDocument == nil ? "Formato nuovi documenti" : "Formato firma") {
            VStack(alignment:.leading,spacing:6) {
                Picker("Formato firma",selection:formatBinding) {
                    Text("CAdES — documento .p7m").tag(SignumFormat.cades)
                    Text("XAdES — XML firmato").tag(SignumFormat.xades)
                        .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectXAdES(for:$0.snapshot) } ?? false)
                    Text("PAdES — PDF firmato").tag(SignumFormat.pades)
                        .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectPAdES(for:$0.snapshot) } ?? false)
                }.pickerStyle(.menu).labelsHidden().accessibilityIdentifier("signum.current-format")
                    .disabled(interfaceLocked || batch.isFrozen)
                if selectedDocument?.format == .xades || (selectedDocument == nil && format == .xades) {
                    Text("XML UTF-8 · una firma · massimo 8 MiB. XAdES include sempre una data dichiarata, non una marca temporale.").font(.caption).foregroundStyle(.secondary)
                }
                if let entry=selectedDocument {
                    Text("Documento corrente: " + entry.snapshot.originalURL.lastPathComponent).font(.caption).lineLimit(2)
                    Text(entry.format.title).font(.callout.bold())
                    if !batch.isFrozen {
                        Text("Puoi cambiare formato fino all’approvazione. Gli altri documenti mantengono la propria scelta.")
                            .font(.caption).foregroundStyle(.secondary)
                        Picker("Per i prossimi documenti",selection:$format) {
                            Text("CAdES").tag(SignumFormat.cades)
                            Text("XAdES").tag(SignumFormat.xades)
                            Text("PAdES").tag(SignumFormat.pades)
                        }.pickerStyle(.menu).font(.caption).disabled(interfaceLocked)
                    }
                }
            }.padding(5)
        }
    }

    @ViewBuilder private var sessionWorkspace: some View {
        if selectedDocument?.format == .pades {
            VStack(spacing: 0) {
                Text("PAdES · " + (documentSnapshot?.originalURL.lastPathComponent ?? ""))
                    .font(.callout.bold()).lineLimit(1).padding(.top, 8)
                Picker("Visualizzazione", selection: $workspace.showingPDFPreview) {
                    Text("Documenti ed esiti").tag(false)
                    Text("Anteprima PDF").tag(true)
                }.pickerStyle(.segmented).labelsHidden().padding(12)
                if workspace.showingPDFPreview {
                    ScrollView { pdfWorkspace.frame(minHeight: 560) }
                } else { documentSession }
            }
        } else { documentSession }
    }

    private var documentSession: some View {
        GroupBox("Documenti") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(batch.documents.count == 1 ? "1 documento" : "\(batch.documents.count) documenti").font(.callout)
                    Spacer()
                    if batch.documents.contains(where: { $0.state == .completed }) {
                        Button("Apri cartella") { NSWorkspace.shared.activateFileViewerSelecting(batch.documents.filter { $0.state == .completed }.compactMap(\.destination)) }
                    }
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
                if !batch.isApproved, let route = devices.selectedRoute {
                    Text("Firmatario: \(selectedHolder) · Certificato: \(route.title)").font(.caption).textSelection(.enabled)
                }
                if let plan = review.approval, review.matches(reviewContext, batch: batch), !batch.isApproved {
                    DisclosureGroup("Dettagli tecnici del riepilogo") {
                        ScrollView { Text(plan.technicalDetails).font(.caption2).textSelection(.enabled) }.frame(maxHeight: 110)
                    }
                }
                if !batch.documents.isEmpty {
                    ProgressView(value: Double(batch.finishedCount), total: Double(max(1, batch.documents.count)))
                    if batch.isApproved { Text((batch.needsOutcomeReview ? "Verifica richiesta · " : "") + presentation.resultSummary).font(.caption) }
                    if batch.isRunning, let current = batch.nextDocument { Text("In corso: " + current.snapshot.originalURL.lastPathComponent).font(.caption).lineLimit(1).help(current.snapshot.originalURL.lastPathComponent) }
                }
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if batch.documents.isEmpty { Text("Aggiungi uno o più documenti per preparare la firma.").foregroundStyle(.secondary).padding() }
                        ForEach(batch.documents) { entry in documentRow(entry) }
                        ForEach(Array(batch.selectionIssues.enumerated()), id: \.offset) { _, message in Text(message).font(.caption) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                if !batch.isApproved { Text("Massimo 100 MiB per documento · 32 documenti e 128 MiB per sessione.").font(.caption2).foregroundStyle(.secondary) }
                if !batch.selectionTechnicalDetails.isEmpty {
                    DisclosureGroup("Dettagli tecnici acquisizione") {
                        Text(batch.selectionTechnicalDetails.joined(separator: "\n")).font(.caption2).textSelection(.enabled)
                    }
                }

            }.padding(7)
        }.padding(12)
    }

    private func documentRow(_ entry: BatchDocument) -> some View {
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
                        Menu(entry.format.shortTitle) {
                            Button("CAdES — documento .p7m") { setDocumentFormat(.cades,for:entry.id) }
                            Button("XAdES — XML firmato") { setDocumentFormat(.xades,for:entry.id) }
                                .disabled(!DocumentSigningConfiguration.canSelectXAdES(for:entry.snapshot))
                            Button("PAdES — PDF firmato") { setDocumentFormat(.pades,for:entry.id) }
                                .disabled(!DocumentSigningConfiguration.canSelectPAdES(for:entry.snapshot))
                        }.font(.caption.bold()).disabled(interfaceLocked)
                    } else { Text(entry.format.shortTitle).font(.caption.bold()) }
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

    private func resetSession() {
        guard !interfaceLocked else { return }
        authenticationSession?.requestStop(); authenticationSession = nil
        authenticationAttempted = false; authenticationStatus = ""
        batch.reset(); placements = [:]; readyPreviews = []; approvedRoute = nil
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
                if devices.selectionOrigin == .automatic, let route=devices.selectedRoute {
                    Text("Selezionato automaticamente: \(route.title)").font(.caption)
                }
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
                    Text(authenticationExplanation).font(.caption).foregroundStyle(.secondary)
                    Button(presentation.signButtonTitle) { prepareBatch() }.disabled(!canApproveBatch)
                    if review.isPreparing { ProgressView("Preparazione del riepilogo…").controlSize(.small) }
                    if !review.issue.isEmpty { Text(review.issue).font(.caption) }
                    Text("Il clic approva i documenti e le destinazioni mostrati. Per ogni PDF apri prima l'anteprima, poi torna a Documenti ed esiti.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    if !authenticationStatus.isEmpty { Text(authenticationStatus).font(.caption) }
                    if !batch.authenticationNotice.isEmpty { Text(batch.authenticationNotice).font(.caption) }
                    if batch.isContinuingAuthenticated || (authenticationSession?.canContinue ?? false) {
                        ProgressView("Firma dei documenti approvati…").controlSize(.small)
                    } else if let prompt = presentation.pinPrompt, let next = batch.nextDocument {
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
                        Button("Interrompi firma corrente") { batch.activeOperation?.requestCancellation(); authenticationSession?.requestStop() }
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
                Text("Il clic su Firma approva questi documenti. " + authenticationExplanation + " Nessun tentativo automatico aggiuntivo.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(5)
        }
    }

    private var statusFooter: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text(status).font(.caption).textSelection(.enabled)
            Spacer(minLength: 0)

        }
    }

    @ViewBuilder
    private var pdfWorkspace: some View {
        let generation = workspace.generation
        if let snapshot = documentSnapshot, selectedDocument?.format == .pades {
            PAdESPlacementPane(
                snapshot: snapshot,
                previewReady: { id, ready in
                    guard workspace.accepts(id, generation: generation) else { return }
                    if ready { previewSnapshotID = id; readyPreviews.insert(id) }
                    if !ready {
                        readyPreviews.remove(id); provider.pin = ""
                        status = "Anteprima in preparazione o appearance da correggere."
                    }
                },
                holder: selectedHolder, certificateDER: devices.selectedRoute?.der,
                placement: Binding(get: { pdfPlacement }, set: { value in
                    guard !interfaceLocked, !batch.isFrozen, workspace.accepts(snapshot.identity.id, generation: generation) else { return }
                    pdfPlacement = value; placements[snapshot.identity.id] = value
                })
            )
            .id(generation)
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
                     : format == .xades ? "XAdES firma un XML UTF-8. Include una data dichiarata, non una marca temporale." : "Con CAdES il documento viene incorporato in una busta .p7m.")
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
        batch.invalidateReview()
        let configuredPaths = MiddlewarePreferences(defaults: preferences.defaults)
            .discoveryPaths(explicitPath: paths.first, authorizedPaths: authorizedManualPaths)
        authorizedManualPaths = configuredPaths
        let expectedPaths = Set(MiddlewareRegistry.known.flatMap(\.candidatePaths) + configuredPaths)
        let request = devices.beginDiscovery(), operation = beginWork()
        busy = true; status = "Ricerca dei dispositivi in corso…"
        DispatchQueue.global(qos: .userInitiated).async {
            let results = MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known,
                manualPaths: configuredPaths, isCancelled: { operation.isCancellationRequested })
            let prepared = DeviceDiscoveryResult(providers: operation.isCancellationRequested ? [] : results, expectedPaths:expectedPaths)
            DispatchQueue.main.async {
                guard self.devices.requestID == request else { return }
                self.busy = false; self.work = nil
                if operation.isCancellationRequested {
                    self.devices.cancelDiscovery(); self.provider.beginDiscovery()
                    self.status = "Ricerca annullata. Cerca nuovamente."; return
                }
                guard self.devices.accept(prepared, request: request) else { return }
                if let route=self.devices.selectedRoute { self.provider.select(route:route) }
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
        authorizedManualPaths.removeAll { $0 == path }
        if manualPath == path { manualPath = "" }
        devices.beginDiscovery(); provider.beginDiscovery(); batch.invalidateReview()
        status = "Configurazione manuale rimossa. Cerca nuovamente per scegliere un certificato."
    }

    private func chooseFile() {
        guard !interfaceLocked, !batch.isFrozen else { return }
        let picker = NSOpenPanel()
        picker.title = "Seleziona i documenti da firmare"
        picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if format == .pades { picker.allowedContentTypes = [.pdf] }
        else if format == .xades { picker.allowedContentTypes = [.xml] }
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
        guard let acquisition = batch.enqueueDocuments(urls, format: kind) else { return }
        Task { @MainActor in
            await acquisition.value
            if documentSnapshot == nil { showDocument(batch.documents.first?.id) }
            status = "\(batch.documents.count) documenti nella selezione. Controlla il riepilogo prima di firmare."
        }
    }

    private func showDocument(_ id: UUID?) {
        if let old = documentSnapshot, batch.documents.contains(where: { $0.id == old.identity.id }) { placements[old.identity.id] = pdfPlacement }
        let entry = batch.documents.first(where: { $0.id == id })
        workspace.select(entry?.snapshot,format:entry?.format)
        inputFile = documentSnapshot?.originalURL
        pdfPlacement = id.flatMap { placements[$0] }
        previewSnapshotID = nil
    }

    private func prepareBatch() {
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

    private func authorizeNextDocument() {
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
            else if job.format == .xades { try job.signXAdES(using:IsolatedPKCS11Client(),pin:pin,operation:operation) }
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
#else
import Foundation
@main
struct SignumApp {
    static func main() { print("SignumApp richiede macOS 13 o successivo.") }
}
#endif
