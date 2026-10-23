#if os(macOS)
import SwiftUI
import SignumCore

extension SignumWindow {
    var signingScreen: some View {
        HSplitView {
            documentWorkspace.frame(minWidth: 410, maxWidth: .infinity, maxHeight: .infinity)
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Firmatario").font(.headline)
                            Picker("Firmatario", selection: Binding(get: { devices.selectedRouteID ?? "" }, set: { selectRoute($0) })) {
                                Text("Seleziona certificato…").tag("")
                                ForEach(CertificateVisibility(devices.certificates).eligible) { group in
                                    ForEach(group.routes) { route in
                                        Text(SigningRouteLabel.title(route)).lineLimit(1).truncationMode(.tail)
                                            .help(SigningRouteLabel.tooltip(route)).tag(route.id)
                                    }
                                }
                            }.pickerStyle(.menu).labelsHidden().frame(maxWidth: .infinity)
                                .modifier(SignumFlexibleControl())
                                .help(devices.selectedRoute.map(SigningRouteLabel.tooltip) ?? "Scegli un certificato e il relativo dispositivo")
                                .disabled(interfaceLocked || batch.isFrozen || devices.isSearching)
                            certificateSelectionFeedback
                        }
                        Divider()
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Formato").font(.headline)
                            Picker("Formato", selection: formatBinding) {
                                Text(SignumFormat.cades.displayTitle).tag(SignumFormat.cades)
                                Text(SignumFormat.pades.displayTitle).tag(SignumFormat.pades)
                                    .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectPAdES(for: $0.snapshot) } ?? false)
                                Section("Altri formati") {
                                    Text(SignumFormat.cadesDetached.displayTitle).tag(SignumFormat.cadesDetached)
                                    Text(SignumFormat.cadesCoSign.displayTitle).tag(SignumFormat.cadesCoSign)
                                    Text(SignumFormat.cadesCounterSign.displayTitle).tag(SignumFormat.cadesCounterSign)
                                    Text(SignumFormat.xades.displayTitle).tag(SignumFormat.xades)
                                        .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectXAdES(for: $0.snapshot) } ?? false)
                                    Text(SignumFormat.asics.displayTitle).tag(SignumFormat.asics).disabled(selectedDocument != nil)
                                    Text(SignumFormat.asice.displayTitle).tag(SignumFormat.asice).disabled(selectedDocument != nil)
                                }
                            }.pickerStyle(.menu).labelsHidden().frame(maxWidth: .infinity)
                                .modifier(SignumFlexibleControl())
                                .disabled(interfaceLocked || batch.isFrozen || selectedDocument?.format.isASiC == true)
                            Text(formatDetails + "\n" + authenticationExplanation).font(.caption).foregroundStyle(.secondary)
                            Text("Documenti successivi").font(.caption).foregroundStyle(.secondary)
                            Picker("Documenti successivi", selection: $subsequentFormat) {
                                Text("Automatico — usa il formato selezionato sopra").tag(Optional<SignumFormat>.none)
                                ForEach(SignumFormat.allCases, id: \.self) { value in
                                    Text(value.displayTitle).tag(Optional(value))
                                }
                            }.pickerStyle(.menu).labelsHidden().frame(maxWidth: .infinity)
                                .modifier(SignumFlexibleControl())
                                .disabled(interfaceLocked || batch.isFrozen)
                            counterSignatureSelection
                        }
                        Divider()
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Destinazione").font(.headline)
                            Picker("Destinazione", selection: $saveAlongsideOriginal) {
                                Text("Accanto agli originali").tag(true)
                                Text("Cartella comune").tag(false)
                            }.pickerStyle(.menu).labelsHidden().frame(maxWidth: .infinity)
                                .modifier(SignumFlexibleControl())
                                .disabled(interfaceLocked || batch.isFrozen)
                            if !saveAlongsideOriginal {
                                Button(customDirectory?.lastPathComponent ?? "Scegli cartella…") { chooseDestination() }
                                    .disabled(interfaceLocked || batch.isFrozen)
                            }
                        }
                    }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                signingControls.padding(16)
            }
            .frame(minWidth: 300, idealWidth: 320, maxWidth: 440)
            .background(Color(nsColor: .controlBackgroundColor))
        }
    }
    var signingAvailability: String {
        if busy || batch.isPreparing { return work == nil ? "Preparazione documenti…" : workPhase.message }
        if batch.documents.isEmpty { return "Aggiungi un documento per iniziare" }
        if devices.isSearching { return "Ricerca dei certificati…" }
        guard devices.selectedRoute != nil else { return "Seleziona un certificato per firmare" }
        if !review.issue.isEmpty { return review.issue }
        if !saveAlongsideOriginal && customDirectory == nil { return "Scegli la cartella di destinazione" }
        if workspace.showingPDFPreview || batch.documents.contains(where: { $0.format == .pades && !readyPreviews.contains($0.id) }) {
            return "Controlla e conferma l’anteprima di ogni PDF"
        }
        if review.isPreparing { return "Verifica dei documenti e del certificato…" }
        return canApproveBatch ? "Pronto per la firma" : status
    }

    @ViewBuilder var certificateSelectionFeedback: some View {
        if !devices.isSearching && devices.selectedRoute == nil {
            VStack(alignment: .leading, spacing: 6) {
                Text(review.credentialUnavailable ? "Certificato non più disponibile." :
                    (devices.certificates.isEmpty ? "Nessun certificato disponibile." :
                     (devices.discoveryComplete ? "Scegli un certificato." : "Ricerca incompleta. Seleziona un certificato o consulta Dispositivi.")))
                    .font(.caption)
                Button("Dispositivi…") { operation = .devices }
                    .buttonStyle(.link).disabled(interfaceLocked || batch.isFrozen)
            }
        } else if let route = devices.selectedRoute, !route.assessment.permitsSigning {
            Text(route.assessment.status.description).font(.caption)
        }
    }

    @ViewBuilder var counterSignatureSelection: some View {
        if let entry = selectedDocument, entry.format == .cadesCounterSign {
            VStack(alignment: .leading, spacing: 6) {
            Text("Firma da controfirmare").font(.caption).foregroundStyle(.secondary)
            Picker("Firma da controfirmare", selection: Binding(get: { entry.configuration.counterSignatureKey ?? "" }, set: { key in
                do { try batch.selectCounterSignature(key, for: entry.id); provider.pin = "" }
                catch { status = error.localizedDescription }
            })) {
                Text("Seleziona firma…").tag("")
                ForEach(entry.snapshot.cmsSignatureTargets) { target in Text(target.title).tag(target.signatureKey) }
            }.pickerStyle(.menu).labelsHidden().frame(maxWidth: .infinity)
                .modifier(SignumFlexibleControl()).disabled(interfaceLocked || batch.isFrozen)
            }
        }
    }

    var formatDetails: String {
        switch selectedDocument?.format.rawValue ?? format.rawValue {
        case "asics", "asice":
            return "ASiC-S: un file per contenitore. ASiC-E: da 2 a 4 file, fino a 8 MiB ciascuno e 16 MiB totali. Data dichiarata, non certificata."
        case "xades": return "XAdES: XML UTF-8, una firma, massimo 8 MiB. Data dichiarata, non una marca temporale."
        case "cadesDetached": return "CAdES detached: conserva l’originale: la verifica .p7s richiede il contenuto esatto."
        case "cadesCoSign": return "Cofirma CAdES: aggiunge una firma sullo stesso contenuto della busta P7M. Le firme esistenti vengono conservate."
        case "cadesCounterSign": return "Controfirma CMS: firma la firma CMS selezionata, senza aggiungere un cofirmatario del contenuto."
        case "pades": return "PAdES: ogni PDF richiede un’anteprima pronta e la conferma dell’aspetto prima dell’approvazione."
        default: return "CAdES: incorpora il documento in una busta CMS/P7M. Le copie firmate non sovrascrivono file esistenti. Le destinazioni definitive sono fissate all’approvazione."
        }
    }

    var certificateControls: some View {
        SignumInspectorSection("Scegli il certificato") {
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

    var signingControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 10) {
                if !batch.isApproved {
                    Text(signingAvailability).font(.callout).accessibilityIdentifier("signum.signing-availability")
                    if canApproveBatch {
                        Text(SigningConsentDeclaration.text(documentCount: batch.documents.count))
                            .font(.caption).foregroundStyle(.secondary)
                    }
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
                    }
                    if presentation.stage == .completed { Text("Sessione conclusa. Consulta gli esiti nei documenti.").font(.caption) }
                    if batch.needsOutcomeReview {
                        Text("Esito incerto: controlla dispositivo ed eventuale output prima di continuare. La firma non verrà ripetuta.").font(.caption)
                        Button("Ho verificato l'esito: consenti il prossimo documento") { batch.acknowledgeUncertainOutcome(); provider.pin = "" }
                            .disabled(batch.isRunning)
                    }
                    if presentation.pinPrompt == nil || interfaceLocked {
                        if batch.isRunning || batch.isContinuingAuthenticated {
                            ProgressView("Firma in corso…").controlSize(.small)
                        }
                        HStack(spacing: 8) {
                            Button("Annulla documenti in attesa") { batch.cancelPending(); provider.pin = "" }
                                .disabled(batch.nextDocument == nil)
                            if batch.isRunning || batch.isContinuingAuthenticated {
                                Button("Interrompi firma corrente") { batch.activeOperation?.requestCancellation(); authenticationSession?.requestStop() }
                            }
                        }.buttonStyle(.bordered).controlSize(.small).modifier(SignumFlexibleControl())
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
            }
            HStack(spacing: 10) {
                if batch.isApproved, presentation.pinPrompt != nil, !interfaceLocked {
                    Button { batch.cancelPending(); provider.pin = "" } label: {
                        Text("Annulla").frame(maxWidth: .infinity)
                    }.buttonStyle(.bordered).controlSize(.large)
                        .disabled(batch.nextDocument == nil)
                        .accessibilityIdentifier("signum.cancel-pending")
                }
                Button {
                    if batch.isApproved { authorizeNextDocument() } else { prepareBatch() }
                } label: { Text(presentation.stage == .signing ? "Firma in corso…" : (batch.isApproved ? "Firma" : "Firma…")).frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .tint(SignumAppearance.burgundy)
                    .accessibilityIdentifier("signum.approve-signing")
                    .disabled(batch.isApproved ? !canAuthorizeNext : !canApproveBatch)
            }.modifier(SignumFlexibleControl())
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    var pdfWorkspace: some View {
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
                     : (format == .asics || format == .asice) ? "Seleziona i documenti da includere nel contenitore ASiC." : format == .xades ? "XAdES firma un XML UTF-8. Include una data dichiarata, non una marca temporale." : "Con CAdES il documento viene incorporato in una busta .p7m.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct SignumInspectorSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content
    init(_ title: String, @ViewBuilder content: @escaping () -> Content) { self.title = title; self.content = content }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) { Text(title).font(.subheadline.weight(.semibold)); content() }
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
#endif
