#if os(macOS)
import SwiftUI
import SignumCore

extension SignumWindow {
    var signingScreen: some View {
        HSplitView {
            documentWorkspace.frame(minWidth: 410, maxWidth: .infinity, maxHeight: .infinity)
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("Firma").font(.headline)
                        Picker("Firmatario", selection: Binding(get: { devices.selectedRouteID ?? "" }, set: { selectRoute($0) })) {
                            Text("Seleziona certificato…").tag("")
                            ForEach(CertificateVisibility(devices.certificates).eligible) { group in
                                ForEach(group.routes) { route in Text(route.title).tag(route.id) }
                            }
                        }.disabled(interfaceLocked || batch.isFrozen)
                        if let route = devices.selectedRoute {
                            Text(route.deviceDescription).font(.caption).foregroundStyle(.secondary)
                        }
                        Picker("Formato", selection: formatBinding) {
                            Text("CAdES · .p7m").tag(SignumFormat.cades)
                            Text("PAdES · PDF").tag(SignumFormat.pades)
                                .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectPAdES(for: $0.snapshot) } ?? false)
                            Section("Altri formati") {
                                Text("CAdES detached · .p7s").tag(SignumFormat.cadesDetached)
                                Text("Cofirma CAdES").tag(SignumFormat.cadesCoSign)
                                Text("Controfirma CMS").tag(SignumFormat.cadesCounterSign)
                                Text("XAdES · XML").tag(SignumFormat.xades)
                                    .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectXAdES(for: $0.snapshot) } ?? false)
                                Text("ASiC-S").tag(SignumFormat.asics).disabled(selectedDocument != nil)
                                Text("ASiC-E").tag(SignumFormat.asice).disabled(selectedDocument != nil)
                            }
                        }.disabled(interfaceLocked || batch.isFrozen || selectedDocument?.format.isASiC == true)
                        Picker("Destinazione", selection: $saveAlongsideOriginal) {
                            Text("Accanto agli originali").tag(true)
                            Text("Cartella comune").tag(false)
                        }.disabled(interfaceLocked || batch.isFrozen)
                        if !saveAlongsideOriginal {
                            Button(customDirectory?.lastPathComponent ?? "Scegli cartella…") { chooseDestination() }
                                .disabled(interfaceLocked || batch.isFrozen)
                        }
                        if selectedDocument?.format == .cadesCounterSign {
                            formatPicker
                        }
                        DisclosureGroup("Opzioni", isExpanded: $showSigningOptions) {
                            formatPicker
                            destinationControls
                        }
                        DisclosureGroup("Dettagli certificato", isExpanded: $showCertificates) { certificateControls }
                        DisclosureGroup("Dispositivi e diagnostica", isExpanded: $showConnections) { tokenControls }
                    }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                signingControls.padding(14)
                statusFooter.padding(.horizontal, 14).padding(.bottom, 12)
            }
            .frame(minWidth: 300, idealWidth: 330, maxWidth: 390)
            .background(Color(nsColor: .controlBackgroundColor))
        }
    }
    var formatPicker: some View {
        SignumInspectorSection(selectedDocument == nil ? "Formato nuovi documenti" : "Formato firma") {
            VStack(alignment:.leading,spacing:6) {
                Picker("Formato firma",selection:formatBinding) {
                    Text("ASiC-S — un documento").tag(SignumFormat.asics)
                        .disabled(selectedDocument.map { $0.format != .asics } ?? false)
                    Text("ASiC-E — più documenti").tag(SignumFormat.asice)
                        .disabled(selectedDocument.map { $0.format != .asice } ?? false)
                    Text("CAdES — documento .p7m").tag(SignumFormat.cades)
                    Text("CAdES detached — firma .p7s").tag(SignumFormat.cadesDetached)
                    Text("Cofirma CAdES — stesso contenuto").tag(SignumFormat.cadesCoSign)
                    Text("Controfirma CMS — firma selezionata").tag(SignumFormat.cadesCounterSign)
                    Text("XAdES — XML firmato").tag(SignumFormat.xades)
                        .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectXAdES(for:$0.snapshot) } ?? false)
                    Text("PAdES — PDF firmato").tag(SignumFormat.pades)
                        .disabled(selectedDocument.map { !DocumentSigningConfiguration.canSelectPAdES(for:$0.snapshot) } ?? false)
                }.pickerStyle(.menu).labelsHidden().accessibilityIdentifier("signum.current-format")
                    .disabled(interfaceLocked || batch.isFrozen || selectedDocument?.format.isASiC == true)
                if selectedDocument?.format.isASiC == true || (selectedDocument == nil && (format == .asics || format == .asice)) {
                    Text("ASiC-S: un file per contenitore. ASiC-E: seleziona insieme da 2 a 4 file, fino a 8 MiB ciascuno e 16 MiB totali. Tutti i contenuti saranno firmati con XAdES-B e una data dichiarata, non certificata.").font(.caption).foregroundStyle(.secondary)
                }
                if selectedDocument?.format == .xades || (selectedDocument == nil && format == .xades) {
                    Text("XML UTF-8 · una firma · massimo 8 MiB. XAdES include sempre una data dichiarata, non una marca temporale.").font(.caption).foregroundStyle(.secondary)
                }
                if let entry=selectedDocument {
                    Text("Documento corrente: " + entry.snapshot.originalURL.lastPathComponent).font(.caption).lineLimit(2)
                    Text(entry.format.title).font(.callout.bold())
                    if entry.format == .cadesCounterSign {
                        Picker("Firma da controfirmare",selection:Binding(get:{entry.configuration.counterSignatureKey ?? ""},set:{ key in
                            do {try batch.selectCounterSignature(key,for:entry.id);provider.pin=""} catch {status=error.localizedDescription}
                        })) {
                            Text("Seleziona esplicitamente…").tag("")
                            ForEach(entry.snapshot.cmsSignatureTargets) { target in Text(target.title).tag(target.signatureKey) }
                        }.disabled(interfaceLocked || batch.isFrozen)
                        Text("La controfirma riguarda la firma selezionata, non aggiunge un cofirmatario del contenuto.").font(.caption)
                    }
                    if entry.format == .cadesDetached { Text("Conserva anche l’originale: la verifica .p7s richiede la selezione separata del contenuto esatto.").font(.caption) }
                    if entry.format.isASiC {
                        Text("Contenuti: " + entry.snapshot.containerPayloadNames.joined(separator:", ")).font(.caption)
                    }
                    if !batch.isFrozen {
                        Text("Puoi cambiare formato fino all’approvazione. Gli altri documenti mantengono la propria scelta.")
                            .font(.caption).foregroundStyle(.secondary)
                        Picker("Per i prossimi documenti",selection:$format) {
                            Text("CAdES").tag(SignumFormat.cades)
                            Text("CAdES detached").tag(SignumFormat.cadesDetached)
                            Text("Cofirma CAdES").tag(SignumFormat.cadesCoSign)
                            Text("Controfirma CMS").tag(SignumFormat.cadesCounterSign)
                            Text("XAdES").tag(SignumFormat.xades)
                            Text("ASiC-S").tag(SignumFormat.asics)
                            Text("ASiC-E").tag(SignumFormat.asice)
                            Text("PAdES").tag(SignumFormat.pades)
                        }.pickerStyle(.menu).font(.caption).disabled(interfaceLocked)
                    }
                }
            }.padding(5)
        }
    }

    var destinationControls: some View {
        SignumInspectorSection("Destinazione") {
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
                    Button("Firma…") { prepareBatch() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(!canApproveBatch)
                    Text("Il clic su Firma approva i documenti e le destinazioni mostrati.")
                        .font(.caption).foregroundStyle(.secondary)
                    if review.isPreparing { ProgressView("Preparazione del riepilogo…").controlSize(.small) }
                    if !review.issue.isEmpty { Text(review.issue).font(.caption) }
                    if selectedDocument?.format == .pades, let entry = selectedDocument,
                        !readyPreviews.contains(entry.id) {
                        Text("Controlla prima l’anteprima PDF e torna all’elenco documenti.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    DisclosureGroup("Dettagli autenticazione") {
                        Text(authenticationExplanation)
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
            }.padding(5)
        }
    }

    var statusFooter: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text(status).font(.caption).textSelection(.enabled)
            Spacer(minLength: 0)

        }
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
