#if os(macOS)
import Foundation
import Combine
import SignumCore

/// Consent and PIN flow of one signing window, outside the View so it can be
/// tested without UI. Holds the approved route/holder/mode and the optional
/// authenticated batch session; never stores a PIN.
@MainActor final class SigningAuthorization: ObservableObject {
    @Published var approvedHolder = ""
    @Published var approvedRoute: DeviceCertificateRoute?
    @Published private(set) var approvedMode: BatchAuthenticationMode = .perSignature
    /// One PIN for the remaining jobs, when the approved batch permits it.
    @Published var session: BatchCAdESSession?
    /// The current approval already tried to open an authenticated session.
    @Published var attempted = false
    /// Session-level text under the PIN field (never the PIN refusal itself).
    @Published var notice = ""

    /// What the window must provide; every callback runs on the MainActor.
    struct Hooks {
        /// The window session that started the request is still current.
        var accepts: () -> Bool
        /// Ties a task to the window session so closing it drains the work.
        var own: (Task<Void, Never>) -> Void
        var status: (String) -> Void
        /// A document completed (refresh "last signed file").
        var signed: () -> Void = {}
    }

    var isContinuing: Bool { session?.canContinue ?? false }

    func approved(holder: String, route: DeviceCertificateRoute, mode: BatchAuthenticationMode, formats: [SigningFormat]) {
        approvedHolder = holder; approvedRoute = route; approvedMode = mode
        attempted = false
        notice = BatchAuthenticationPolicy.explanation(formats: formats, serial: route.token.serial, mode: mode)
    }
    /// The consent no longer matches the device or the documents.
    func withdrawApproval() { approvedRoute = nil; approvedHolder = ""; attempted = false }
    /// A finished session: keep nothing that belongs to it.
    func clear() { approvedRoute = nil; approvedHolder = ""; attempted = false; notice = "" }
    /// New session requested by the user while nothing is running.
    func reset() { session?.requestStop(); session = nil; attempted = false; notice = "" }
    /// Window closed or revoked: stop the session and retire its worker once idle.
    func revoke(batch: BatchSigningCoordinator, own: (Task<Void, Never>) -> Void) {
        attempted = false; notice = ""
        guard let context = session else { return }
        context.requestStop()
        guard !batch.isContinuingAuthenticated else { return } // The continuation retires it.
        let retirement = batch.retireAuthenticatedSession(using: context)
        own(Task { @MainActor in
            await retirement.value
            if self.session === context { self.session = nil }
        })
    }

    /// Submit the typed PIN for the next approved document. The field is cleared
    /// synchronously. Returns false when nothing was started.
    @discardableResult
    func authorizeNext(pin: inout String, batch: BatchSigningCoordinator, interaction: SigningInteraction,
                       worker: IsolatedPKCS11Client, padesAvailable: Bool = SignumPAdESHelper.available,
                       hooks: Hooks) -> Bool {
        guard let route = approvedRoute else { return false }
        let holder = approvedHolder, mode = approvedMode
        if !attempted, let plan = batch.approval,
           BatchAuthenticationPolicy.canAttempt(jobs: plan.jobs, serial: route.token.serial, mode: mode) {
            attempted = true
            do {
                session = try BatchCAdESSession(approval: plan, serial: route.token.serial,
                    moduleIdentity: route.moduleIdentity, automaticModule: route.origin == .known,
                    temporaryPIN: mode == .temporaryPIN, startingAt: batch.nextDocument?.id,
                    remainingSnapshotIDs: Set(batch.documents.filter { !$0.state.isTerminal }.map(\.id)),
                    executable: worker.executable,
                    padesRunner: padesAvailable ? { job, operation, signer in
                        // The helper loads no middleware and never receives the PIN.
                        try SignumPAdESHelper.sign(job: job, pin: nil, appearanceName: holder, field: nil, operation: operation,
                                                   appearance: job.padesAppearance, remoteSigner: signer)
                    } : nil)
            } catch { pin = ""; hooks.status(error.localizedDescription); return false }
        }
        let session = self.session, documentID = batch.nextDocument?.id
        let submission = interaction.submitPIN(&pin, batch: batch, execute: { job, pin, operation in
            try Self.execute(job: job, pin: pin, operation: operation, route: route, session: session, worker: worker, holder: holder)
        }, completion: { result in
            guard hooks.accepts() else { return }
            hooks.signed()
            guard let session else { hooks.status(Self.perSignatureStatus(result, batch: batch)); return }
            if session.canContinue && batch.isApproved { self.continueBatch(session, batch: batch, mode: mode, hooks: hooks) }
            else { self.retire(session, refusal: Self.refusal(result, document: documentID, batch: batch), batch: batch, hooks: hooks) }
        })
        guard let submission else { return false }
        hooks.own(submission)
        return true
    }

    /// One approved job, routed by format. A session, when present, signs every job.
    nonisolated static func execute(job: SigningJob, pin: String, operation: SigningOperation, route: DeviceCertificateRoute,
                                    session: BatchCAdESSession?, worker: IsolatedPKCS11Client, holder: String) throws {
        guard job.providerContext != nil else { throw SignumError.module("Contesto dispositivo approvato mancante.") }
        try route.requireCurrentModule()
        if let session { try session.sign(job: job, pin: pin, operation: operation) }
        else if job.format == .cades { try job.signCAdES(using: worker, pin: pin, operation: operation) }
        else if job.format.isAdvancedCAdES { try job.signAdvancedCAdES(using: worker, pin: pin, operation: operation) }
        else if job.format == .xades || job.format.isASiC { try job.signXAdES(using: worker, pin: pin, operation: operation) }
        else { try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: holder, field: nil, operation: operation, appearance: job.padesAppearance) }
    }

    private func continueBatch(_ session: BatchCAdESSession, batch: BatchSigningCoordinator, mode: BatchAuthenticationMode, hooks: Hooks) {
        notice = Self.continuingNotice(mode)
        hooks.own(Task { @MainActor in
            await batch.continueAuthenticatedBatch(using: session)
            if self.session === session { self.session = nil }
            guard hooks.accepts() else { return }
            hooks.signed()
            self.notice = batch.authenticationNotice.isEmpty ? "Sessione autenticata conclusa." : batch.authenticationNotice
            hooks.status(Self.summary(batch))
        })
    }

    /// A PIN refusal proven before C_Sign. The coordinator keeps the document
    /// authorizable and records the refusal on it instead of throwing.
    static func refusal(_ result: Result<Void, Error>, document: UUID?, batch: BatchSigningCoordinator) -> Error? {
        if case .failure(let error) = result, error.allowsNewPIN { return error }
        guard let refusal = batch.documents.first(where: { $0.id == document })?.authenticationRefusal, refusal.allowsNewPIN else { return nil }
        return refusal
    }

    private func retire(_ session: BatchCAdESSession, refusal: Error?, batch: BatchSigningCoordinator, hooks: Hooks) {
        let retirement = batch.retireAuthenticatedSession(using: session)
        hooks.own(Task { @MainActor in
            await retirement.value
            if self.session === session { self.session = nil }
            guard hooks.accepts() else { return }
            if let error = refusal {
                // Nothing was signed: the next PIN may open a new session for the same batch.
                // The PIN field shows the refusal; keep the session text quiet.
                self.attempted = false; self.notice = ""
                hooks.status(error.localizedDescription)
                return
            }
            self.notice = Self.retiredNotice(batch)
            hooks.status(Self.summary(batch))
        })
    }

    // Texts, pure so they can be tested without a token.
    static func continuingNotice(_ mode: BatchAuthenticationMode) -> String {
        mode == .temporaryPIN ? "PIN temporaneo attivo soltanto per questo batch approvato."
                              : "Sessione autenticata per questo batch. Nessun PIN riutilizzato."
    }
    static func retiredNotice(_ batch: BatchSigningCoordinator) -> String {
        guard batch.authenticationNotice.isEmpty else { return batch.authenticationNotice }
        return batch.documents.contains(where: { $0.state == .failed || $0.state == .uncertain })
            ? "Batch interrotto. Consulta i dettagli; nessun tentativo viene ripetuto."
            : "Riuso non verificabile per questa chiave o sessione: PIN esplicito per le firme restanti."
    }
    static func perSignatureStatus(_ result: Result<Void, Error>, batch: BatchSigningCoordinator) -> String {
        switch result {
        case .success: return batch.nextDocument == nil ? "Sessione conclusa. Consulta gli esiti." : "Consulta l'esito e inserisci il PIN per la firma successiva."
        case .failure(let error): return error.localizedDescription
        }
    }
    static func summary(_ batch: BatchSigningCoordinator) -> String { BatchWorkspaceSummary.summary(batch.documents.map(\.state)) }
}
#endif
