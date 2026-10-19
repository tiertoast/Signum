#if os(macOS)
import Foundation
import Combine
import Darwin

public enum BatchDocumentState: String, Sendable {
    case pending, preparing, waitingForAuthorization, signing, verifying, completed, failed, uncertain, cancelled
    public var message: String {
        switch self {
        case .pending: return "Da firmare"
        case .preparing: return "In preparazione"
        case .waitingForAuthorization: return "Autorizzazione richiesta"
        case .signing: return "In firma"
        case .verifying: return "In verifica"
        case .completed: return "Completato"
        case .failed: return "Errore"
        case .uncertain: return "Esito incerto"
        case .cancelled: return "Annullato"
        }
    }
    public var isTerminal: Bool { [.completed, .failed, .uncertain, .cancelled].contains(self) }
}

public struct BatchDocument: Identifiable, Sendable {
    public var id: UUID { snapshot.identity.id }
    public let snapshot: DocumentSnapshot
    public fileprivate(set) var configuration: DocumentSigningConfiguration
    public var format: SigningFormat { configuration.format }
    init(snapshot: DocumentSnapshot) {
        self.snapshot = snapshot
        configuration = .init(snapshotID:snapshot.identity.id,format:snapshot.format)
    }
    public fileprivate(set) var destination: URL?
    public fileprivate(set) var state: BatchDocumentState = .pending
    public fileprivate(set) var result: String = ""
}

public struct BatchApproval: Sendable {
    public let id: UUID
    public let jobs: [SigningJob]
    public var technicalDetails: String {
        jobs.map { "\($0.snapshot.originalURL.lastPathComponent)\n\($0.approvalDescription)\nJob: \($0.id)\nSnapshot: \($0.snapshotIdentity.id)\nProvider: \($0.providerPath)\nSlot: \($0.slot) · ID certificato: \($0.certificate.id)\nCertificato SHA-256: \($0.certificateSHA256)" }.joined(separator: "\n\n")
    }
}

/// UI mutations are main-actor isolated. Acquisition, planning and signing run
/// off-main. One explicit authorizeNext call can execute exactly ONE job; the
/// coordinator never stores a PIN or retries a completed/failed request.
@MainActor public final class BatchSigningCoordinator: ObservableObject {
    public static let maximumDocuments = 32
    public static let maximumTotalBytes = SigningResourceLimits.maximumSessionBytes
    @Published public private(set) var documents: [BatchDocument] = []
    @Published public private(set) var selectionIssues: [String] = []
    @Published public private(set) var selectionTechnicalDetails: [String] = []
    @Published public private(set) var isPreparing = false
    @Published public private(set) var isFrozen = false
    @Published public private(set) var isApproved = false
    @Published public private(set) var isRunning = false
    @Published public private(set) var isContinuingAuthenticated = false
    @Published public private(set) var authenticationNotice = ""
    @Published public private(set) var needsOutcomeReview = false
    @Published public private(set) var activeOperation: SigningOperation?
    public private(set) var approval: BatchApproval?
    @Published public private(set) var review: BatchApproval?
    @Published public private(set) var revision = UUID()
    private var reviewRequest = UUID()
    private var acquisitionID = UUID()
    private var activeID: UUID?
    private var acquisitionOperation: SigningOperation?
    private var captureDocument: @Sendable (URL, SigningFormat, SigningOperation) throws -> DocumentSnapshot = {
        url, format, operation in try DocumentSnapshot.capture(source: url, format: format, isCancelled: { operation.isCancellationRequested })
    }
    private let padesHelper: URL?
    public init(padesHelper: URL? = nil) { self.padesHelper = padesHelper }
    init(capture: @escaping @Sendable (URL, SigningFormat, SigningOperation) throws -> DocumentSnapshot) { captureDocument = capture; padesHelper = nil }

    /// Invalidates a displayed but unapproved plan. Approved jobs stay immutable.
    public func invalidateReview() {
        guard !isFrozen else { return }
        reviewRequest = UUID(); review = nil
    }

    /// Synchronous invalidation precedes any asynchronous preflight/render. No
    /// source reread, clone, output or private operation is performed here.
    public func setFormat(_ format: SigningFormat, for id: UUID) throws {
        guard !isFrozen, !isApproved, !isPreparing, !isRunning, !isContinuingAuthenticated,
              let index=documents.firstIndex(where:{$0.id == id}), !documents[index].state.isTerminal else {
            throw Self.failure("Il formato è bloccato dopo l’approvazione. Prepara una nuova sessione.")
        }
        guard documents[index].format != format else { return }
        if format == .pades, !DocumentSigningConfiguration.canSelectPAdES(for:documents[index].snapshot) {
            throw Self.failure("Questo documento non è un PDF. Per questo file scegli CAdES.")
        }
        invalidateReview(); revision = UUID()
        documents[index].configuration = .init(snapshotID:id,format:format)
        documents[index].destination = nil
    }

    /// Read-only preflight for the main-screen summary. Does not freeze/approve,
    /// create output or ask for a PIN; edits invalidate the plan by revision.
    public func prepareReview(provider: String, slot: UInt, certificate: SignumCertificate,
                              der: Data, destination: BatchOutputDestination,
                              providerContext: SigningProviderContext? = nil,
                              appearances: [UUID: RenderedPAdESAppearance] = [:],
                              isCancelled: @escaping @Sendable () -> Bool = { false }) async throws -> BatchApproval {
        guard !isFrozen, !isPreparing, !documents.isEmpty, documents.allSatisfy({ !$0.state.isTerminal }) else { throw Self.failure("Selezione non disponibile.") }
        invalidateReview()
        let request = reviewRequest, version = revision, selected = documents.map(\.snapshot), padesHelper = padesHelper
        let formats = Dictionary(uniqueKeysWithValues:documents.map { ($0.id,$0.format) })
        let control = SigningOperation()
        let cancelled: @Sendable () -> Bool = { control.isCancellationRequested || isCancelled() }
        let work = Task.detached(priority: .userInitiated) {
            if cancelled() { throw CancellationError() }
            try CertificateEligibility.requireEligible(certificateDER: der)
            for snapshot in selected {
                if cancelled() { throw CancellationError() }
                _ = try snapshot.verifiedBytes()
            }
            if cancelled() { throw CancellationError() }
            let outputs = try destination.plan(selected,formats:formats)
            let jobs = try zip(selected, outputs).map { snapshot, output in
                try SigningJob(snapshot: snapshot, format: formats[snapshot.identity.id], providerPath: provider, slot: slot, certificate: certificate,
                    certificateDER: der, destination: output.url, destinationDirectoryIdentity: output.directoryIdentity,
                    padesSourcePreflight: formats[snapshot.identity.id] == .pades ? Self.preflight(snapshot, helper: padesHelper, isCancelled: cancelled) : nil,
                    padesAppearance: appearances[snapshot.identity.id], providerContext: providerContext)
            }
            return BatchApproval(id: UUID(), jobs: jobs)
        }
        let result = try await withTaskCancellationHandler(operation: { try await work.value },
            onCancel: { control.requestCancellation(); work.cancel() })
        guard !Task.isCancelled, !isCancelled(), reviewRequest == request, revision == version, !isFrozen, !isPreparing else {
            throw Self.failure("Il riepilogo è cambiato. Controlla la nuova lista prima di firmare.")
        }
        review = result
        return result
    }

    /// Synchronous MainActor boundary: freeze exactly the plan already displayed.
    public func freezeReview(_ value: BatchApproval) throws {
        guard !isFrozen, !isPreparing, !isApproved, review?.id == value.id,
              value.jobs.map(\.snapshotIdentity.id) == documents.map(\.id),
              value.jobs.map(\.format) == documents.map(\.format),
              documents.allSatisfy({ !$0.state.isTerminal }) else { throw Self.failure("Riepilogo non più valido. Controlla la lista aggiornata.") }
        approval = value; isFrozen = true
        for i in documents.indices { documents[i].destination = value.jobs[i].destination }
    }

    public var nextDocument: BatchDocument? { documents.first { !$0.state.isTerminal } }
    public var finishedCount: Int { documents.filter { $0.state.isTerminal }.count }
    public var sessionReport: String {
        documents.map { "\($0.snapshot.originalURL.lastPathComponent) · \($0.format.rawValue.uppercased()) · \($0.state.message)\n\($0.destination?.path ?? "Destinazione da scegliere")\n\($0.result)" }.joined(separator: "\n\n")
    }

    /// Reserve the UI selection synchronously, before scheduling a Task. A click
    /// in that scheduling gap must never approve the preceding displayed list.
    @discardableResult public func enqueueDocuments(_ urls: [URL], format: SigningFormat) -> Task<Void, Never>? {
        guard !isFrozen, !isPreparing, !isRunning else { return nil }
        invalidateReview(); revision = UUID(); isPreparing = true
        let ticket = UUID(); acquisitionID = ticket
        return Task { @MainActor in
            guard acquisitionID == ticket, !Task.isCancelled else { if acquisitionID == ticket { isPreparing = false }; return }
            isPreparing = false
            await addDocuments(urls, format: format)
        }
    }

    public func addDocuments(_ urls: [URL], format: SigningFormat) async {
        guard !isFrozen, !isPreparing, !isRunning else { return }
        invalidateReview(); revision = UUID()
        isPreparing = true; selectionIssues = []; selectionTechnicalDetails = []
        if urls.count > Self.maximumDocuments { selectionIssues.append("Acquisiti soltanto i primi 32 elementi della selezione.") }
        let request = UUID(); acquisitionID = request
        let operation = SigningOperation(), capture = captureDocument
        acquisitionOperation = operation
        defer { if acquisitionID == request { isPreparing = false; acquisitionOperation = nil } }
        for url in urls.prefix(Self.maximumDocuments) {
            guard acquisitionID == request, !Task.isCancelled else { operation.requestCancellation(); break }
            guard documents.count < Self.maximumDocuments else {
                selectionIssues.append("Massimo \(Self.maximumDocuments) documenti per sessione."); break
            }
            if documents.contains(where: { $0.snapshot.originalURL.standardizedFileURL == url.standardizedFileURL }) {
                selectionIssues.append("\(url.lastPathComponent): documento già selezionato."); continue
            }
            let captureTask = Task.detached(priority: .userInitiated) { Result { try capture(url, format, operation) } }
            let captured = await withTaskCancellationHandler(operation: { await captureTask.value },
                onCancel: { operation.requestCancellation(); captureTask.cancel() })
            guard acquisitionID == request, !Task.isCancelled else { if case .success(let snapshot) = captured { snapshot.close() }; break }
            switch captured {
            case .failure(let error):
                selectionIssues.append("\(url.lastPathComponent): \(error.localizedDescription)")
                if let failure = error as? DocumentAcquisitionFailure { selectionTechnicalDetails.append("\(url.lastPathComponent): \(failure.kind.rawValue) · \(failure.technicalDetails)") }
            case .success(let snapshot):
                if documents.contains(where: { $0.snapshot.identity.sha256 == snapshot.identity.sha256 && $0.format == format }) {
                    snapshot.close(); selectionIssues.append("\(url.lastPathComponent): contenuto duplicato nello stesso formato.")
                } else if documents.reduce(0, { $0 + $1.snapshot.identity.byteCount }) + snapshot.identity.byteCount > Self.maximumTotalBytes {
                    snapshot.close(); selectionIssues.append("Dimensione totale massima: 128 MiB.")
                } else { documents.append(BatchDocument(snapshot: snapshot)) }
            }
        }
    }

    public func remove(_ id: UUID) {
        guard !isFrozen, !isPreparing, !isRunning, let index = documents.firstIndex(where: { $0.id == id }) else { return }
        invalidateReview(); revision = UUID()
        documents.remove(at: index).snapshot.close()
    }
    public func reset() {
        guard !isRunning, !isPreparing, !isContinuingAuthenticated else { return }
        authenticationNotice = ""
        isFrozen = false; invalidateReview(); revision = UUID()
        documents.forEach { $0.snapshot.close() }
        documents = []; approval = nil; selectionIssues = []; selectionTechnicalDetails = []
        isFrozen = false; isApproved = false; needsOutcomeReview = false
    }

    public func prepareApproval(provider: String, slot: UInt, certificate: SignumCertificate,
                                der: Data, directory: URL) async throws -> BatchApproval {
        try await prepareApproval(provider: provider, slot: slot, certificate: certificate, der: der, destination: .commonDirectory(directory))
    }

    public func prepareApproval(provider: String, slot: UInt, certificate: SignumCertificate,
                                der: Data, destination: BatchOutputDestination = .originalFolders) async throws -> BatchApproval {
        guard !isFrozen, !isPreparing, !documents.isEmpty, documents.allSatisfy({ !$0.state.isTerminal }) else { throw Self.failure("Selezione non disponibile.") }
        isFrozen = true; isPreparing = true
        let request = UUID(); acquisitionID = request
        let selected = documents.map(\.snapshot), padesHelper = padesHelper
        let formats = Dictionary(uniqueKeysWithValues:documents.map { ($0.id,$0.format) })
        do {
            let prepared = try await Task.detached(priority: .userInitiated) {
                try CertificateEligibility.requireEligible(certificateDER: der)
                for snapshot in selected { _ = try snapshot.verifiedBytes() }
                let outputs = try destination.plan(selected,formats:formats)
                let jobs = try zip(selected, outputs).map { snapshot, output in
                    try SigningJob(snapshot: snapshot, format: formats[snapshot.identity.id], providerPath: provider, slot: slot,
                        certificate: certificate, certificateDER: der, destination: output.url,
                        destinationDirectoryIdentity: output.directoryIdentity,
                        padesSourcePreflight: formats[snapshot.identity.id] == .pades ? Self.preflight(snapshot, helper: padesHelper) : nil)
                }
                return BatchApproval(id: UUID(), jobs: jobs)
            }.value
            guard acquisitionID == request, documents.allSatisfy({ !$0.state.isTerminal }) else { throw Self.failure("Preparazione annullata.") }
            approval = prepared
            for index in documents.indices { documents[index].destination = prepared.jobs[index].destination }
            isPreparing = false
            return prepared
        } catch { isFrozen = false; isPreparing = false; throw error }
    }

    nonisolated private static func preflight(_ snapshot: DocumentSnapshot, helper: URL?, isCancelled: () -> Bool = { false }) throws -> PAdESSourcePreflight {
        let result = try PAdESSourcePreflight.inspect(snapshot, helper: helper, isCancelled: isCancelled)
        try result.requireAccepted(for: snapshot)
        return result
    }

    public func confirm(_ value: BatchApproval) throws {
        guard !isApproved, let approval, value.id == approval.id, isFrozen, !isPreparing,
              value.jobs.map(\.snapshotIdentity.id) == documents.map(\.id),
              value.jobs.map(\.format) == documents.map(\.format) else { throw Self.failure("Riepilogo non più valido.") }
        isApproved = true
        if !documents.isEmpty { documents[0].state = .waitingForAuthorization }
    }
    public func declineApproval() {
        guard !isApproved, !isPreparing else { return }
        approval = nil; isFrozen = false
        for index in documents.indices { documents[index].destination = nil }
    }

    public func cancelPending() {
        invalidateReview(); revision = UUID()
        acquisitionOperation?.requestCancellation()
        acquisitionID = UUID(); isPreparing = false; acquisitionOperation = nil
        for id in documents.map(\.id) { cancelDocument(id) }
    }
    public func cancelDocument(_ id: UUID) {
        guard id != activeID, let index = documents.firstIndex(where: { $0.id == id }), !documents[index].state.isTerminal else { return }
        invalidateReview(); revision = UUID()
        documents[index].state = .cancelled
        documents[index].result = "Nessuna richiesta privata inviata."
        documents[index].snapshot.close()
    }
    public func cancelAll() { cancelPending(); activeOperation?.requestCancellation() }
    public func acknowledgeUncertainOutcome() { if !isRunning { needsOutcomeReview = false } }

    public func authorizeNext(pin: String, expectedDocumentID: UUID? = nil, execute: @escaping @Sendable (SigningJob, String, SigningOperation) throws -> Void) async throws {
        guard isApproved, !isRunning, !needsOutcomeReview, let next = nextDocument,
              expectedDocumentID == nil || next.id == expectedDocumentID,
              !isContinuingAuthenticated, !pin.isEmpty, pin.utf8.count <= 64, !pin.utf8.contains(0),
              next.format != .pades || PAdESInputContract.validPIN(pin) else { throw Self.failure("Autorizza il documento corrente con il PIN.") }
        await executeNext(expectedDocumentID: expectedDocumentID) { job, operation in try execute(job, pin, operation) }
    }

    /// Retire an attempted session even when its first document failed locally.
    @discardableResult public func retireAuthenticatedSession(using session: BatchCAdESSession) -> Task<Void, Never> {
        let belongsToApproval = approval?.id == session.approvalID
        let wasContinuing = isContinuingAuthenticated
        if belongsToApproval { isContinuingAuthenticated = true }
        session.requestStop()
        return Task { @MainActor in
            await session.stopAndWait()
            guard belongsToApproval, approval?.id == session.approvalID else { return }
            if session.cleanupUncertain {
                needsOutcomeReview = true
                authenticationNotice = "Chiusura della sessione non confermata. Verifica il dispositivo prima di continuare."
            }
            isContinuingAuthenticated = wasContinuing
        }
    }

    /// No PIN argument or stored secret. Only a capability bound to this exact
    /// approved batch can continue; each job is verified/committed before next.
    public func continueAuthenticatedBatch(using session: BatchCAdESSession) async {
        guard isApproved, !isRunning, !isContinuingAuthenticated, approval?.id == session.approvalID else { session.requestStop(); return }
        isContinuingAuthenticated = true
        while session.canContinue, !needsOutcomeReview, let next = nextDocument {
            await executeNext(expectedDocumentID: next.id) { job, operation in try session.signCAdES(job: job, pin: nil, operation: operation) }
            guard documents.first(where: { $0.id == next.id })?.state == .completed else { break }
        }
        await retireAuthenticatedSession(using: session).value
        isContinuingAuthenticated = false
    }

    private func executeNext(expectedDocumentID: UUID?, execute: @escaping @Sendable (SigningJob, SigningOperation) throws -> Void) async {
        guard isApproved, !isRunning, !needsOutcomeReview, let approval, let next = nextDocument,
              expectedDocumentID == nil || expectedDocumentID == next.id,
              let job = approval.jobs.first(where: { $0.snapshotIdentity.id == next.id }) else { return }
        isRunning = true; activeID = next.id
        let operation = SigningOperation(id: job.id) { [weak self] phase in
            Task { @MainActor in
                guard let self, self.activeID == next.id, let i = self.documents.firstIndex(where: { $0.id == next.id }) else { return }
                switch phase {
                case .preparing: self.documents[i].state = .preparing
                case .waitingForAuthentication: self.documents[i].state = .waitingForAuthorization
                case .signing: self.documents[i].state = .signing
                case .verifying: self.documents[i].state = .verifying
                default: break
                }
            }
        }
        activeOperation = operation
        let outcome = await Task.detached(priority: .userInitiated) {
            defer { job.snapshot.close() }
            return Result {
                var info = stat()
                try job.requireAvailableDestination()
                _ = try job.verifiedBytes()
                operation.transition(to: .preparing)
                try execute(job, operation)
                guard operation.state == .completed, lstat(job.destination.path, &info) == 0,
                      info.st_mode & S_IFMT == S_IFREG, info.st_size > 0 else {
                    throw SignumError.outputUncertain("Il motore non ha confermato una pubblicazione verificata. Controllare l'esito senza ripetere questa firma.")
                }
            }
        }.value
        activeID = nil; activeOperation = nil; isRunning = false
        guard let index = documents.firstIndex(where: { $0.id == next.id }) else { return }
        switch outcome {
        case .success:
            documents[index].state = .completed; documents[index].result = "Integrità verificata; copia pubblicata."
        case .failure(let error):
            if case SignumError.outputUncertain = error {
                operation.transition(to: .outcomeUncertain)
                documents[index].state = .uncertain; needsOutcomeReview = true
            } else if (error as? SupervisedProcess.Failure) == .cancelled {
                operation.transition(to: .cancelled); documents[index].state = .cancelled
            } else { operation.transition(to: .failed); documents[index].state = .failed }
            documents[index].result = error.localizedDescription
        }
        if let index = documents.firstIndex(where: { !$0.state.isTerminal }) { documents[index].state = .waitingForAuthorization }
    }
    private nonisolated static func failure(_ message: String) -> SignumError { .module(message) }
}
#endif
