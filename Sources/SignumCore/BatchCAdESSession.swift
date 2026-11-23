#if os(macOS)
import Foundation
import Darwin
import COutputPermissions

/// One approved CAdES/PAdES batch, one isolated worker and one PIN. No PIN
/// property, no middleware loaded into the caller. CAdES is verified and
/// published here; PAdES runs the PDF helper as a remote signer (no middleware,
/// no PIN in the helper), which verifies and publishes the PDF itself.
public final class BatchCAdESSession: @unchecked Sendable {
    /// Runs the PDF helper for one job with the given remote signer (app-provided).
    public typealias PAdESRunner = (SigningJob, SigningOperation, @escaping (Data) throws -> Data) throws -> Void
    private let padesRunner: PAdESRunner?
    public let approvalID: UUID
    private let jobs: [SigningJob], serial: String, identity: MiddlewareFileIdentity, automatic: Bool, executable: URL
    private let temporaryPIN: Bool
    // connection/began/factory are accessed only under ioLock. stopped/reusable/
    // cleanupFailed use state. No caller holds state while waiting for ioLock.
    // The narrow connection owner survives session deinit, so off-main retirement
    // uses the SAME lock instead of sending an unprotected existential.
    private final class ConnectionOwner: @unchecked Sendable {
        let lock = NSLock()
        var value: BatchSigningConnection? // only while lock is held
        func retire() {
            lock.lock(); defer { lock.unlock() }
            try? value?.finish(); value?.abort(); value = nil
        }
    }
    private let owner = ConnectionOwner(), state = NSLock()
    private var ioLock: NSLock { owner.lock }
    private var connection: BatchSigningConnection? {
        get { owner.value }
        set { owner.value = newValue }
    }
    // Internal test seam for the session lifecycle, without launching a worker.
    private var connectionFactory: (BatchWorkerStart, URL) -> BatchSigningConnection = { BatchSignatureConnection(manifest: $0, executable: $1) }
    var makeConnection: (BatchWorkerStart, URL) -> BatchSigningConnection {
        get { ioLock.lock(); defer { ioLock.unlock() }; return connectionFactory }
        set { ioLock.lock(); defer { ioLock.unlock() }; precondition(!began); connectionFactory = newValue }
    }
    private var signingTimes: [UUID: Date] = [:]
    private var stopped = false, reusable = false, began = false, cleanupFailed = false
    public var cleanupUncertain: Bool { state.lock(); defer { state.unlock() }; return cleanupFailed }
    public var canContinue: Bool { state.lock(); defer { state.unlock() }; return reusable && !stopped }
    public init(approval: BatchApproval, serial: String, moduleIdentity: MiddlewareFileIdentity,
                automaticModule: Bool = false, temporaryPIN: Bool = false, startingAt snapshotID: UUID? = nil, remainingSnapshotIDs: Set<UUID>? = nil,
                executable: URL = IsolatedPKCS11Client.bundledExecutable, padesRunner: PAdESRunner? = nil) throws {
        guard approval.jobs.count > 1,
              approval.jobs.allSatisfy({ $0.format == .cades || ($0.format == .pades && padesRunner != nil && $0.providerContext != nil) }),
              (1...16).contains(serial.utf8.count), !serial.utf8.contains(0), let first = approval.jobs.first,
              approval.jobs.allSatisfy({ $0.providerPath == first.providerPath && $0.slot == first.slot &&
                  $0.certificate.identifier == first.certificate.identifier && $0.certificateDER == first.certificateDER }) else {
            throw SignumError.module("La modalità automatica richiede un batch CAdES/PAdES e un'identità dispositivo disponibile.")
        }
        let start: Int
        if let snapshotID {
            guard let index = approval.jobs.firstIndex(where: { $0.snapshotIdentity.id == snapshotID }) else { throw SignumError.module("Documento iniziale non approvato.") }
            start = index
        } else { start = 0 }
        jobs = approval.jobs.dropFirst(start).filter { remainingSnapshotIDs?.contains($0.snapshotIdentity.id) ?? true }; approvalID = approval.id
        guard !jobs.isEmpty else { throw SignumError.module("Nessun documento in attesa.") }
        self.temporaryPIN = temporaryPIN
        self.serial = serial; identity = moduleIdentity; automatic = automaticModule; self.executable = executable
        self.padesRunner = padesRunner
    }
    /// One entry point for the coordinator: CAdES or PAdES by job format.
    public func sign(job: SigningJob, pin: String?, operation: SigningOperation) throws {
        if job.format == .pades {
            guard let padesRunner else { throw SignumError.module("Motore PAdES non disponibile per la sessione.") }
            try signPAdES(job: job, pin: pin, operation: operation, run: padesRunner)
        } else { try signCAdES(job: job, pin: pin, operation: operation) }
    }
    /// Starts the worker on the first signature. A PAdES first job supplies its
    /// DigestInfo now; later PAdES jobs send theirs with each command.
    private func beginIfNeeded(job: SigningJob, pin: String?, firstDigest: Data?) throws {
        guard !began else { return }
        guard pin != nil, job.id == jobs[0].id, (jobs[0].format == .pades) == (firstDigest != nil) else {
            throw SupervisedProcess.Failure.protocolViolation
        }
        let manifestJobs = try jobs.enumerated().map { index, approved -> BatchWorkerJob in
            if approved.format == .pades {
                return .init(id: approved.id, snapshotID: approved.snapshotIdentity.id, sha256: approved.contentSHA256,
                             attributes: index == 0 ? firstDigest! : Data(), lateDigest: true)
            }
            let bytes = try approved.verifiedBytes()
            let when = Date(); signingTimes[approved.id] = when
            let attributes = try CAdES.Prepared(document: bytes, certificateDER: approved.certificateDER, declaredSigningTime: approved.includeSigningTime ? when : nil).attributesToSign
            return .init(id: approved.id, snapshotID: approved.snapshotIdentity.id, sha256: approved.contentSHA256, attributes: attributes)
        }
        var manifest = BatchWorkerStart(version: temporaryPIN ? 3 : 2, batchID: approvalID,
            provider: job.providerPath, slot: job.slot, serial: serial,
            certificate: WorkerCertificate(job.certificate, der: job.certificateDER), automatic: automatic,
            moduleIdentity: identity, jobs: manifestJobs, pin: nil)
        if temporaryPIN { manifest.temporaryPIN = true }
        connection = connectionFactory(manifest, executable)
        began = true
    }
    private func update(reusable: Bool) { state.lock(); self.reusable = reusable; state.unlock() }
    private var isStopped: Bool { state.lock(); defer { state.unlock() }; return stopped }
    /// UI-safe: marks revocation immediately; all waiting/teardown is off-main.
    public func requestStop() {
        state.lock(); let first = !stopped; stopped = true; reusable = false; state.unlock()
        guard first else { return }
        DispatchQueue.global(qos: .utility).async { [self] in retire() }
    }
    private func retire() {
        ioLock.lock(); defer { ioLock.unlock() }
        retireConnection()
    }
    // ioLock is held by every caller. Uncertainty is monotonic and independent
    // of the primary document error and the lifetime of the connection.
    private func finishConnection() throws {
        do { try connection?.finish() }
        catch { state.lock(); cleanupFailed = true; state.unlock(); throw error }
    }
    private func retireConnection() {
        try? finishConnection()
        connection?.abort(); connection = nil
    }
    func stopAndWait() async {
        requestStop()
        await Task.detached(priority: .utility) { self.retire() }.value
    }
    deinit {
        let retiring = owner
        DispatchQueue.global(qos: .utility).async { retiring.retire() }
    }
    public func signCAdES(job: SigningJob, pin: String?, operation: SigningOperation, timeout: TimeInterval = 120) throws {
        guard ioLock.try() else { throw IsolatedPKCS11Client.Failure.busy }
        defer { ioLock.unlock() }
        guard !isStopped, jobs.contains(where: { $0.id == job.id && $0.snapshotIdentity == job.snapshotIdentity && $0.destination == job.destination }) else {
            throw SignumError.module("Job non autorizzato in questa sessione.")
        }
        var submitted = false, receivedSignature = false
        let cancelled = { self.isStopped || operation.isCancellationRequested }
        var io = SignumFileOutput.OutputIO()
        io.beforePublish = { if cancelled() { throw SupervisedProcess.Failure.cancelled } }
        io.publish = { stage, payload, parent, destination in
            if cancelled() { operation.requestCancellation() }
            guard operation.beginPublication() else { errno = ECANCELED; return -1 }
            return sg_output_publish_exclusive(stage, payload, parent, destination)
        }
        do {
            guard !cancelled() else { throw SupervisedProcess.Failure.cancelled }
            let inspected = try MiddlewareFileSecurity.inspect(job.providerPath, automatic: automatic)
            guard inspected.identity == identity, inspected.canonicalPath == job.providerPath else { throw MiddlewareFileSecurity.Failure.changed }
            guard job.format == .cades else { throw SupervisedProcess.Failure.protocolViolation }
            try beginIfNeeded(job: job, pin: pin, firstDigest: nil)
            guard let connection, pin == nil || connection.next == 0 else { throw SupervisedProcess.Failure.protocolViolation }
            operation.transition(to: .preparing)
            try job.executeCAdES(io: io, isCancelled: cancelled) { bytes in
                guard let when = signingTimes[job.id] else { throw SupervisedProcess.Failure.protocolViolation }
                let prepared = try CAdES.Prepared(document: bytes, certificateDER: job.certificateDER, declaredSigningTime: job.includeSigningTime ? when : nil)
                while connection.next < jobs.count && jobs[connection.next].id != job.id {
                    try connection.skip(isCancelled: cancelled) // Cancelled approved jobs are never signed.
                }
                operation.transition(to: .waitingForAuthentication)
                guard !cancelled() else { throw SupervisedProcess.Failure.cancelled }
                operation.transition(to: .signing); submitted = true
                let signature = try connection.sign(jobID: job.id, attributes: prepared.attributesToSign, pin: pin,
                    timeout: timeout, isCancelled: cancelled)
                receivedSignature = true
                if connection.next == jobs.count {
                    do { try finishConnection() }
                    catch { throw SignumError.outputUncertain("Chiusura della sessione non confermata. Nessuna ripetizione automatica.") }
                }
                operation.transition(to: .verifying)
                return try prepared.finish(signature: signature)
            }
            operation.transition(to: .completed)
            update(reusable: connection.reusable)
        } catch {
            update(reusable: false)
            // No teardown races with an active vendor call: transport errors
            // already terminated the worker, otherwise it is idle here.
            retireConnection()
            state.lock(); stopped = true; state.unlock()
            if error is BatchSignatureConnection.Failure { throw error } // Explicit pre-login refusal, not an uncertain Sign.
            if error.provablyNotSigned { throw error } // Worker proved that no C_Sign was issued.
            if submitted && !receivedSignature {
                throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Non ripetere automaticamente questo job.")
            }
            if operation.isCancellationRequested { throw SupervisedProcess.Failure.cancelled }
            throw error
        }
    }

    public func signPAdES(job: SigningJob, pin: String?, operation: SigningOperation, timeout: TimeInterval = 120,
                          run: PAdESRunner) throws {
        guard ioLock.try() else { throw IsolatedPKCS11Client.Failure.busy }
        defer { ioLock.unlock() }
        guard !isStopped, job.format == .pades,
              jobs.contains(where: { $0.id == job.id && $0.snapshotIdentity == job.snapshotIdentity && $0.destination == job.destination }) else {
            throw SignumError.module("Job non autorizzato in questa sessione.")
        }
        var submitted = false, receivedSignature = false
        var signerError: Error? // The original error, not the helper's relay of it.
        let cancelled = { self.isStopped || operation.isCancellationRequested }
        do {
            guard !cancelled() else { throw SupervisedProcess.Failure.cancelled }
            let inspected = try MiddlewareFileSecurity.inspect(job.providerPath, automatic: automatic)
            guard inspected.identity == identity, inspected.canonicalPath == job.providerPath else { throw MiddlewareFileSecurity.Failure.changed }
            if began { guard pin == nil else { throw SupervisedProcess.Failure.protocolViolation } }
            // The helper calls back exactly once, from inside this call, with the
            // DigestInfo of the prepared PDF; the worker signs it in its session.
            try run(job, operation) { digestInfo in
              do {
                guard !receivedSignature, BatchWorkerJob.isSHA256DigestInfo(digestInfo) else { throw SupervisedProcess.Failure.protocolViolation }
                try self.beginIfNeeded(job: job, pin: pin, firstDigest: digestInfo)
                guard let connection = self.connection, pin == nil || connection.next == 0 else { throw SupervisedProcess.Failure.protocolViolation }
                while connection.next < self.jobs.count && self.jobs[connection.next].id != job.id {
                    try connection.skip(isCancelled: cancelled) // Cancelled approved jobs are never signed.
                }
                guard !cancelled() else { throw SupervisedProcess.Failure.cancelled }
                submitted = true
                let signature: Data
                do { signature = try connection.sign(jobID: job.id, attributes: digestInfo, pin: pin, timeout: timeout, isCancelled: cancelled) }
                catch {
                    // Classified here: the helper only relays it. Before C_Sign stays typed.
                    if error is BatchSignatureConnection.Failure || error.provablyNotSigned { throw error }
                    throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Non ripetere automaticamente questo job.")
                }
                receivedSignature = true
                if connection.next == self.jobs.count {
                    do { try self.finishConnection() }
                    catch { throw SignumError.outputUncertain("Chiusura della sessione non confermata. Nessuna ripetizione automatica.") }
                }
                return signature
              } catch { signerError = error; throw error }
            }
            update(reusable: connection?.reusable ?? false)
        } catch {
            update(reusable: false)
            retireConnection()
            state.lock(); stopped = true; state.unlock()
            let error = signerError ?? error
            if error is BatchSignatureConnection.Failure { throw error }
            if error.provablyNotSigned { throw error }
            if submitted && !receivedSignature {
                throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Non ripetere automaticamente questo job.")
            }
            throw error
        }
    }
}
#endif
