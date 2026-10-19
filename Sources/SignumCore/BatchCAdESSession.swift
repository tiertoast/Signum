#if os(macOS)
import Foundation
import Darwin

/// One approved CAdES batch, one isolated worker. No PIN property, no middleware
/// loaded into the caller. Cryptographic verification and publication stay here.
public final class BatchCAdESSession: @unchecked Sendable {
    public let approvalID: UUID
    private let jobs: [SigningJob], serial: String, identity: MiddlewareFileIdentity, automatic: Bool, executable: URL
    private let temporaryPIN: Bool
    private let ioLock = NSLock(), state = NSLock()
    private var connection: BatchSigningConnection?
    // Internal test seam for the session lifecycle, without launching a worker.
    var makeConnection: (BatchWorkerStart, URL) -> BatchSigningConnection = { BatchSignatureConnection(manifest: $0, executable: $1) }
    private var stopped = false, reusable = false, began = false, cleanupFailed = false
    public var cleanupUncertain: Bool { state.lock(); defer { state.unlock() }; return cleanupFailed }
    public var canContinue: Bool { state.lock(); defer { state.unlock() }; return reusable && !stopped }
    public init(approval: BatchApproval, serial: String, moduleIdentity: MiddlewareFileIdentity,
                automaticModule: Bool = false, temporaryPIN: Bool = false, startingAt snapshotID: UUID? = nil, remainingSnapshotIDs: Set<UUID>? = nil,
                executable: URL = IsolatedPKCS11Client.bundledExecutable) throws {
        guard approval.jobs.count > 1, approval.jobs.allSatisfy({ $0.format == .cades }),
              (1...16).contains(serial.utf8.count), !serial.utf8.contains(0), let first = approval.jobs.first,
              approval.jobs.allSatisfy({ $0.providerPath == first.providerPath && $0.slot == first.slot &&
                  $0.certificate.identifier == first.certificate.identifier && $0.certificateDER == first.certificateDER }) else {
            throw SignumError.module("La modalità automatica richiede un batch CAdES e un'identità dispositivo disponibile.")
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
        if let remaining = connection {
            DispatchQueue.global(qos: .utility).async { try? remaining.finish(); remaining.abort() }
        }
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
            return renameatx_np(stage, payload, parent, destination, UInt32(RENAME_EXCL))
        }
        do {
            guard !cancelled() else { throw SupervisedProcess.Failure.cancelled }
            let inspected = try MiddlewareFileSecurity.inspect(job.providerPath, automatic: automatic)
            guard inspected.identity == identity, inspected.canonicalPath == job.providerPath else { throw MiddlewareFileSecurity.Failure.changed }
            if !began {
                guard pin != nil, job.id == jobs[0].id else { throw SupervisedProcess.Failure.protocolViolation }
                let manifestJobs = try jobs.map { approved -> BatchWorkerJob in
                    let bytes = try approved.verifiedBytes()
                    let attributes = try CAdES.Prepared(document: bytes, certificateDER: approved.certificateDER).attributesToSign
                    return .init(id: approved.id, snapshotID: approved.snapshotIdentity.id, sha256: approved.contentSHA256, attributes: attributes)
                }
                var manifest = BatchWorkerStart(version: temporaryPIN ? 3 : 2, batchID: approvalID,
                    provider: job.providerPath, slot: job.slot, serial: serial,
                    certificate: WorkerCertificate(job.certificate, der: job.certificateDER), automatic: automatic,
                    moduleIdentity: identity, jobs: manifestJobs, pin: nil)
                if temporaryPIN { manifest.temporaryPIN = true }
                connection = makeConnection(manifest, executable)
                began = true
            }
            guard let connection, pin == nil || connection.next == 0 else { throw SupervisedProcess.Failure.protocolViolation }
            operation.transition(to: .preparing)
            try job.executeCAdES(io: io, isCancelled: cancelled) { bytes in
                let prepared = try CAdES.Prepared(document: bytes, certificateDER: job.certificateDER)
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
            if submitted && !receivedSignature {
                throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Non ripetere automaticamente questo job.")
            }
            if operation.isCancellationRequested { throw SupervisedProcess.Failure.cancelled }
            throw error
        }
    }
}
#endif
