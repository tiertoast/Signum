#if os(macOS)
import Foundation
import Darwin

public enum SigningOperationPhase: String, Sendable {
    case idle, preparing, waitingForAuthentication, signing, verifying
    case completed, failed, cancelled, outcomeUncertain
    public var message: String {
        switch self {
        case .idle: return "Pronto"
        case .preparing: return "Preparazione in corso…"
        case .waitingForAuthentication: return "Autenticazione del dispositivo…"
        case .signing: return "Richiesta di firma in corso…"
        case .verifying: return "Verifica dell'integrità…"
        case .completed: return "Operazione completata"
        case .failed: return "Operazione non riuscita"
        case .cancelled: return "Operazione annullata"
        case .outcomeUncertain: return "Esito da verificare prima di ripetere"
        }
    }
    public var isTerminal: Bool { [.completed, .failed, .cancelled, .outcomeUncertain].contains(self) }
}
/// Per-request state, separate from view state and immutable SigningJob inputs.
/// Callbacks run outside the lock. The tiny publication barrier never waits on
/// vendor/verification code; cancellation is refused once commit has begun.
public final class SigningOperation: @unchecked Sendable {
    public let id: UUID
    private let lock = NSLock()
    private var phase: SigningOperationPhase = .idle, cancelled = false, publishing = false
    private let changed: (SigningOperationPhase) -> Void
    public init(id: UUID = UUID(), changed: @escaping (SigningOperationPhase) -> Void = { _ in }) {
        self.id = id; self.changed = changed
    }
    public var state: SigningOperationPhase { lock.lock(); defer { lock.unlock() }; return phase }
    public var isCancellationRequested: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    @discardableResult public func requestCancellation() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !phase.isTerminal, !publishing else { return false }
        cancelled = true; return true
    }
    @discardableResult public func transition(to next: SigningOperationPhase) -> Bool {
        lock.lock()
        let allowed: Bool
        if phase.isTerminal { allowed = false }
        else if next == phase { lock.unlock(); return true }
        else if next.isTerminal { allowed = next != .completed || (!cancelled && phase != .idle) }
        else {
            switch (phase, next) {
            case (.idle, .preparing), (.preparing, .waitingForAuthentication), (.preparing, .signing),
                 (.preparing, .verifying), (.waitingForAuthentication, .signing), (.signing, .verifying): allowed = !cancelled
            default: allowed = false
            }
        }
        if allowed { phase = next }
        lock.unlock()
        if allowed { changed(next) }
        return allowed
    }
    /// A verified publication has already happened in the native helper.
    /// A late cancellation cannot undo it or turn it into a missing-output error.
    public func recordPublished() {
        lock.lock()
        guard !phase.isTerminal else { lock.unlock(); return }
        publishing = true; cancelled = false; phase = .completed
        lock.unlock(); changed(.completed)
    }
    func checkCancellation() throws {
        if isCancellationRequested { throw SupervisedProcess.Failure.cancelled }
    }
    func beginPublication() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard phase == .verifying, !cancelled, !publishing else { return false }
        publishing = true; return true
    }
}

extension SigningJob {
    /// Parent owns approved bytes, attributes, signature verification and commit.
    /// The worker never receives original/snapshot/output file paths.
    public func signCAdES(using worker: IsolatedPKCS11Client, pin: String,
                          operation: SigningOperation, timeout: TimeInterval = 120) throws {
        defer { snapshot.close() }
        guard operation.state == .idle || operation.state == .preparing else {
            throw SignumError.module("Operazione già avviata o conclusa.")
        }
        var submitted = false, receivedVerifiedSignature = false
        operation.transition(to: .preparing)
        var io = SignumFileOutput.OutputIO()
        io.beforePublish = { try operation.checkCancellation() }
        io.publish = { stage, payload, parent, destination in
            guard operation.beginPublication() else { errno = ECANCELED; return -1 }
            return renameatx_np(stage, payload, parent, destination, UInt32(RENAME_EXCL))
        }
        do {
            try operation.checkCancellation()
            try executeCAdES(io: io, isCancelled: { operation.isCancellationRequested }) { bytes in
                let prepared = try CAdES.Prepared(document: bytes, certificateDER: certificateDER)
                operation.transition(to: .waitingForAuthentication)
                try operation.checkCancellation()
                operation.transition(to: .signing)
                submitted = true
                let signature = try worker.sign(provider: providerPath, slot: slot, certificate: certificate,
                    der: certificateDER, attributes: prepared.attributesToSign, pin: pin, id: id,
                    timeout: timeout, isCancelled: { operation.isCancellationRequested })
                receivedVerifiedSignature = true
                operation.transition(to: .verifying)
                try operation.checkCancellation()
                return try prepared.finish(signature: signature)
            }
            operation.transition(to: .completed)
        } catch {
            if submitted && !receivedVerifiedSignature && !(error is IsolatedPKCS11Client.Failure) &&
                (error as? SupervisedProcess.Failure) != .launch && (error as? SupervisedProcess.Failure) != .capacity {
                operation.transition(to: .outcomeUncertain)
                throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Questo job non ha pubblicato un documento. Non ripetere automaticamente il PIN.")
            }
            if operation.isCancellationRequested {
                operation.transition(to: .cancelled)
                throw SupervisedProcess.Failure.cancelled
            }
            operation.transition(to: .failed)
            throw error
        }
    }
}
#endif
