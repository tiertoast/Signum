import Foundation
import CPKCS11

/// A provider refusal that provably happened before any `C_Sign` request.
/// No signature can exist for such an attempt, so it is an ordinary failure,
/// never an uncertain outcome. Carries no vendor diagnostics or credentials.
public enum SigningAuthenticationFailure: String, Error, LocalizedError, Codable, Sendable, CaseIterable {
    case pinIncorrect, pinIncorrectCountLow, pinIncorrectFinalTry
    case pinLocked, pinInvalid, pinExpired
    case notSigned

    /// The same approved document can be authorized again with a new PIN.
    public var allowsNewPIN: Bool {
        [.pinIncorrect, .pinIncorrectCountLow, .pinIncorrectFinalTry, .pinInvalid].contains(self)
    }

    public var errorDescription: String? {
        let none = " Nessuna firma è stata richiesta al dispositivo."
        switch self {
        case .pinIncorrect:
            return "PIN errato." + none + " Controlla il PIN e riprova: errori ripetuti bloccano la carta."
        case .pinIncorrectCountLow:
            return "PIN errato. Restano pochi tentativi prima del blocco della carta." + none
        case .pinIncorrectFinalTry:
            return "PIN errato. Attenzione: resta un solo tentativo prima del blocco della carta." + none
        case .pinLocked:
            return "PIN bloccato dal dispositivo." + none + " Sbloccalo con il PUK o con lo strumento del produttore."
        case .pinInvalid:
            return "Il dispositivo non accetta questo PIN (lunghezza o caratteri non validi)." + none
        case .pinExpired:
            return "Il PIN è scaduto e va cambiato con lo strumento del produttore." + none
        case .notSigned:
            return "Il dispositivo ha rifiutato l'operazione prima della firma." + none + " Controlla il dispositivo e prepara una nuova firma."
        }
    }

    /// One-line feedback shown next to the PIN field.
    public var shortDescription: String {
        switch self {
        case .pinIncorrect: return "PIN errato. Nessuna firma eseguita: riprova."
        case .pinIncorrectCountLow: return "PIN errato. Restano pochi tentativi prima del blocco."
        case .pinIncorrectFinalTry: return "PIN errato. Resta un solo tentativo prima del blocco."
        case .pinInvalid: return "Il dispositivo non accetta questo PIN (lunghezza o caratteri)."
        case .pinLocked: return "PIN bloccato. Usa il PUK o lo strumento del produttore."
        case .pinExpired: return "PIN scaduto. Cambialo con lo strumento del produttore."
        case .notSigned: return "Operazione rifiutata dal dispositivo prima della firma."
        }
    }
    /// The last attempts are serious enough to warrant stronger emphasis.
    public var isCritical: Bool { self == .pinIncorrectFinalTry || self == .pinIncorrectCountLow || self == .pinLocked }

    /// Wire value used between worker processes and the app.
    var wire: String { "auth." + rawValue }
    init?(wire: String?) {
        guard let wire, wire.hasPrefix("auth."), let value = Self(rawValue: String(wire.dropFirst(5))) else { return nil }
        self = value
    }

    /// Pure classification of the shim outcome (shared with the PAdES helper).
    /// `nil` means `C_Sign` may have been invoked: keep treating it as uncertain.
    static func classify(signCalled: Bool, loginRV: UInt, tokenFlags: UInt) -> Self? {
        guard let name = sg_sign_refusal_name(signCalled ? 1 : 0, loginRV, tokenFlags) else { return nil }
        return Self(rawValue: String(cString: name)) ?? .notSigned
    }
}

private let uncertainSigningMessage =
    "Richiesta privata interrotta o senza firma verificabile. Nessun documento pubblicato; non ripetere automaticamente il PIN."

extension Error {
    /// True when the private operation provably never reached `C_Sign`: a shim
    /// refusal before Sign, a pre-login refusal of the batch worker, a busy or
    /// changed device context, or a worker that never started.
    var provablyNotSigned: Bool {
        if self is SigningAuthenticationFailure || self is IsolatedPKCS11Client.Failure ||
            self is BatchSignatureConnection.Failure { return true }
        let process = self as? SupervisedProcess.Failure
        return process == .launch || process == .capacity
    }
    /// The one rule for every signing path: once the request reached the token
    /// (`submitted`) and no signature came back (`received`), any error that does
    /// not prove "no C_Sign" becomes an uncertain outcome, never a retry.
    func classifiedAfterSigningRequest(submitted: Bool, received: Bool) -> Error {
        if case SignumError.outputUncertain? = self as? SignumError { return self }
        guard submitted, !received, !provablyNotSigned else { return self }
        return SignumError.outputUncertain(uncertainSigningMessage)
    }
    /// True when the approved document may be authorized again with a new PIN.
    public var allowsNewPIN: Bool { (self as? SigningAuthenticationFailure)?.allowsNewPIN ?? false }
}
