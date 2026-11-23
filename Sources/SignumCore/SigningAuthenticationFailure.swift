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

extension Error {
    /// True when the private operation provably never reached `C_Sign`.
    var provablyNotSigned: Bool { self is SigningAuthenticationFailure }
    /// True when the approved document may be authorized again with a new PIN.
    public var allowsNewPIN: Bool { (self as? SigningAuthenticationFailure)?.allowsNewPIN ?? false }
}
