import Foundation

public enum BatchAuthenticationMode: String, CaseIterable, Sendable {
    case automatic, temporaryPIN, perSignature
    public var title: String {
        switch self {
        case .automatic: return "Automatica, quando supportata"
        case .temporaryPIN: return "PIN temporaneo per il batch"
        case .perSignature: return "Richiedi PIN per ogni firma"
        }
    }
    public var explanation: String {
        if self == .temporaryPIN {
            return "Il PIN viene conservato temporaneamente in memoria per autorizzare i documenti di questa sessione. Modalità sperimentale, solo CAdES: aumenta il tempo di esposizione del PIN rispetto alla richiesta per ogni firma."
        }
        return self == .automatic ? "La modalità automatica verifica il supporto al primo PIN, solo per batch CAdES. Il PIN non viene conservato per le firme successive." : "Un nuovo inserimento del PIN è richiesto per ogni documento."
    }
}
public enum BatchAuthenticationPolicy {
    public static func canAttempt(jobs: [SigningJob], serial: String, mode: BatchAuthenticationMode) -> Bool {
        mode != .perSignature && jobs.count > 1 && jobs.allSatisfy { $0.format == .cades } &&
            (1...16).contains(serial.utf8.count) && !serial.utf8.contains(0)
    }
    public static func explanation(formats: [SigningFormat], serial: String, mode: BatchAuthenticationMode) -> String {
        if mode == .perSignature { return "PIN richiesto esplicitamente per ogni firma." }
        if formats.contains(.pades) { return "PAdES e batch misti: PIN per ogni firma. La sessione condivisa è disponibile solo per CAdES." }
        if formats.count <= 1 { return "Per un solo documento è richiesta una sola autenticazione." }
        if !(1...16).contains(serial.utf8.count) || serial.utf8.contains(0) { return "Identità dispositivo insufficiente per una sessione condivisa: PIN per ogni firma." }
        if mode == .temporaryPIN { return "Il PIN viene conservato temporaneamente in memoria per autorizzare i documenti di questa sessione. Il dispositivo può richiedere autenticazioni distinte; errori o perdita della sessione interrompono il batch." }
        return "Al primo PIN verrà verificato se la sessione può essere riutilizzata per questo batch. Il dispositivo potrebbe richiedere altri PIN."
    }
}
