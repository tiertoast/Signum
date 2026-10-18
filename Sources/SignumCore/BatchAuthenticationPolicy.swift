import Foundation

public enum BatchAuthenticationMode: String, CaseIterable, Sendable {
    case automatic, perSignature
    public var title: String {
        self == .automatic ? "Automatica, quando supportata" : "Richiedi PIN per ogni firma"
    }
}
public enum BatchAuthenticationPolicy {
    public static func canAttempt(jobs: [SigningJob], serial: String, mode: BatchAuthenticationMode) -> Bool {
        mode == .automatic && jobs.count > 1 && jobs.allSatisfy { $0.format == .cades } &&
            (1...16).contains(serial.utf8.count) && !serial.utf8.contains(0)
    }
    public static func explanation(formats: [SigningFormat], serial: String, mode: BatchAuthenticationMode) -> String {
        if mode == .perSignature { return "PIN richiesto esplicitamente per ogni firma." }
        if formats.contains(.pades) { return "PAdES e batch misti: PIN per ogni firma. La sessione condivisa è disponibile solo per CAdES." }
        if formats.count <= 1 { return "Per un solo documento è richiesta una sola autenticazione." }
        if !(1...16).contains(serial.utf8.count) || serial.utf8.contains(0) { return "Identità dispositivo insufficiente per una sessione condivisa: PIN per ogni firma." }
        return "Al primo PIN verrà verificato se la sessione può essere riutilizzata per questo batch. Il dispositivo potrebbe richiedere altri PIN."
    }
}
