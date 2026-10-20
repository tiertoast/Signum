#if os(macOS)
import SignumCore

/// Presentation only; successful signatures and uncertain outcomes stay distinct.
enum BatchWorkspaceSummary {
    static func status(_ state: BatchDocumentState) -> String {
        switch state {
        case .completed: return "Firmato"
        case .failed: return "Errore"
        case .uncertain: return "Da verificare"
        case .cancelled: return "Annullato"
        case .pending: return "In attesa"
        case .waitingForAuthorization: return "PIN richiesto"
        case .preparing: return "Preparazione"
        case .signing: return "Firma in corso"
        case .verifying: return "Verifica"
        }
    }
    static func symbol(_ state: BatchDocumentState) -> String {
        switch state {
        case .completed: return "checkmark.circle"
        case .failed, .uncertain: return "exclamationmark.triangle"
        case .cancelled: return "xmark.circle"
        default: return "circle"
        }
    }
    static func summary(_ states: [BatchDocumentState]) -> String {
        guard !states.isEmpty else { return "Nessun documento" }
        let completed = states.filter { $0 == .completed }.count
        if completed == states.count { return states.count == 1 ? "Documento firmato correttamente" : "\(completed) documenti firmati correttamente" }
        var parts = ["\(completed) \(completed == 1 ? "firmato" : "firmati")"]
        for (state, singular, plural) in [(BatchDocumentState.failed, "non riuscito", "non riusciti"), (.uncertain, "da verificare", "da verificare"), (.cancelled, "annullato", "annullati")] {
            let count = states.filter { $0 == state }.count
            if count > 0 { parts.append("\(count) \(count == 1 ? singular : plural)") }
        }
        let pending = states.filter { !$0.isTerminal }.count
        if pending > 0 { parts.append("\(pending) in attesa") }
        return parts.joined(separator: " · ")
    }
}
#endif
