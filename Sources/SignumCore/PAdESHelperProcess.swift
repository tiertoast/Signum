#if os(macOS)
import Foundation
import Darwin

/// Native helper still owns verification and commit. A post-commit interruption
/// is uncertain and never deletes/retries output. No child diagnostics are logged.
public enum PAdESHelperProcess {
    public enum Outcome: Equatable {
        case published, failed(String), cancelled(String), uncertain(String)
    }
    private struct Status: Decodable {
        let version: Int, jobID: UUID
        let outcome: String, reason: String
        let cleanupConfirmed, documentVerified, documentPublished: Bool?
        let primaryFailure: String?
    }
    public static func requirePublished(_ outcome: Outcome) throws {
        switch outcome {
        case .published: return
        case .failed(let message): throw SignumError.module(message)
        case .cancelled: throw SupervisedProcess.Failure.cancelled
        case .uncertain(let message): throw SignumError.outputUncertain(message)
        }
    }
    public static func run(executable: URL, arguments: [String], input: inout Data,
                           destination: URL, timeout: TimeInterval = 120,
                           expectedJobID: UUID? = nil, expectedProtocolVersion: Int = 4, maximumInput: Int = 512,
                           isCancelled: () -> Bool = { false }) -> Outcome {
        defer { input.resetBytes(in: 0..<input.count) }
        func exists() -> Bool { var info = stat(); return lstat(destination.path, &info) == 0 }
        guard !exists() else { return .failed("La destinazione esiste già.") }
        guard !isCancelled() else { return .cancelled("Firma annullata prima dell'avvio.") }
        guard (4...5).contains(expectedProtocolVersion), (512...8*1024*1024+69).contains(maximumInput), input.count <= maximumInput, timeout.isFinite, timeout > 0 else { return .failed("Richiesta al motore non valida.") }
        do {
            let response = try SupervisedProcess.run(executable: executable, arguments: arguments, input: &input,
                maximumInput: maximumInput, timeout: timeout, isCancelled: isCancelled)
            if let expectedJobID {
                guard response.count <= 1024, let status = try? JSONDecoder().decode(Status.self, from: response),
                      status.version == expectedProtocolVersion, status.jobID == expectedJobID else {
                    return .uncertain("Risposta del motore assente o non vincolata al job. Non ripetere automaticamente la firma.")
                }
                if status.cleanupConfirmed == false {
                    let document = status.documentPublished == true ? "Documento pubblicato: conservalo e verificane l’integrità. "
                        : status.documentVerified == true ? "Integrità del PDF verificata; documento non pubblicato. " : "Documento non pubblicato o non verificato. "
                    let primary = status.reason == "primaryAndCleanupUnconfirmed"
                        ? (status.primaryFailure == "verification" ? "Errore principale durante la verifica del PDF. " : "Errore principale durante la firma o la preparazione. ") : ""
                    return .uncertain(primary + document + "Chiusura del dispositivo non confermata. Verifica l’esito prima di continuare; non ripetere automaticamente il PIN.")
                }
                if status.outcome == "rejectedBeforeAuthentication", ["busy", "coordination", "preflight"].contains(status.reason), !exists() {
                    return .failed(status.reason == "busy"
                        ? "Dispositivo occupato da un'altra operazione Signum. Nessun PIN inviato al provider."
                        : "Firma rifiutata prima dell'autenticazione. Nessun PIN inviato al provider.")
                }
                guard status.outcome == "published", status.reason == "none", status.cleanupConfirmed == true,
                      status.documentVerified == true, status.documentPublished == true else {
                    return .uncertain("Chiusura o pubblicazione del motore non confermata. Conservare eventuali output e non ripetere automaticamente il PIN.")
                }
            }
            var info = stat()
            guard lstat(destination.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0 else {
                return .uncertain("Il motore è terminato, ma l'output pubblicato non è disponibile. Non ripetere automaticamente la firma.")
            }
            return .published
        } catch {
            if exists() { return .uncertain("Motore interrotto con destinazione presente. Conservare e verificare l'output prima di ripetere la firma.") }
            if let failure = error as? SupervisedProcess.Failure, [.launch, .capacity].contains(failure) {
                return .failed(error.localizedDescription)
            }
            return .uncertain("Processo interrotto senza un rifiuto pre-autenticazione confermato. Nessun output presente; non ripetere automaticamente il PIN.")
        }
    }
}
#endif
