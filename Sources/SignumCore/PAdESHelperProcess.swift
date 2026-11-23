#if os(macOS)
import Foundation
import Darwin

/// Native helper still owns verification and commit. A post-commit interruption
/// is uncertain and never deletes/retries output. No child diagnostics are logged.
public enum PAdESHelperProcess {
    private struct RemoteRefusal: Error { let refusal: SigningAuthenticationFailure }
    public enum Outcome: Equatable {
        case published, failed(String), cancelled(String), uncertain(String)
        case authenticationRefused(SigningAuthenticationFailure)
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
        case .authenticationRefused(let refusal): throw refusal
        }
    }
    public static func run(executable: URL, arguments: [String], input: inout Data,
                           destination: URL, timeout: TimeInterval = 120,
                           expectedJobID: UUID? = nil, expectedProtocolVersion: Int = 4, maximumInput: Int = 512,
                           isCancelled: () -> Bool = { false },
                           remoteSigner: ((Data) throws -> Data)? = nil) -> Outcome {
        defer { input.resetBytes(in: 0..<input.count) }
        func exists() -> Bool { var info = stat(); return lstat(destination.path, &info) == 0 }
        guard !exists() else { return .failed("La destinazione esiste già.") }
        guard !isCancelled() else { return .cancelled("Firma annullata prima dell'avvio.") }
        guard (4...5).contains(expectedProtocolVersion), (512...8*1024*1024+69+65540).contains(maximumInput), input.count <= maximumInput, timeout.isFinite, timeout > 0 else { return .failed("Richiesta al motore non valida.") }
        do {
            // Remote signer: hex DigestInfo in, hex signature (or "ERR auth.<kind>") out.
            let respond: ((Data) throws -> Data)? = remoteSigner.map { signer in { request in
                guard let digestInfo = Data(hexLowercase: request) else { throw SupervisedProcess.Failure.protocolViolation }
                do { return Data(try signer(digestInfo).map { String(format: "%02x", $0) }.joined().utf8) }
                catch let refusal as SigningAuthenticationFailure { throw RemoteRefusal(refusal: refusal) }
            } }
            let response = try SupervisedProcess.run(executable: executable, arguments: arguments, input: &input,
                maximumInput: maximumInput, timeout: timeout, isCancelled: isCancelled, respond: respond)
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
                // The helper proved (via the shared shim) that no C_Sign was issued.
                if status.outcome == "authenticationRefused", let refusal = SigningAuthenticationFailure(wire: status.reason), !exists() {
                    return .authenticationRefused(refusal)
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
        } catch let failure as SupervisedProcess.ResponderFailure {
            // The worker's own classification wins: the helper never saw a signature.
            if exists() { return .uncertain("Motore interrotto con destinazione presente. Conservare e verificare l'output prima di ripetere la firma.") }
            switch failure.underlying {
            case let refusal as RemoteRefusal: return .authenticationRefused(refusal.refusal)
            case SignumError.outputUncertain(let message): return .uncertain(message)
            case SupervisedProcess.Failure.cancelled: return .cancelled("Firma annullata.")
            default: return .failed(failure.underlying.localizedDescription)
            }
        } catch {
            if exists() { return .uncertain("Motore interrotto con destinazione presente. Conservare e verificare l'output prima di ripetere la firma.") }
            if let failure = error as? SupervisedProcess.Failure, [.launch, .capacity].contains(failure) {
                return .failed(error.localizedDescription)
            }
            return .uncertain("Processo interrotto senza un rifiuto pre-autenticazione confermato. Nessun output presente; non ripetere automaticamente il PIN.")
        }
    }
}
extension Data {
    /// Strict lowercase hex, as written by the helper.
    init?(hexLowercase text: Data) {
        guard text.count % 2 == 0, text.count <= 8192 else { return nil }
        var bytes = [UInt8](); bytes.reserveCapacity(text.count / 2)
        func nibble(_ c: UInt8) -> UInt8? { (48...57).contains(c) ? c - 48 : (97...102).contains(c) ? c - 87 : nil }
        var index = text.startIndex
        while index < text.endIndex {
            guard let hi = nibble(text[index]), let lo = nibble(text[text.index(after: index)]) else { return nil }
            bytes.append(hi << 4 | lo); index = text.index(index, offsetBy: 2)
        }
        self.init(bytes)
    }
}
#endif
