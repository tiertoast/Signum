#if os(macOS)
import Foundation
import Darwin

/// Native helper still owns verification and commit. A post-commit interruption
/// is uncertain and never deletes/retries output. No child diagnostics are logged.
public enum PAdESHelperProcess {
    public enum Outcome: Equatable {
        case published, failed(String), cancelled(String), uncertain(String)
    }
    public static func run(executable: URL, arguments: [String], input: inout Data,
                           destination: URL, timeout: TimeInterval = 120,
                           isCancelled: () -> Bool = { false }) -> Outcome {
        defer { input.resetBytes(in: 0..<input.count) }
        func exists() -> Bool { var info = stat(); return lstat(destination.path, &info) == 0 }
        guard !exists() else { return .failed("La destinazione esiste già.") }
        guard !isCancelled() else { return .cancelled("Firma annullata prima dell'avvio.") }
        do {
            _ = try SupervisedProcess.run(executable: executable, arguments: arguments, input: &input,
                maximumInput: 512, timeout: timeout, isCancelled: isCancelled)
            var info = stat()
            guard lstat(destination.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0 else {
                return .uncertain("Il motore è terminato, ma l'output pubblicato non è disponibile. Non ripetere automaticamente la firma.")
            }
            return .published
        } catch {
            if exists() { return .uncertain("Motore interrotto con destinazione presente. Conservare e verificare l'output prima di ripetere la firma.") }
            if (error as? SupervisedProcess.Failure) == .cancelled {
                return .cancelled("Processo interrotto su richiesta. Nessun output presente; l'operazione sul dispositivo potrebbe essere avvenuta. Non ripetere automaticamente il PIN.")
            }
            return .failed(error.localizedDescription)
        }
    }
}
#endif
