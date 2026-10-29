#if os(macOS)
import Foundation
import CSecurePIN

/// Strict acquisition precedes any provider/session. The terminal's sole
/// submission delimiter is explicit LF (Ctrl-J), not part of the credential.
public enum TerminalPIN {
    public static func read() throws -> String {
        guard let storage = sg_secure_pin_create() else { throw SignumError.module("Memoria PIN protetta non disponibile; nessuna sessione aperta.") }
        defer { sg_secure_pin_destroy(storage) }
        guard sg_secure_pin_read_terminal(storage, 120) == 0,
              let bytes = sg_secure_pin_bytes(storage),
              let value = String(bytes: UnsafeBufferPointer(start: bytes, count: sg_secure_pin_length(storage)), encoding: .utf8) else {
            throw SignumError.module("PIN rifiutato: servono 1–64 byte UTF-8, senza NUL/CR/LF. Conferma con Ctrl-J (LF). Nessuna sessione o autenticazione tentata.")
        }
        return value
    }
}
#endif
