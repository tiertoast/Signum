#if os(macOS)
import Foundation
import CryptoKit
import SignumCore

/// Launches the separately built PoDoFo proof-of-concept with a private stdin pipe.
/// No PIN is passed via argv or process environment. This is not production IPC:
/// secrets may remain in Swift and middleware memory.
enum SignumPAdESHelper {
    static var executableURL: URL {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/signum-pades-local")
    }

    static var available: Bool {
        FileManager.default.isExecutableFile(atPath: executableURL.path)
    }

    struct Field: Equatable {
        let pageIndex: Int
        let x: Double
        let y: Double
        let width: Double
        let height: Double
    }

    static func sign(input: URL,
                     output: URL,
                     modulePath: String,
                     slot: UInt,
                     certificateID: String,
                     expectedCertificate: Data,
                     pin: String,
                     appearanceName: String,
                     field: Field?) throws {
        guard available else {
            throw SignumError.module("Motore PAdES non installato nel bundle. Compila PoDoFo in locale.")
        }
        guard input.isFileURL, output.isFileURL,
              input.pathExtension.lowercased() == "pdf",
              output.pathExtension.lowercased() == "pdf",
              input.standardizedFileURL != output.standardizedFileURL else {
            throw SignumError.module("Input e output devono essere PDF differenti.")
        }
        guard !FileManager.default.fileExists(atPath: output.path) else {
            throw SignumError.module("File PDF di destinazione già esistente.")
        }
        guard !pin.isEmpty, pin.utf8.count <= 64 else {
            throw SignumError.module("PIN mancante o troppo lungo.")
        }

        var args = [
            input.path,
            output.path,
            modulePath,
            String(slot),
            certificateID
        ]
        if let field {
            let values = [field.x, field.y, field.width, field.height]
            guard field.pageIndex >= 0,
                  values.allSatisfy({ $0.isFinite }),
                  field.width > 0, field.height > 0 else {
                throw SignumError.module("Coordinate firma grafica non valide.")
            }
            args += [
                String(field.pageIndex),
                String(field.x),
                String(field.y),
                String(field.width),
                String(field.height)
            ]
        }
        args.append("--pin-stdin")
        if field != nil { args.append("--appearance-stdin") }

        // Supply exactly one line to the helper. This avoids getpass() in GUI
        // contexts and avoids leaking credentials through command arguments.
        var secret = Data(pin.utf8)
        secret.append(0x0A)
        if field != nil {
            // Helvetica (PDF Standard 14) is used by this first text-only AP.
            // Limit to printable ASCII and avoid injecting protocol delimiters.
            let normalizedName = appearanceName.folding(
                options: .diacriticInsensitive,
                locale: Locale(identifier: "en_US_POSIX")
            )
            let cleanedName = Array(normalizedName.utf8.filter {
                $0 >= 0x20 && $0 <= 0x7E
            }.prefix(90))
            let printableName = cleanedName.isEmpty
                ? Data("Firmatario".utf8)
                : Data(cleanedName)
            secret.append(printableName)
            secret.append(0x0A)
        }
        defer { secret.resetBytes(in: 0..<secret.count) }
        let fingerprint = SHA256.hash(data: expectedCertificate).map { String(format: "%02x", $0) }.joined()
        args += ["--expected-cert-sha256", fingerprint, "--verified-output-v1"]
        switch PAdESHelperProcess.run(executable: executableURL, arguments: args,
                                      input: &secret, destination: output) {
        case .published: return
        case .failed(let diagnostic): throw SignumError.module("PAdES non riuscita: \(diagnostic)")
        case .uncertain(let diagnostic): throw SignumError.outputUncertain(diagnostic)
        }
    }
}
#endif
