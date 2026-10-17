#if os(macOS)
import Foundation
import Darwin

/// Transport for the verified-output-v2 helper. The native helper owns staging,
/// verification and atomic commit. Never retry a signing request automatically.
public enum PAdESHelperProcess {
    public enum Outcome: Equatable {
        case published
        case failed(String)
        case uncertain(String)
    }

    public static func run(executable: URL, arguments: [String], input: inout Data,
                           destination: URL, timeout: TimeInterval = 120) -> Outcome {
        defer { input.resetBytes(in: 0..<input.count) }
        func exists() -> Bool {
            var info = stat()
            return lstat(destination.path, &info) == 0
        }
        guard !exists() else { return .failed("La destinazione esiste già.") }
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let stdin = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = FileHandle.nullDevice
        process.standardError = stderr
        let reader = stderr.fileHandleForReading
        let writer = stdin.fileHandleForWriting
        defer {
            try? reader.close()
            try? writer.close()
        }
        let descriptor = reader.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            return .failed("Impossibile preparare i canali privati del motore PAdES.")
        }
        do { try process.run() }
        catch { return .failed("Impossibile avviare il motore PAdES: \(error.localizedDescription)") }
        // Bounded protocol message, well below PIPE_BUF. No secrets in argv/env.
        // Rejecting large messages also avoids blocking on a helper not reading.
        var sendFailed = input.count > 512
        if !sendFailed {
            do { try writer.write(contentsOf: input) }
            catch { sendFailed = true }
        }
        input.resetBytes(in: 0..<input.count)
        try? writer.close()

        var diagnostic = Data()
        func drain() {
            var chunk = [UInt8](repeating: 0, count: 4096)
            // Bound work per iteration so an endless producer cannot defeat the
            // deadline. Retain at most 1200 bytes while discarding excess output.
            for _ in 0..<64 {
                let count = Darwin.read(descriptor, &chunk, chunk.count)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { break }
                let retained = min(count, 1200 - diagnostic.count)
                if retained > 0 { diagnostic.append(contentsOf: chunk.prefix(retained)) }
            }
        }
        let start = ProcessInfo.processInfo.systemUptime
        var timedOut = false
        var sentKill = false
        var terminationTime: TimeInterval = 0
        while process.isRunning {
            drain()
            let now = ProcessInfo.processInfo.systemUptime
            if !timedOut && (now - start >= max(0.05, timeout) || sendFailed) {
                timedOut = true
                terminationTime = now
                process.terminate()
            } else if timedOut && !sentKill && now - terminationTime > 2 {
                _ = kill(process.processIdentifier, SIGKILL)
                sentKill = true
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        process.waitUntilExit()
        drain()
        if !timedOut && !sendFailed && process.terminationReason == .exit && process.terminationStatus == 0 {
            var info = stat()
            guard lstat(destination.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0 else {
                return .uncertain("Il motore è terminato, ma l'output pubblicato non è disponibile. Non ripetere automaticamente la firma.")
            }
            return .published
        }
        if exists() {
            // The child can die between atomic commit and exit. Never remove
            // this file: it may be committed output or another process's file.
            return .uncertain("Il motore si è interrotto e la destinazione è presente. Verificare l'esito prima di ripetere la firma.")
        }
        let detail = timedOut ? "Motore interrotto per timeout o errore del canale privato." :
            String(decoding: diagnostic, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return .failed(detail.isEmpty ? "Il motore ha interrotto la firma." : detail)
    }
}
#endif
