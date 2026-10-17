#if os(macOS)
import Foundation
import Darwin

/// One-shot, off-main transport. No shell, credential argv/env, or child logs.
/// Both pipe directions are nonblocking; a noisy/nonreading child cannot extend
/// the monotonic deadline. Cancellation never retries a private operation.
public enum SupervisedProcess {
    public enum Failure: Error, LocalizedError, Equatable {
        case launch, timeout, cancelled, abnormalExit, protocolViolation, capacity, terminationPending
        public var errorDescription: String? {
            switch self {
            case .launch: return "Impossibile avviare il processo di lavoro."
            case .timeout: return "Tempo massimo del processo di lavoro superato."
            case .cancelled: return "Operazione annullata."
            case .abnormalExit: return "Il processo di lavoro si è interrotto."
            case .protocolViolation: return "Risposta del processo di lavoro non valida."
            case .capacity: return "Troppi processi di lavoro ancora attivi."
            case .terminationPending: return "Terminazione del processo ancora in attesa del sistema."
            }
        }
    }
    private static let lock = NSLock()
    private static var active = 0
    private static func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active < 8 else { return false }; active += 1; return true
    }
    private static func release() { lock.lock(); active -= 1; lock.unlock() }

    public static func run(executable: URL, arguments: [String] = [], input: inout Data,
                           maximumInput: Int = 131072, maximumOutput: Int = 2 * 1024 * 1024,
                           timeout: TimeInterval = 30,
                           isCancelled: () -> Bool = { false }) throws -> Data {
        defer { input.resetBytes(in: 0..<input.count) }
        guard maximumInput > 0, maximumOutput > 0, input.count <= maximumInput,
              timeout.isFinite, timeout > 0 else { throw Failure.protocolViolation }
        guard !isCancelled() else { throw Failure.cancelled }
        guard acquire() else { throw Failure.capacity }
        var retainedForReaping = false
        defer { if !retainedForReaping { release() } }
        let process = Process(), incoming = Pipe(), outgoing = Pipe()
        process.executableURL = executable; process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": NSHomeDirectory(),
                               "TMPDIR": FileManager.default.temporaryDirectory.path, "LC_ALL": "C"]
        process.standardInput = incoming; process.standardOutput = outgoing
        process.standardError = FileHandle.nullDevice
        let writer = incoming.fileHandleForWriting, reader = outgoing.fileHandleForReading
        defer {
            try? writer.close(); try? reader.close()
            try? incoming.fileHandleForReading.close(); try? outgoing.fileHandleForWriting.close()
        }
        for fd in [writer.fileDescriptor, reader.fileDescriptor] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw Failure.launch }
        }
        guard fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else { throw Failure.launch }
        do { try process.run() } catch { throw Failure.launch }
        // Close the parent's copies of the child's ends (including on early exit).
        try? incoming.fileHandleForReading.close(); try? outgoing.fileHandleForWriting.close()
        var result = Data(), sent = 0, writerClosed = false, failure: Failure?
        var stopAt: TimeInterval?, killed = false
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var chunk = [UInt8](repeating: 0, count: 16384)
        func drain() {
            for _ in 0..<32 {
                let count = Darwin.read(reader.fileDescriptor, &chunk, chunk.count)
                if count < 0 && errno == EINTR { continue }
                if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK { failure = failure ?? .protocolViolation }
                guard count > 0 else { break }
                if count > maximumOutput - result.count { failure = failure ?? .protocolViolation; break }
                result.append(contentsOf: chunk.prefix(count))
            }
        }
        while process.isRunning {
            let now = ProcessInfo.processInfo.systemUptime
            if failure == nil {
                if isCancelled() { failure = .cancelled }
                else if now >= deadline { failure = .timeout }
            }
            drain()
            if failure == nil && !writerClosed {
                if sent < input.count {
                    let count = input.withUnsafeBytes { bytes in
                        Darwin.write(writer.fileDescriptor, bytes.baseAddress!.advanced(by: sent), min(16384, input.count - sent))
                    }
                    if count > 0 { sent += count }
                    else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { failure = .protocolViolation }
                }
                if sent == input.count { try? writer.close(); writerClosed = true; input.resetBytes(in: 0..<input.count) }
            }
            if failure != nil {
                if stopAt == nil { stopAt = now; process.terminate() }
                else if !killed && now - stopAt! >= 0.25 { _ = kill(process.processIdentifier, SIGKILL); killed = true }
                else if killed && now - stopAt! >= 2 {
                    // Do not hang the caller on an OS-level uninterruptible child.
                    // Keep its slot until it actually dies; resource usage is capped.
                    retainedForReaping = true
                    DispatchQueue.global(qos: .utility).async { process.waitUntilExit(); release() }
                    throw Failure.terminationPending
                }
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
        process.waitUntilExit(); drain()
        if let failure { throw failure }
        guard !isCancelled() else { throw Failure.cancelled }
        guard process.terminationReason == .exit, process.terminationStatus == 0,
              sent == input.count else { throw Failure.abnormalExit }
        return result
    }
}
#endif
