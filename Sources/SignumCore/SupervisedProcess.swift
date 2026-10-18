#if os(macOS)
import Foundation
import Darwin
import CProcessCoordination

/// One-shot, off-main transport. No shell, credential argv/env, or child logs.
/// Both pipe directions are nonblocking; a noisy/nonreading child cannot extend
/// the monotonic deadline. Cancellation never retries a private operation.
public enum SupervisedProcess {
    public enum Failure: Error, LocalizedError, Equatable {
        case launch, timeout, cancelled, abnormalExit, protocolViolation, capacity, terminationPending, resourceLimit, memoryMonitoringUnavailable
        public var errorDescription: String? {
            switch self {
            case .launch: return "Impossibile avviare il processo di lavoro."
            case .timeout: return "Tempo massimo del processo di lavoro superato."
            case .cancelled: return "Operazione annullata."
            case .abnormalExit: return "Il processo di lavoro si è interrotto."
            case .protocolViolation: return "Risposta del processo di lavoro non valida."
            case .capacity: return "Troppi processi di lavoro ancora attivi."
            case .terminationPending: return "Terminazione del processo ancora in attesa del sistema."
            case .resourceLimit: return "Il processo ha superato il limite di memoria della verifica."
            case .memoryMonitoringUnavailable: return "Impossibile controllare la memoria del processo di verifica."
            }
        }
    }
    private static let lock = NSLock()
    private static var active = 0
    static func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active < 8 else { return false }; active += 1; return true
    }
    static func release() { lock.lock(); active -= 1; lock.unlock() }

    public static func run(executable: URL, arguments: [String] = [], input: inout Data,
                           maximumInput: Int = 131072, maximumOutput: Int = 2 * 1024 * 1024,
                           maximumResidentBytes: UInt64? = nil,
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
        var stopAt: TimeInterval?, killed = false, unavailableRSSCount = 0
        var nextRSSSample: TimeInterval = 0
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
            if failure == nil, let maximumResidentBytes, now >= nextRSSSample {
                nextRSSSample = now + 0.005
                var resident: UInt64 = 0
                let sample = sg_process_resident_bytes(process.processIdentifier, &resident)
                if sample == 0 {
                    unavailableRSSCount = 0
                    if resident > maximumResidentBytes {
                    failure = .resourceLimit; stopAt = now; killed = true
                    _ = kill(process.processIdentifier, SIGKILL)
                    }
                } else if sample < 0 {
                    unavailableRSSCount += 1
                    // Allow exit/reaping races; fail closed if a live child
                    // remains unobservable across successive samples.
                    if unavailableRSSCount >= 3 && process.isRunning { failure = .memoryMonitoringUnavailable }
                } else { unavailableRSSCount = 0 }
            }
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
            if failure == nil {
                // Wake on pipe capacity/data rather than throttling every
                // 16 KiB write by 5 ms (100 MiB otherwise exceeds 30 seconds).
                var descriptors = [pollfd(fd: reader.fileDescriptor, events: Int16(POLLIN), revents: 0)]
                if !writerClosed { descriptors.append(pollfd(fd: writer.fileDescriptor, events: Int16(POLLOUT), revents: 0)) }
                _ = descriptors.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 5) }
            } else { Thread.sleep(forTimeInterval: 0.005) }
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
