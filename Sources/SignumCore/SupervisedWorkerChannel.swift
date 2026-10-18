#if os(macOS)
import Foundation
import Darwin

/// Internal bounded duplex pipe. All methods run off-main, one owner, no vendor
/// diagnostics, no credential argv/env. Same shared process cap as one-shot jobs.
final class SupervisedWorkerChannel {
    private let process = Process(), input = Pipe(), output = Pipe()
    private var pending = Data(), retired = false
    private let started = ProcessInfo.processInfo.systemUptime
    init(executable: URL) throws {
        guard SupervisedProcess.acquire() else { throw SupervisedProcess.Failure.capacity }
        do {
            process.executableURL = executable; process.arguments = ["--batch-v1"]
            process.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(), "LC_ALL": "C",
                                   "TMPDIR": FileManager.default.temporaryDirectory.path]
            process.standardInput = input; process.standardOutput = output; process.standardError = FileHandle.nullDevice
            for fd in [input.fileHandleForWriting.fileDescriptor, output.fileHandleForReading.fileDescriptor] {
                guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
                      fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw SupervisedProcess.Failure.launch }
            }
            guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else { throw SupervisedProcess.Failure.launch }
            try process.run()
            try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close()
        } catch { SupervisedProcess.release(); retired = true; throw SupervisedProcess.Failure.launch }
    }
    deinit { abort() }
    func exchange<Request: Encodable>(_ value: Request, timeout: TimeInterval,
                                      isCancelled: () -> Bool) throws -> BatchWorkerReply {
        var bytes = try JSONEncoder().encode(value)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard bytes.count <= 131072, timeout.isFinite, timeout > 0, !retired else { throw SupervisedProcess.Failure.protocolViolation }
        var frame = Data((0..<4).reversed().map { UInt8((UInt32(bytes.count) >> ($0*8)) & 255) })
        frame.append(bytes); bytes.resetBytes(in: 0..<bytes.count)
        defer { frame.resetBytes(in: 0..<frame.count) }
        var sent = 0, chunk = [UInt8](repeating: 0, count: 8192)
        let deadline = min(ProcessInfo.processInfo.systemUptime + timeout, started + 600)
        do {
            while true {
                if isCancelled() { throw SupervisedProcess.Failure.cancelled }
                if ProcessInfo.processInfo.systemUptime >= deadline { throw SupervisedProcess.Failure.timeout }
                if sent < frame.count {
                    let count = frame.withUnsafeBytes { Darwin.write(input.fileHandleForWriting.fileDescriptor, $0.baseAddress!.advanced(by: sent), min(8192, frame.count-sent)) }
                    if count > 0 { sent += count }
                    else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw SupervisedProcess.Failure.protocolViolation }
                    if sent == frame.count { frame.resetBytes(in: 0..<frame.count) }
                }
                let count = Darwin.read(output.fileHandleForReading.fileDescriptor, &chunk, chunk.count)
                if count > 0 {
                    guard count <= 65540-pending.count else { throw SupervisedProcess.Failure.protocolViolation }
                    pending.append(contentsOf: chunk.prefix(count))
                } else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw SupervisedProcess.Failure.protocolViolation }
                if pending.count >= 4 {
                    let length = pending.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
                    guard length > 0, length <= 65536 else { throw SupervisedProcess.Failure.protocolViolation }
                    if pending.count >= length+4 {
                        guard pending.count == length+4, sent == frame.count,
                              let reply = try? JSONDecoder().decode(BatchWorkerReply.self, from: pending.dropFirst(4)) else { throw SupervisedProcess.Failure.protocolViolation }
                        pending.removeAll(keepingCapacity: false)
                        return reply
                    }
                }
                if !process.isRunning { throw SupervisedProcess.Failure.abnormalExit }
                Thread.sleep(forTimeInterval: 0.005)
            }
        } catch { abort(); throw error }
    }
    func waitForExit() throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.005) }
        guard !process.isRunning else { abort(); throw SupervisedProcess.Failure.terminationPending }
        // Foundation Process.waitUntilExit can block when launch and teardown
        // run on different pool threads. isRunning=false already means reaped.
        let success = process.terminationReason == .exit && process.terminationStatus == 0
        retire()
        guard success else { throw SupervisedProcess.Failure.abnormalExit }
    }
    private func retire() {
        guard !retired else { return }; retired = true
        try? input.fileHandleForWriting.close(); try? output.fileHandleForReading.close()
        try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close()
        SupervisedProcess.release()
    }
    func abort() {
        guard !retired else { return }
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
        let deadline = ProcessInfo.processInfo.systemUptime + 0.25
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.005) }
        if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
        let reapAt = ProcessInfo.processInfo.systemUptime + 2
        while process.isRunning && ProcessInfo.processInfo.systemUptime < reapAt { Thread.sleep(forTimeInterval: 0.005) }
        if process.isRunning {
            retired = true
            let child = process
            DispatchQueue.global(qos: .utility).async {
                while child.isRunning { Thread.sleep(forTimeInterval: 0.1) }
                SupervisedProcess.release()
            }
        } else { retire() }
    }
}
#endif
