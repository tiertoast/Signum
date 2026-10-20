#if os(macOS)
import Foundation
import Darwin
import CPKCS11
import CProcessCoordination

/// Runs only behind the worker's parent-death/core-dump/vendor-output hardening.
enum BatchWorkerServer {
    private static func readFrame(until limit: Double = .infinity, idle: Double = 60) throws -> Data? {
        var result = Data(), expected = 4, payload = false
        let deadline = min(limit, sg_batch_monotonic_now() + idle)
        while result.count < expected {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let count = poll(&descriptor, 1, 100)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, sg_batch_monotonic_now() < deadline else { throw SupervisedProcess.Failure.timeout }
            if count == 0 { continue }
            var chunk = [UInt8](repeating: 0, count: min(8192, expected-result.count))
            let n = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
            defer { _ = chunk.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            if n == 0 && result.isEmpty { return nil }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw SupervisedProcess.Failure.protocolViolation }
            result.append(contentsOf: chunk.prefix(n))
            if result.count == 4 && !payload {
                let length = result.reduce(0) { ($0 << 8) | Int($1) }
                guard (1...131072).contains(length) else { throw SupervisedProcess.Failure.protocolViolation }
                expected = length; result.removeAll(); payload = true
            }
        }
        return result
    }
    private static func write(_ value: BatchWorkerReply, to fd: Int32) throws {
        let data = try JSONEncoder().encode(value)
        guard data.count <= 65536 else { throw SupervisedProcess.Failure.protocolViolation }
        var frame = Data((0..<4).reversed().map { UInt8((UInt32(data.count) >> ($0*8)) & 255) }); frame.append(data)
        var offset = 0
        while offset < frame.count {
            let n = frame.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), frame.count-offset) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw SupervisedProcess.Failure.protocolViolation }; offset += n
        }
    }
    private static func requireModule(_ start: BatchWorkerStart) throws {
        let inspected = try MiddlewareFileSecurity.inspect(start.provider, automatic: start.automatic)
        guard inspected.canonicalPath == start.provider, inspected.identity == start.moduleIdentity else { throw MiddlewareFileSecurity.Failure.changed }
    }
    static func serve(reply: Int32) -> Int32 {
        var module: PKCS11Module?
        var lease: OpaquePointer?
        var securePIN: WorkerBatchPINContext?
        defer {
            securePIN?.erase() // Erase before any potentially blocking vendor teardown.
            if let module { try? module.closeInWorker() }
            if let lease { sg_token_lease_release(lease) }
        }
        do {
            guard var frame = try readFrame() else { return 2 }
            var start: BatchWorkerStart
            do { defer { frame.resetBytes(in: 0..<frame.count) }; start = try JSONDecoder().decode(BatchWorkerStart.self, from: frame) }
            guard start.valid else { return 2 }
            if start.version == 3 {
                do { securePIN = try WorkerBatchPINContext(lifetime: start.lifetime) }
                catch WorkerBatchPINContext.Failure.memoryUnavailable {
                    try write(.init(version: 2, batchID: start.batchID, jobID: start.jobs[0].id, index: 0,
                        signature: nil, reusable: false, closed: true, succeeded: false, failureKind: "pinMemoryUnavailable"), to: reply)
                    return 0 // No provider loaded, no private operation attempted.
                }
            }
            let deadline = securePIN?.deadline ?? (sg_batch_monotonic_now() + 600)
            // Release the decoded PIN immediately after the first operation,
            // before reading any later job command. No PIN field in commands.
            guard let owned = sg_token_lease_acquire(start.provider, UInt64(start.slot), 0, 10000) else { return 2 }
            lease = owned
            try requireModule(start)
            let loaded = try PKCS11Module(path: start.provider); module = loaded
            let first: (Data, Bool)
            do {
                defer { start.pin = nil }
                if let securePIN {
                    first = try loaded.firstTemporaryBatchSignature(slot: start.slot, serial: start.serial,
                        certificate: start.certificate.value, der: start.certificate.der,
                        attributes: start.jobs[0].attributes, pin: securePIN)
                    if !loaded.batchRequiresPIN || start.jobs.count == 1 { securePIN.erase() }
                } else {
                    first = try loaded.firstBatchSignature(slot: start.slot, serial: start.serial,
                        certificate: start.certificate.value, der: start.certificate.der,
                        attributes: start.jobs[0].attributes, pin: start.pin!)
                }
            }
            if !first.1 {
                securePIN?.erase()
                module = nil; try loaded.closeInWorker()
                try write(.init(version: 2, batchID: start.batchID, jobID: start.jobs[0].id, index: 0,
                    signature: first.0, reusable: false, closed: true, succeeded: true), to: reply)
                return 0
            }
            try write(.init(version: 2, batchID: start.batchID, jobID: start.jobs[0].id, index: 0,
                signature: first.0, reusable: true, closed: false, succeeded: true), to: reply)
            var next = 1
            while let data = try readFrame(until: deadline, idle: start.idle) {
                guard sg_batch_monotonic_now() < deadline,
                      let command = try? JSONDecoder().decode(BatchWorkerCommand.self, from: data),
                      command.version == 2, command.batchID == start.batchID, command.index == next else { return 2 }
                if command.finish {
                    guard command.jobID == nil, !command.skip else { return 2 }
                    securePIN?.erase()
                    module = nil; try loaded.closeInWorker()
                    try write(.init(version: 2, batchID: start.batchID, jobID: nil, index: next,
                        signature: nil, reusable: false, closed: true, succeeded: true), to: reply)
                    return 0
                }
                guard next < start.jobs.count, command.jobID == start.jobs[next].id else { return 2 }
                if command.skip {
                    try write(.init(version: 2, batchID: start.batchID, jobID: command.jobID, index: next,
                        signature: nil, reusable: true, closed: false, succeeded: true), to: reply)
                    next += 1
                    if next == start.jobs.count { securePIN?.erase() }
                    continue
                }
                try requireModule(start)
                let signature: Data
                if let securePIN { signature = try loaded.nextTemporaryBatchSignature(attributes: start.jobs[next].attributes, pin: securePIN) }
                else { signature = try loaded.nextBatchSignature(attributes: start.jobs[next].attributes) }
                if next + 1 == start.jobs.count { securePIN?.erase() }
                try write(.init(version: 2, batchID: start.batchID, jobID: command.jobID, index: next,
                    signature: signature, reusable: true, closed: false, succeeded: true), to: reply)
                next += 1
            }
            // Parent closed stdin: terminate rather than retaining authentication.
            securePIN?.erase()
            module = nil; try loaded.closeInWorker()
            return 0
        } catch { return 2 } // No vendor/PIN diagnostics across the pipe.
    }
}
#endif
