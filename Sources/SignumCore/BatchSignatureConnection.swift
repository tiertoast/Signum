#if os(macOS)
import Foundation
import Security

/// Single-owner off-main connection. Contains only public manifest data, never PIN.
final class BatchSignatureConnection {
    let manifest: BatchWorkerStart
    private let executable: URL
    private var channel: SupervisedWorkerChannel?
    private(set) var next = 0
    private(set) var reusable = false
    private var retired = false
    init(manifest: BatchWorkerStart, executable: URL) {
        precondition(manifest.pin == nil)
        self.manifest = manifest; self.executable = executable
    }
    func sign(jobID: UUID, attributes: Data, pin: String?, timeout: TimeInterval = 120,
              isCancelled: () -> Bool = { false }) throws -> Data {
        guard !retired, next < manifest.jobs.count, manifest.jobs[next].id == jobID,
              manifest.jobs[next].attributes == attributes else { throw SupervisedProcess.Failure.protocolViolation }
        let reply: BatchWorkerReply
        do {
            if next == 0 {
                guard let pin else { throw SupervisedProcess.Failure.protocolViolation }
                var start = manifest; start.pin = pin
                defer { start.pin = nil }
                guard start.valid else { throw SupervisedProcess.Failure.protocolViolation }
                let child = try SupervisedWorkerChannel(executable: executable); channel = child
                reply = try child.exchange(start, timeout: timeout, isCancelled: isCancelled)
            } else {
                guard pin == nil, reusable, let channel else { throw SupervisedProcess.Failure.protocolViolation }
                reply = try channel.exchange(BatchWorkerCommand(version: 2, batchID: manifest.batchID, jobID: jobID, index: next, finish: false),
                                             timeout: timeout, isCancelled: isCancelled)
            }
            guard reply.version == 2, reply.batchID == manifest.batchID, reply.jobID == jobID,
                  reply.index == next, reply.succeeded, reply.reusable != reply.closed,
                  let signature = reply.signature, (128...1024).contains(signature.count),
                  let certificate = SecCertificateCreateWithData(nil, manifest.certificate.der as CFData),
                  let key = SecCertificateCopyKey(certificate),
                  SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256, attributes as CFData, signature as CFData, nil) else {
                throw SignumError.invalidSignature
            }
            reusable = reply.reusable; next += 1
            if reply.closed { try channel?.waitForExit(); channel = nil }
            return signature
        } catch { abort(); throw error }
    }
    func skip(isCancelled: () -> Bool) throws {
        guard reusable, let channel, next < manifest.jobs.count else { throw SupervisedProcess.Failure.protocolViolation }
        var command = BatchWorkerCommand(version: 2, batchID: manifest.batchID, jobID: manifest.jobs[next].id, index: next, finish: false)
        command.skip = true
        let reply = try channel.exchange(command, timeout: 5, isCancelled: isCancelled)
        guard reply.version == 2, reply.batchID == manifest.batchID, reply.jobID == manifest.jobs[next].id,
              reply.index == next, reply.signature == nil, reply.reusable, !reply.closed, reply.succeeded else { abort(); throw SupervisedProcess.Failure.protocolViolation }
        next += 1
    }
    func finish() throws {
        guard let channel else { return }
        defer { self.channel = nil; reusable = false; retired = true }
        do {
            let reply = try channel.exchange(BatchWorkerCommand(version: 2, batchID: manifest.batchID, jobID: nil, index: next, finish: true),
                                             timeout: 5, isCancelled: { false })
            guard reply.version == 2, reply.batchID == manifest.batchID, reply.jobID == nil, reply.index == next,
                  reply.signature == nil, reply.closed, !reply.reusable, reply.succeeded else { throw SupervisedProcess.Failure.protocolViolation }
            try channel.waitForExit()
        } catch { channel.abort(); throw error }
    }
    func abort() { channel?.abort(); channel = nil; reusable = false; retired = true }
    deinit { abort() }
}
#endif
