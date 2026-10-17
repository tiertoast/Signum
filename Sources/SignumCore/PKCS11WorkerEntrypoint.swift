#if os(macOS)
import Foundation
import Darwin

/// Implementation entry point for our bundled one-shot worker executable only.
public enum PKCS11WorkerEntrypoint {
    public static func serve() -> Int32 {
        var coreLimit = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &coreLimit) == 0 else { return 2 }
        // Reserve a reply fd, then silence incidental/vendor stdout and stderr.
        let reply = dup(STDOUT_FILENO), sink = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard reply >= 0, sink >= 0, fcntl(reply, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(reply, F_SETNOSIGPIPE, 1) == 0 else { return 2 }
        defer { Darwin.close(reply); Darwin.close(sink) }
        guard dup2(sink, STDOUT_FILENO) >= 0, dup2(sink, STDERR_FILENO) >= 0 else { return 2 }
        var input = Data(), chunk = [UInt8](repeating: 0, count: 8192)
        defer { input.resetBytes(in: 0..<input.count) }
        while true {
            let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, count <= 131072 - input.count else { return 2 }
            if count == 0 { break }
            input.append(contentsOf: chunk.prefix(count))
        }
        Darwin.close(STDIN_FILENO)
        guard let request = try? JSONDecoder().decode(PKCS11WorkerRequest.self, from: input), request.valid else { return 2 }
        input.resetBytes(in: 0..<input.count)
        var response = PKCS11WorkerResponse(version: 1, id: request.id, action: request.action,
            provider: request.provider, tokens: [], unavailable: 0, certificates: [], signature: nil, succeeded: false)
        do { response = try perform(request) } catch { /* Never return vendor diagnostics or request bytes. */ }
        guard var output = try? JSONEncoder().encode(response), output.count <= 2 * 1024 * 1024 else { return 2 }
        defer { output.resetBytes(in: 0..<output.count) }
        var offset = 0
        while offset < output.count {
            let count = output.withUnsafeBytes { Darwin.write(reply, $0.baseAddress!.advanced(by: offset), output.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return 2 }; offset += count
        }
        return 0
    }
    private static func perform(_ request: PKCS11WorkerRequest) throws -> PKCS11WorkerResponse {
        let module = try PKCS11Module(path: request.provider)
        let result = Result { () -> PKCS11WorkerResponse in
            var tokens: [WorkerToken] = [], certificates: [WorkerCertificate] = [], unavailable = 0
            var signature: Data?
            switch request.action {
            case .scan:
                let scan = try module.scanTokens(); tokens = scan.tokens.map(WorkerToken.init); unavailable = scan.unavailableSlots
            case .certificates:
                var total = 0
                for certificate in try module.certificates(slot: request.slot!) {
                    let der = try module.certificateDER(slot: request.slot!, certificate: certificate)
                    total += der.count
                    guard total <= 1024 * 1024 else { throw SignumError.invalidCertificate }
                    certificates.append(WorkerCertificate(certificate, der: der))
                }
            case .rsaSHA256:
                let certificate = request.certificate!
                try CertificateEligibility.requireEligible(certificateDER: certificate.der)
                signature = try module.signRSASHA256(slot: request.slot!, certificate: certificate.value,
                    pin: request.pin!, message: request.attributes!, expectedCertificateDER: certificate.der)
            }
            return PKCS11WorkerResponse(version: 1, id: request.id, action: request.action, provider: module.modulePath,
                tokens: tokens, unavailable: unavailable, certificates: certificates, signature: signature, succeeded: true)
        }
        // A blocked Finalize is contained by the parent's same deadline. Do not
        // announce success before checked provider teardown completes.
        try module.closeInWorker()
        return try result.get()
    }
}
#endif
