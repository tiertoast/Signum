#if os(macOS)
import Foundation
import Security

/// App-internal client for the bundled worker, not a public integration protocol.
/// Calls are synchronous off-main and bounded. No installed provider is loaded here.
public final class IsolatedPKCS11Client: Sendable {
    public enum Failure: Error, LocalizedError {
        case busy
        case authenticationRequired
        case contextChanged
        public var errorDescription: String? {
            switch self {
            case .busy: return "Dispositivo occupato da un'altra operazione Signum. Nessun PIN inviato al provider."
            case .contextChanged: return "Il contesto del dispositivo è cambiato. Nessuna autenticazione inviata. Cerca nuovamente e approva una nuova sessione."
            case .authenticationRequired: return "Il dispositivo richiede autenticazione per leggere i certificati. La ricerca non invia PIN."
            }
        }
    }
    public let executable: URL
    private let leaseWaitMilliseconds: UInt
    let auditSupportDirectory: URL?
    public static var bundledExecutable: URL {
        let bundle = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/SignumPKCS11Worker")
        if Bundle.main.bundleURL.pathExtension == "app" { return bundle }
        return URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
            .deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
    }
    public convenience init(executable: URL = IsolatedPKCS11Client.bundledExecutable, leaseWaitMilliseconds: UInt = 10000) {
        self.init(executable: executable, leaseWaitMilliseconds: leaseWaitMilliseconds, auditSupportDirectory: nil)
    }
    init(executable: URL, leaseWaitMilliseconds: UInt = 10000, auditSupportDirectory: URL?) {
        self.executable = executable
        self.leaseWaitMilliseconds = leaseWaitMilliseconds
        self.auditSupportDirectory = auditSupportDirectory
    }

    public struct Scan: Sendable {
        public let provider: String
        public let tokens: [SignumToken]
        public let unavailableSlots: Int
        public var version: String? = nil
    }
    public struct Certificate: Sendable {
        public let certificate: SignumCertificate
        public let der: Data
    }
    public func scan(provider: String, timeout: TimeInterval = 30,
                     expectedModule: MiddlewareFileIdentity? = nil, automatic: Bool = false,
                     isCancelled: () -> Bool = { false }) throws -> Scan {
        var request = PKCS11WorkerRequest(action: .scan, provider: provider, leaseWaitMilliseconds: leaseWaitMilliseconds)
        request.expectedModule = expectedModule; request.automaticModule = automatic
        let result = try exchange(request, timeout: timeout, isCancelled: isCancelled)
        guard result.tokens.count <= 256, result.unavailable >= 0, result.unavailable <= 256,
              result.certificates.isEmpty, result.signature == nil,
              result.tokens.allSatisfy({ $0.label.utf8.count <= 128 && $0.model.utf8.count <= 128 &&
                  $0.manufacturer.utf8.count <= 128 && $0.reader.utf8.count <= 256 && ($0.serial?.utf8.count ?? 0) <= 32 }),
              (result.libraryVersion?.utf8.count ?? 0) <= 32 else { throw SupervisedProcess.Failure.protocolViolation }
        return Scan(provider: result.provider, tokens: result.tokens.map(\.value), unavailableSlots: result.unavailable, version: result.libraryVersion)
    }
    public func certificates(provider: String, slot: UInt, timeout: TimeInterval = 30,
                             expectedModule: MiddlewareFileIdentity? = nil, automatic: Bool = false,
                             isCancelled: () -> Bool = { false }) throws -> [Certificate] {
        var request = PKCS11WorkerRequest(action: .certificates, provider: provider, slot: slot, leaseWaitMilliseconds: leaseWaitMilliseconds)
        request.expectedModule = expectedModule; request.automaticModule = automatic
        let result = try exchange(request, timeout: timeout, isCancelled: isCancelled)
        guard result.tokens.isEmpty, result.signature == nil, result.certificates.count <= 256,
              result.certificates.allSatisfy(\.valid), result.certificates.reduce(0, { $0 + $1.der.count }) <= 1024 * 1024,
              Set(result.certificates.map { $0.value.id }).count == result.certificates.count else { throw SupervisedProcess.Failure.protocolViolation }
        return result.certificates.map { Certificate(certificate: $0.value, der: $0.der) }
    }
    // Only internal callers supply the exact attributes/proof message and the
    // approved DER; even a lying worker cannot return an accepted foreign key.
    func sign(provider: String, slot: UInt, certificate: SignumCertificate, der: Data, attributes: Data,
              pin: String, id: UUID, timeout: TimeInterval = 120, providerContext: SigningProviderContext? = nil,
              audit: CAdESWorkerAudit? = nil, isCancelled: () -> Bool = { false }) throws -> Data {
        try CertificateEligibility.requireEligible(certificateDER: der)
        if let providerContext, !providerContext.matches(provider: provider, slot: slot, certificate: certificate, der: der) { throw Failure.contextChanged }
        var request = PKCS11WorkerRequest(version: providerContext == nil ? 1 : 2, id: id, action: .rsaSHA256, provider: provider, slot: slot,
            certificate: WorkerCertificate(certificate, der: der), attributes: attributes, pin: pin, leaseWaitMilliseconds: leaseWaitMilliseconds)
        request.providerContext = providerContext
        request.expectedModule = providerContext?.moduleIdentity; request.automaticModule = providerContext?.automatic
        request.auditDirectory = audit?.directory.path
        let result = try exchange(request, timeout: timeout, audit: audit, isCancelled: isCancelled)
        guard result.tokens.isEmpty, result.certificates.isEmpty, let signature = result.signature,
              (128...1024).contains(signature.count), let cert = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(cert),
              SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256, attributes as CFData, signature as CFData, nil) else {
            audit?.record(.signatureRejected)
            throw SignumError.invalidSignature
        }
        audit?.record(.signatureVerified)
        return signature
    }
    public func signProof(provider: String, slot: UInt, certificate: SignumCertificate, der: Data,
                          pin: String, isCancelled: () -> Bool = { false }) throws {
        _ = try sign(provider: provider, slot: slot, certificate: certificate, der: der,
            attributes: Data("Signum PKCS11 proof of concept v0.1\n".utf8), pin: pin, id: UUID(), isCancelled: isCancelled)
    }
    private func exchange(_ request: PKCS11WorkerRequest, timeout: TimeInterval, audit: CAdESWorkerAudit? = nil,
                          isCancelled: () -> Bool) throws -> PKCS11WorkerResponse {
        guard request.valid else {
            audit?.record(.ipcError)
            throw SupervisedProcess.Failure.protocolViolation
        }
        var input: Data
        do { input = try JSONEncoder().encode(request) }
        catch { audit?.record(.ipcError); throw error }
        let data = try SupervisedProcess.run(executable: executable, input: &input, timeout: timeout, audit: audit, isCancelled: isCancelled)
        func rejectResponse() -> SupervisedProcess.Failure {
            audit?.record(.responseRejected)
            return .protocolViolation
        }
        guard let response = try? JSONDecoder().decode(PKCS11WorkerResponse.self, from: data),
              response.version == request.version, response.id == request.id, response.action == request.action,
              response.provider.hasPrefix("/"), response.provider.utf8.count <= 4096,
              !response.provider.utf8.contains(0) else { throw rejectResponse() }
        if !response.succeeded { audit?.record(.providerRejected) }
        if !response.succeeded, response.failureKind == "busy" { throw Failure.busy }
        if !response.succeeded, response.failureKind == "authenticationRequired", request.action != .rsaSHA256 { throw Failure.authenticationRequired }
        if !response.succeeded, response.failureKind == "contextChanged", request.version == 2 { throw Failure.contextChanged }
        if let binding = request.providerContext, response.succeeded {
            guard response.provider == binding.provider, response.validatedContext == binding else { throw rejectResponse() }
        }
        guard response.succeeded, response.failureKind == nil else {
            if response.succeeded { audit?.record(.responseRejected) }
            throw SignumError.module("Operazione del provider non riuscita. Nessun tentativo automatico aggiuntivo.")
        }
        if let expected = request.expectedModule {
            guard response.validatedModule == expected, response.automaticValidated == request.automaticModule else { throw rejectResponse() }
            let inspected = try MiddlewareFileSecurity.inspect(request.provider, automatic: request.automaticModule == true)
            guard inspected.identity == expected, inspected.canonicalPath == response.provider else { throw MiddlewareFileSecurity.Failure.changed }
        }
        return response
    }
}
#endif
