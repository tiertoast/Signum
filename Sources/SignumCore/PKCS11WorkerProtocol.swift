#if os(macOS)
import Foundation

// Internal, bounded, versioned one-shot IPC; not an integration API.
struct PKCS11WorkerRequest: Codable {
    enum Action: String, Codable { case scan, certificates, rsaSHA256 }
    let version: Int
    let id: UUID
    let action: Action
    let provider: String
    let leaseWaitMilliseconds: UInt
    let slot: UInt?
    let certificate: WorkerCertificate?
    let attributes: Data?
    var pin: String?
    var expectedModule: MiddlewareFileIdentity? = nil
    var automaticModule: Bool? = nil
    var providerContext: SigningProviderContext? = nil
    init(version: Int = 1, id: UUID = UUID(), action: Action, provider: String, slot: UInt? = nil,
         certificate: WorkerCertificate? = nil, attributes: Data? = nil, pin: String? = nil, leaseWaitMilliseconds: UInt = 10000) {
        self.version = version; self.id = id; self.action = action; self.provider = provider
        self.leaseWaitMilliseconds = leaseWaitMilliseconds
        self.slot = slot; self.certificate = certificate; self.attributes = attributes; self.pin = pin
    }
    var valid: Bool {
        guard (version == 1 || version == 2), leaseWaitMilliseconds <= 30000, provider.hasPrefix("/"), provider.utf8.count <= 4096, !provider.utf8.contains(0) else { return false }
        if version == 1 && providerContext != nil { return false } // Explicit legacy locator/DER contract.
        if version == 2 {
            guard action == .rsaSHA256, let context = providerContext, let slot, let certificate,
                  context.matches(provider: provider, slot: slot, certificate: certificate.value, der: certificate.der),
                  expectedModule == context.moduleIdentity, automaticModule == context.automatic else { return false }
        }
        if automaticModule == true && expectedModule == nil { return false }
        switch action {
        case .scan: return slot == nil && certificate == nil && attributes == nil && pin == nil
        case .certificates: return slot != nil && certificate == nil && attributes == nil && pin == nil
        case .rsaSHA256:
            guard slot != nil, let certificate, certificate.valid, let attributes, (1...4096).contains(attributes.count),
                  let pin, (1...64).contains(pin.utf8.count), !pin.utf8.contains(0) else { return false }
            return true
        }
    }
}
struct WorkerToken: Codable {
    let slot: UInt, label: String, manufacturer: String, model: String, reader: String
    let serial: String?
    init(_ token: SignumToken) {
        slot = token.slot; label = token.label; manufacturer = token.manufacturer; model = token.model; reader = token.reader
        serial = token.serial
    }
    var value: SignumToken { .init(slot: slot, label: label, manufacturer: manufacturer, model: model, reader: reader, serial: serial ?? "") }
}
struct WorkerCertificate: Codable {
    let label: String, identifier: Data, der: Data
    init(_ certificate: SignumCertificate, der: Data) { label = certificate.label; identifier = certificate.identifier; self.der = der }
    var valid: Bool { label.utf8.count <= 512 && (1...64).contains(identifier.count) && (1...65536).contains(der.count) }
    var value: SignumCertificate { .init(label: label, identifier: identifier) }
}
struct PKCS11WorkerResponse: Codable {
    let version: Int, id: UUID
    let action: PKCS11WorkerRequest.Action
    let provider: String
    let tokens: [WorkerToken]
    let unavailable: Int
    let certificates: [WorkerCertificate]
    let signature: Data?
    let succeeded: Bool
    var failureKind: String? = nil
    var libraryVersion: String? = nil
    var validatedModule: MiddlewareFileIdentity? = nil
    var automaticValidated: Bool? = nil
    var validatedContext: SigningProviderContext? = nil
}
#endif
