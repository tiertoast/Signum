#if os(macOS)
import Foundation

/// Observed route properties, never a physical token attestation. No secret.
public struct SigningProviderContext: Codable, Hashable, Sendable {
    public let version: Int
    public let provider: String
    public let moduleIdentity: MiddlewareFileIdentity
    public let automatic: Bool
    public let token: SignumToken
    public let objectID: Data
    public let certificateSHA256: String
    public let routeID: String
    public let discoveryID: UUID

    public var valid: Bool {
        let m = moduleIdentity
        return version == 1 && provider.hasPrefix("/") && provider.utf8.count <= 4096 && !provider.utf8.contains(0) &&
            !provider.split(separator: "/").contains("..") && m.device >= 0 && m.inode > 0 && m.size >= 0 &&
            m.modifiedSeconds >= 0 && m.changedSeconds >= 0 && (0..<1_000_000_000).contains(m.modifiedNanoseconds) &&
            (0..<1_000_000_000).contains(m.changedNanoseconds) && (1...64).contains(objectID.count) &&
            Self.digest(certificateSHA256) && Self.digest(routeID) &&
            [(token.label, 128), (token.manufacturer, 128), (token.model, 128), (token.reader, 256), (token.serial, 32)].allSatisfy {
                $0.0.utf8.count <= $0.1 && !$0.0.utf8.contains(0)
            }
    }
    private static func digest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    func matches(provider: String, slot: UInt, certificate: SignumCertificate, der: Data) -> Bool {
        valid && self.provider == provider && token.slot == slot && objectID == certificate.identifier &&
            certificateSHA256 == DocumentSnapshot.digest(der)
    }
    func requireCurrentModule() throws {
        let actual = try MiddlewareFileSecurity.inspect(provider, automatic: automatic)
        guard valid, actual.canonicalPath == provider, actual.identity == moduleIdentity else { throw MiddlewareFileSecurity.Failure.changed }
    }
    func requireCurrentToken(_ module: PKCS11Module) throws {
        guard module.modulePath == provider, try module.scanTokens().tokens.contains(token) else {
            throw MiddlewareFileSecurity.Failure.changed
        }
    }
    /// Bounded public context for native PAdES v5. Hex fields cannot contain the
    /// separator; decimal integers have explicit bounds in the native consumer.
    public var padesWire: String {
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        func text(_ value: String) -> String { hex(Data(value.utf8)) }
        let m = moduleIdentity
        return ["1", text(provider), String(m.device), String(m.inode), String(m.size), String(m.modifiedSeconds),
            String(m.modifiedNanoseconds), String(m.changedSeconds), String(m.changedNanoseconds), automatic ? "1" : "0",
            String(token.slot), text(token.label), text(token.manufacturer), text(token.model), text(token.reader), text(token.serial),
            hex(objectID), certificateSHA256, routeID, discoveryID.uuidString].joined(separator: ":")
    }
}

extension DeviceCertificateRoute {
    public func signingContext(discoveryID: UUID) -> SigningProviderContext {
        .init(version: 1, provider: providerPath, moduleIdentity: moduleIdentity, automatic: origin == .known,
            token: token, objectID: certificate.identifier, certificateSHA256: certificateFingerprint,
            routeID: id, discoveryID: discoveryID)
    }
}
#endif
