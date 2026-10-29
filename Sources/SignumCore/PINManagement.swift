#if os(macOS)
import Foundation
import CryptoKit
import CPINManagement

public enum PINManagementOperation: String, Codable, Sendable { case changePIN, unblockPIN }

/// Capability evidence is deliberately separate from any advertised entry point.
public struct PINManagementProfile: Codable, Hashable, Sendable {
    public enum Evidence: String, Codable, Sendable { case unknown, documented, observed, hardwareQualified }
    public let id: String
    public let changeEvidence: Evidence
    public let unblockEvidence: Evidence
    public static let unqualified = Self(id: "unqualified-12A", changeEvidence: .unknown, unblockEvidence: .unknown)
    /// Build 12A/12B have no enabled real backend, irrespective of metadata.
    public var permitsRealMutation: Bool { false }
}

/// Independent administrative observation. No certificate, signing route or PIN.
/// Public token metadata is not cryptographic attestation of physical identity.
public struct PINManagementContext: Codable, Hashable, Sendable {
    public let version: Int
    public let provider: String
    public let moduleIdentity: MiddlewareFileIdentity
    public let automatic: Bool
    public let token: SignumToken
    public let discoveryID: UUID
    public let profile: PINManagementProfile
    public let pinDomain: String?
    public let applicationID: String?
    public let authenticationID: String?
    public let configurationIdentity: String?

    public init(provider: String, inspection: MiddlewareFileSecurity.Inspection, automatic: Bool,
                token: SignumToken, discoveryID: UUID) {
        version = 1; self.provider = provider; moduleIdentity = inspection.identity
        self.automatic = automatic; self.token = token; self.discoveryID = discoveryID
        profile = .unqualified
        pinDomain = nil; applicationID = nil; authenticationID = nil; configurationIdentity = nil
    }
    public var valid: Bool {
        let m = moduleIdentity
        return version == 1 && provider.hasPrefix("/") && provider.utf8.count <= 4096 && !provider.utf8.contains(0) &&
            !provider.split(separator: "/").contains("..") && m.device >= 0 && m.inode > 0 && m.size >= 0 &&
            m.modifiedSeconds >= 0 && m.changedSeconds >= 0 &&
            (0..<1_000_000_000).contains(m.modifiedNanoseconds) && (0..<1_000_000_000).contains(m.changedNanoseconds) &&
            profile == .unqualified && pinDomain == nil && applicationID == nil && authenticationID == nil && configurationIdentity == nil &&
            [(token.label, 128), (token.manufacturer, 128), (token.model, 128), (token.reader, 256), (token.serial, 32)].allSatisfy {
                $0.0.utf8.count <= $0.1 && !$0.0.utf8.contains(0)
            }
    }
    public var fingerprint: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard valid, let bytes = try? encoder.encode(self) else { return "" }
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    func requireCurrentModule() throws {
        let current = try MiddlewareFileSecurity.inspect(provider, automatic: automatic)
        guard valid, current.canonicalPath == provider, current.identity == moduleIdentity else {
            throw PINManagementFailure.contextChanged
        }
    }
}

public struct PINStatusSnapshot: Codable, Equatable, Sendable {
    public let version: Int
    public let contextFingerprint: String
    public let readAt: Date
    public let flags: UInt64
    public let minimumBytes: UInt64?
    public let maximumBytes: UInt64?
    public let moduleVersion: String?
    public var userPINInitialized: Bool { flags & (1 << 3) != 0 }
    public var userPINCountLow: Bool { flags & (1 << 16) != 0 }
    public var userPINFinalTry: Bool { flags & (1 << 17) != 0 }
    public var userPINLocked: Bool { flags & (1 << 18) != 0 }
    public var userPINMustChange: Bool { flags & (1 << 19) != 0 }
    public var protectedAuthenticationPath: Bool { flags & (1 << 8) != 0 }
    public var valid: Bool {
        version == 1 && contextFingerprint.utf8.count == 64 &&
            contextFingerprint.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
            readAt.timeIntervalSince1970.isFinite && readAt.timeIntervalSince1970 >= 0 &&
            (moduleVersion?.utf8.count ?? 0) <= 32
    }
    public var limitsConsistent: Bool {
        guard let minimumBytes, let maximumBytes else { return false }
        return minimumBytes > 0 && maximumBytes >= minimumBytes
    }
    public var statusDescription: String {
        if userPINLocked { return "Il middleware segnala il PIN utente bloccato." }
        if userPINFinalTry { return "Il middleware segnala l’ultimo tentativo disponibile. Un codice errato può bloccare il PIN." }
        if userPINCountLow { return "Il middleware segnala pochi tentativi disponibili." }
        if userPINMustChange { return "Il middleware richiede la modifica del PIN utente." }
        return "Nessuna segnalazione di blocco restituita. L’utilizzabilità del PIN non è accertata."
    }
}

/// A future consent cannot be substituted across operations, domains or scans.
/// No public initializer and no Codable conformance: not a persisted permission.
public struct PINManagementApproval: Sendable {
    let requestID: UUID
    let contextFingerprint: String
    let operation: PINManagementOperation
    let nonce: UUID
    let deadlineUptime: TimeInterval
}

public enum PINManagementFailure: String, Error, Codable, Sendable, LocalizedError {
    case compatibilityUnverified, contextChanged, busy, publicReadFailed, protocolViolation
    public var errorDescription: String? {
        switch self {
        case .compatibilityUnverified: return "Compatibilità non ancora verificata. Cambio PIN e sblocco con PUK non sono disponibili in questa build."
        case .contextChanged: return "Il dispositivo o il software è cambiato. Seleziona nuovamente l’accesso amministrativo."
        case .busy: return "Il dispositivo è occupato da un’altra operazione Signum. Nessun codice inviato."
        case .publicReadFailed: return "Stato PIN non disponibile. La lettura pubblica non è riuscita; nessun codice inviato."
        case .protocolViolation: return "Risposta amministrativa non valida. Nessun tentativo automatico aggiuntivo."
        }
    }
}

/// Real application facade. No injectable mutating backend, environment switch,
/// module fallback, retry, signing-route conversion or secret-accepting method.
public enum PINManagementCoordinator {
    public static func readStatus(context: PINManagementContext,
                                  isCancelled: () -> Bool = { false }) throws -> PINStatusSnapshot {
        try PINManagementWorkerClient.read(context: context, isCancelled: isCancelled)
    }
    public static func confirm(operation: PINManagementOperation, context: PINManagementContext,
                               workflowLocked: Bool) throws -> PINManagementApproval {
        // Before credential UI, IPC or vendor load. Never infer qualification.
        guard context.valid else { throw PINManagementFailure.contextChanged }
        if workflowLocked { throw PINManagementFailure.busy }
        throw PINManagementFailure.compatibilityUnverified
    }
}
#endif
