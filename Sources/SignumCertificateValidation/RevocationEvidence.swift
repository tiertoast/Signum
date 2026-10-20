import Foundation
import Darwin
import CCertificatePath

/// Validates a revocation statement for one certificate/issuer pair. This does
/// not authenticate a document, a path, or the time at which a signature existed.
public enum RevocationEvidenceKind: Int32, Codable, Sendable { case ocsp = 1, crl = 2 }
public enum RevocationEvidenceState: String, Codable, Sendable {
    case good, revoked, unknown, invalid, stale
}
public struct RevocationEvidence: Codable, Equatable, Sendable {
    public let kind: RevocationEvidenceKind
    public let der: Data
    public init(kind: RevocationEvidenceKind, der: Data) { self.kind = kind; self.der = der }
}
public struct RevocationEvidenceResult: Equatable, Sendable {
    public let state: RevocationEvidenceState
    public let kind: RevocationEvidenceKind
    public let evaluatedAt: Date
    public let thisUpdate: Date?, nextUpdate: Date?, revokedAt: Date?
    public let reason: String
    public var authenticated: Bool { state == .good || state == .revoked }
}
public enum RevocationEvidenceVerifier {
    public static let maximumBytes = 8 * 1024 * 1024
    public static func verify(_ evidence: RevocationEvidence, certificate: Data, issuer: Data, now: Date = Date()) -> RevocationEvidenceResult {
        var reason = [CChar](repeating: 0, count: 512)
        var first: Int64 = 0, next: Int64 = 0, revoked: Int64 = 0
        var code: Int32 = 0
        let seconds = now.timeIntervalSince1970
        if seconds.isFinite, seconds >= 1, seconds < 253402300799,
           certificate.count <= 65536, issuer.count <= 65536, evidence.der.count <= maximumBytes {
            code = certificate.withUnsafeBytes { c in issuer.withUnsafeBytes { i in evidence.der.withUnsafeBytes { e in
                signum_revocation_evidence(evidence.kind.rawValue,
                    c.bindMemory(to: UInt8.self).baseAddress, c.count,
                    i.bindMemory(to: UInt8.self).baseAddress, i.count,
                    e.bindMemory(to: UInt8.self).baseAddress, e.count, Int64(seconds),
                    &first, &next, &revoked, &reason, reason.count)
            } } }
        }
        let state: RevocationEvidenceState = code == 1 ? .good : code == 2 ? .revoked : code == -1 ? .invalid : code == -2 ? .stale : .unknown
        return .init(state: state, kind: evidence.kind, evaluatedAt: now,
            thisUpdate: first > 0 ? Date(timeIntervalSince1970: Double(first)) : nil,
            nextUpdate: next > 0 ? Date(timeIntervalSince1970: Double(next)) : nil,
            revokedAt: revoked > 0 ? Date(timeIntervalSince1970: Double(revoked)) : nil,
            reason: reason[0] == 0 ? "Dati o data oltre i limiti supportati" : String(cString: reason))
    }
}

/// Disk bytes are always reverified, never decoded into a trusted boolean.
/// An invalid replacement cannot discard the last usable evidence. This cache
/// is deliberately separate from the authenticated Trusted List snapshots.
public actor RevocationEvidenceCache {
    private let directory: URL
    public init(directory: URL) { self.directory = directory }
    private struct Entry: Codable { let version: Int; let certificate: Data; let issuer: Data; let evidence: RevocationEvidence }
    private func key(_ certificate: Data, _ issuer: Data, _ kind: RevocationEvidenceKind) -> String {
        CertificatePathValidator.hash(certificate) + "-" + CertificatePathValidator.hash(issuer) + "-\(kind.rawValue).json"
    }
    public func store(_ evidence: RevocationEvidence, certificate: Data, issuer: Data, now: Date = Date()) throws -> RevocationEvidenceResult {
        let result = RevocationEvidenceVerifier.verify(evidence, certificate: certificate, issuer: issuer, now: now)
        guard result.authenticated else { return result }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent(key(certificate, issuer, evidence.kind))
        let lock = open(url.path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, S_IRUSR | S_IWUSR)
        guard lock >= 0 else { throw CacheError.unsupportedFile }
        defer { close(lock) }
        var lockAttributes = stat()
        guard fstat(lock, &lockAttributes) == 0, (lockAttributes.st_mode & S_IFMT) == S_IFREG else { throw CacheError.unsupportedFile }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw CacheError.writerBusy }
        defer { _ = flock(lock, LOCK_UN) }
        if let old = try load(evidence.kind, certificate: certificate, issuer: issuer, now: now), old.result.authenticated {
            // Conflicting current signed statements must not turn into a
            // positive cache result, even if one has a newer thisUpdate.
            if old.result.state != result.state { throw CacheError.conflictingEvidence }
            if let oldDate = old.result.thisUpdate, let newDate = result.thisUpdate, oldDate > newDate { return old.result }
        }
        let bytes = try JSONEncoder().encode(Entry(version: 1, certificate: certificate, issuer: issuer, evidence: evidence))
        try bytes.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return result
    }
    public func load(_ kind: RevocationEvidenceKind, certificate: Data, issuer: Data, now: Date = Date()) throws -> (evidence: RevocationEvidence, result: RevocationEvidenceResult)? {
        let url = directory.appendingPathComponent(key(certificate, issuer, kind))
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0, errno == ENOENT { return nil }
        guard fd >= 0 else { throw CacheError.unsupportedFile }
        defer { close(fd) }
        var attributes = stat()
        guard fstat(fd, &attributes) == 0, (attributes.st_mode & S_IFMT) == S_IFREG,
              attributes.st_size >= 0, attributes.st_size <= 12 * 1024 * 1024 else { throw CacheError.unsupportedFile }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n >= 0, n <= 12 * 1024 * 1024 - bytes.count else { throw CacheError.unsupportedFile }
            if n == 0 { break }; bytes.append(contentsOf: buffer.prefix(n))
        }
        let entry = try JSONDecoder().decode(Entry.self, from: bytes)
        guard entry.version == 1, entry.certificate == certificate, entry.issuer == issuer,
              entry.evidence.kind == kind else { throw CacheError.wrongIdentity }
        let result = RevocationEvidenceVerifier.verify(entry.evidence, certificate: certificate, issuer: issuer, now: now)
        return (entry.evidence, result)
    }
    public enum CacheError: Error { case unsupportedFile, wrongIdentity, writerBusy, conflictingEvidence }
}
