import Foundation
import Darwin
import SignumTrustCore

/// Raw signed bytes, never a trust assertion. Legacy A.1 envelopes decode with zero pivots.
public struct TLBundle: Codable, Sendable {
    public let country: String
    public let lotl: Data
    /// Legacy envelope key retained for A compatibility; contains the national XML for `country`.
    public let italy: Data
    public let pivots: [LOTLPivotChain.Pivot]
    public let refreshedAt: Date?
    public init(lotl: Data, italy: Data, pivots: [LOTLPivotChain.Pivot] = [], refreshedAt: Date? = nil, country: String = "IT") {
        self.country = country; self.lotl = lotl; self.italy = italy; self.pivots = pivots; self.refreshedAt = refreshedAt
    }
    enum CodingKeys: String, CodingKey { case country, lotl, italy, pivots, refreshedAt }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        country = try c.decodeIfPresent(String.self, forKey: .country) ?? "IT"
        lotl = try c.decode(Data.self, forKey: .lotl); italy = try c.decode(Data.self, forKey: .italy)
        pivots = try c.decodeIfPresent([LOTLPivotChain.Pivot].self, forKey: .pivots) ?? []
        refreshedAt = try c.decodeIfPresent(Date.self, forKey: .refreshedAt)
    }
}

struct VerifiedSnapshot: Sendable {
    let bundle: TLBundle
    let europe: AuthenticatedTL
    let italy: AuthenticatedTL
    let expired: Bool
}

/// Exact signed XML is reauthenticated on every read. One atomic envelope binds
/// the EU list, complete pivot history and one national TL; flock serializes local writers.
public enum TLSnapshot {
    public static func save(lotl: Data, italy: Data, to url: URL, now: Date) throws {
        try save(TLBundle(lotl: lotl, italy: italy, refreshedAt: now), to: url, now: now)
    }
    public static func save(_ bundle: TLBundle, to url: URL, now: Date) throws {
        try save(bundle, to: url, now: now, anchors: EUTrustPolicy.journalAnchors)
    }
    static func save(_ bundle: TLBundle, to url: URL, now: Date, anchors: Set<Data>, currentTime: (() -> Date)? = nil) throws {
        let current = try verify(bundle, now: now, allowExpired: false, anchors: anchors)
        // Stable sidecar lock, never the inode replaced by atomic rename.
        let fd = open(url.path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw TLAuthenticationError.rejected("cache lock open: \(errno)") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw TLAuthenticationError.rejected("cache writer busy") }
        defer { _ = flock(fd, LOCK_UN) }
        if FileManager.default.fileExists(atPath: url.path) {
            let old = try readVerified(url, now: currentTime?() ?? now, anchors: anchors)
            guard old.bundle.country == bundle.country else { throw TLAuthenticationError.rejected("cache territory changed") }
            for (candidate, previous) in [(current.europe, old.europe), (current.italy, old.italy)] {
                if case .rejected(let reason) = TLContinuityPolicy.assess(previous: previous.revision, candidate: candidate.revision, now: currentTime?() ?? now) {
                    throw TLAuthenticationError.rejected("saved snapshot rollback: \(reason)")
                }
            }
            // The authenticated post-reset pivot history must never be shortened.
            let oldURLs = old.bundle.pivots.map(\.location)
            guard Array(bundle.pivots.prefix(oldURLs.count).map(\.location)) == oldURLs else {
                throw TLAuthenticationError.rejected("pivot history rollback")
            }
        }
        let encoded = try JSONEncoder().encode(bundle)
        guard encoded.count <= maximumEnvelopeBytes else { throw TLAuthenticationError.rejected("cache bounds") }
        let commitTime = currentTime?() ?? now
        guard min(current.europe.document.nextUpdate, current.italy.document.nextUpdate) > commitTime,
              max(current.europe.document.issuedAt, current.italy.document.issuedAt) <= commitTime.addingTimeInterval(300) else {
            throw TLAuthenticationError.rejected("snapshot no longer current at commit")
        }
        // A.1 Foundation atomic replacement: failures leave the previous file intact.
        try encoded.write(to: url, options: .atomic)
    }
    public static func load(from url: URL, now: Date) throws -> (AuthenticatedTL, AuthenticatedTL) {
        let verified = try readVerified(url, now: now)
        guard !verified.expired else { throw TLAuthenticationError.rejected("cache expired") }
        return (verified.europe, verified.italy)
    }
    static let maximumEnvelopeBytes = 180 * 1024 * 1024
    static func readVerified(_ url: URL, now: Date, anchors: Set<Data> = EUTrustPolicy.journalAnchors) throws -> VerifiedSnapshot {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        // Bound the actual read, including a file changed after stat.
        var data = Data()
        while let chunk = try handle.read(upToCount: min(1024 * 1024, maximumEnvelopeBytes + 1 - data.count)), !chunk.isEmpty {
            data.append(chunk)
            guard data.count <= maximumEnvelopeBytes else { throw TLAuthenticationError.rejected("cache bounds") }
        }
        return try verify(JSONDecoder().decode(TLBundle.self, from: data), now: now, allowExpired: true, anchors: anchors)
    }
    static func verify(_ bundle: TLBundle, now: Date, allowExpired: Bool, anchors: Set<Data>) throws -> VerifiedSnapshot {
        guard bundle.pivots.count <= 16,
              bundle.lotl.count <= UntrustedTLParser.maximumInputBytes,
              bundle.italy.count <= UntrustedTLParser.maximumInputBytes,
              bundle.pivots.reduce(bundle.lotl.count + bundle.italy.count, { $0 + $1.xml.count }) <= 128 * 1024 * 1024 else {
            throw TLAuthenticationError.rejected("bundle bounds")
        }
        let euRaw = try UntrustedTLParser.parse(bundle.lotl), itRaw = try UntrustedTLParser.parse(bundle.italy)
        let historicalDate = max(euRaw.issuedAt, itRaw.issuedAt)
        guard historicalDate <= now.addingTimeInterval(300) else { throw TLAuthenticationError.rejected("future cache") }
        let expired = min(euRaw.nextUpdate, itRaw.nextUpdate) <= now
        guard allowExpired || !expired else { throw TLAuthenticationError.rejected("cache expired") }
        // Historical evaluation verifies provenance, never promotes an expired pair to current.
        let evaluationDate = expired ? historicalDate : now
        let eu = try LOTLPivotChain.validate(current: bundle.lotl, pivotsOldestFirst: bundle.pivots, now: evaluationDate, initialAnchors: anchors)
        let it: AuthenticatedTL
        if bundle.country == "IT" { it = try TLAuthenticator.authenticateItaly(bundle.italy, lotl: eu, now: evaluationDate) }
        else { it = try TLAuthenticator.authenticateNational(bundle.italy, country: bundle.country, lotl: eu, now: evaluationDate) }
        return VerifiedSnapshot(bundle: bundle, europe: eu, italy: it, expired: expired)
    }
}
