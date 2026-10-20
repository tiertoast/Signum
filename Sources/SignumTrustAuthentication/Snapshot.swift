import Foundation
import SignumTrustCore

/// A single atomic file holds the exact signed bytes. Reload always reauthenticates.
/// Expired/offline bytes cannot produce a current result by bypassing verification.
public enum TLSnapshot {
    private struct Envelope: Codable { let lotl: Data; let italy: Data }
    public static func save(lotl: Data, italy: Data, to url: URL, now: Date) throws {
        let current = try verify(lotl: lotl, italy: italy, now: now)
        if FileManager.default.fileExists(atPath: url.path) {
            let old = try read(url)
            let e = try UntrustedTLParser.parse(old.lotl), i = try UntrustedTLParser.parse(old.italy)
            let historicalDate = max(e.issuedAt, i.issuedAt)
            guard historicalDate <= now else { throw TLAuthenticationError.rejected("future saved revision") }
            let previous = try verify(lotl: old.lotl, italy: old.italy, now: historicalDate)
            for (candidate, accepted) in [(current.0, previous.0), (current.1, previous.1)] {
                if case .rejected(let reason) = TLContinuityPolicy.assess(previous: accepted.revision, candidate: candidate.revision, now: now) {
                    throw TLAuthenticationError.rejected("saved snapshot rollback: \(reason)")
                }
            }
        }
        try JSONEncoder().encode(Envelope(lotl: lotl, italy: italy)).write(to: url, options: .atomic)
    }
    public static func load(from url: URL, now: Date) throws -> (AuthenticatedTL, AuthenticatedTL) {
        let e = try read(url)
        return try verify(lotl: e.lotl, italy: e.italy, now: now)
    }
    private static func read(_ url: URL) throws -> Envelope {
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
        guard size <= 180 * 1024 * 1024 else { throw TLAuthenticationError.rejected("snapshot bounds") }
        return try JSONDecoder().decode(Envelope.self, from: Data(contentsOf: url))
    }
    private static func verify(lotl: Data, italy: Data, now: Date) throws -> (AuthenticatedTL, AuthenticatedTL) {
        // This PoC snapshot format supports the current reset with zero pivots.
        // A later rotation requires explicit pivot inputs; fail closed until supplied.
        let eu = try LOTLPivotChain.authenticate(current: lotl, pivotsOldestFirst: [], now: now)
        return (eu, try TLAuthenticator.authenticateItaly(italy, lotl: eu, now: now))
    }
}
