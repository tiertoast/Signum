import Foundation
import SignumTrustCore

/// Offline pivot validation. URLs in an unverified current LOTL are discovery hints
/// only. Every pivot must authenticate with the PREVIOUS authorized certificate set.
/// Reset notices are pinned policy updates, never learned as trust from XML.
public enum LOTLPivotChain {
    public struct Pivot: Codable, Sendable {
        public let location: String
        public let xml: Data
        public init(location: String, xml: Data) { self.location = location; self.xml = xml }
    }
    public static func authenticate(current: Data, pivotsOldestFirst: [Pivot], now: Date,
                                    previous: AuthenticatedTL? = nil) throws -> AuthenticatedTL {
        try validate(current: current, pivotsOldestFirst: pivotsOldestFirst, now: now,
                     previous: previous, initialAnchors: EUTrustPolicy.journalAnchors)
    }
    // Internal injection used only by deterministic test vectors, not the official entry point.
    static func validate(current: Data, pivotsOldestFirst: [Pivot], now: Date,
                         previous: AuthenticatedTL? = nil, initialAnchors: Set<Data>) throws -> AuthenticatedTL {
        guard pivotsOldestFirst.count <= 16 else { throw TLAuthenticationError.rejected("pivot chain too long") }
        var anchors = initialAnchors
        var last: AuthenticatedTL?
        for (index, pivot) in pivotsOldestFirst.enumerated() {
            guard allowedPivotURL(pivot.location) else { throw TLAuthenticationError.rejected("unauthorized pivot location") }
            let observation = try UntrustedTLParser.parse(pivot.xml)
            guard observation.issuedAt <= now else { throw TLAuthenticationError.rejected("future pivot") }
            // Archived pivots may be expired TODAY. Their signature, chronology and
            // anchor transition must still verify. Their output is never a current TL.
            let verified = try TLAuthenticator.authenticate(pivot.xml, authorizedCertificateSHA256: anchors,
                territory: "EU", now: observation.issuedAt)
            if let last {
                guard verified.document.sequenceNumber > last.document.sequenceNumber,
                      verified.document.issuedAt >= last.document.issuedAt else {
                    throw TLAuthenticationError.rejected("pivot order/rollback")
                }
            }
            let priorURLs = try pivotURLs(in: verified)
            let consumed = pivotsOldestFirst.prefix(index + 1).map(\.location).reversed()
            guard priorURLs == Array(consumed) else { throw TLAuthenticationError.rejected("pivot history mismatch") }
            let eu = verified.document.pointers.filter { $0.territory == "EU" && $0.location == EUTrustPolicy.location }
            guard eu.count == 1, !eu[0].signingCertificateDERs.isEmpty else {
                throw TLAuthenticationError.rejected("unique authorized EU rollover pointer required")
            }
            anchors = Set(eu[0].signingCertificateDERs.map(TLAuthenticator.sha256))
            last = verified
        }
        let currentTL = try TLAuthenticator.authenticate(current, authorizedCertificateSHA256: anchors,
            territory: "EU", now: now, previous: previous)
        guard try pivotURLs(in: currentTL) == pivotsOldestFirst.reversed().map(\.location) else {
            throw TLAuthenticationError.rejected("missing/unexpected post-reset pivot")
        }
        if let previous {
            let priorChain = Array(try pivotURLs(in: previous).reversed())
            guard pivotsOldestFirst.prefix(priorChain.count).map(\.location) == priorChain else {
                throw TLAuthenticationError.rejected("pivot history rollback")
            }
        }
        let selfPointers = currentTL.document.pointers.filter { $0.territory == "EU" && $0.location == EUTrustPolicy.location }
        guard selfPointers.count == 1,
              Set(selfPointers[0].signingCertificateDERs.map(TLAuthenticator.sha256)) == anchors else {
            throw TLAuthenticationError.rejected("current EU keys differ from authenticated pivot chain")
        }
        if let last {
            guard currentTL.document.sequenceNumber >= last.document.sequenceNumber,
                  currentTL.document.issuedAt >= last.document.issuedAt,
                  (currentTL.document.sequenceNumber != last.document.sequenceNumber || currentTL.revision.xmlSHA256 == last.revision.xmlSHA256) else {
                throw TLAuthenticationError.rejected("current LOTL precedes pivot")
            }
        }
        return currentTL
    }
    private static func pivotURLs(in tl: AuthenticatedTL) throws -> [String] {
        try pivotURLs(in: tl.schemeInformationURIs)
    }
    /// Bounded, untrusted discovery hints; callers must still authenticate the complete chain.
    static func discoveryURLs(in xml: Data) throws -> [String] {
        _ = try UntrustedTLParser.parse(xml)
        return try pivotURLs(in: TLAuthenticator.schemeURIs(in: xml)).reversed()
    }
    static func pivotURLs(in uris: [String]) throws -> [String] {
        guard let reset = uris.firstIndex(of: EUTrustPolicy.journal) else {
            throw TLAuthenticationError.rejected("pinned 2026 OJ reset missing")
        }
        let urls = Array(uris.prefix(reset))
        guard Set(urls).count == urls.count, urls.allSatisfy(allowedPivotURL) else {
            throw TLAuthenticationError.rejected("invalid post-reset pivot history")
        }
        return urls
    }
    static func allowedPivotURL(_ text: String) -> Bool {
        guard let url = URL(string: text), url.scheme == "https", url.host == "ec.europa.eu",
              url.port == nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else { return false }
        return text.range(of: #"^https://ec\.europa\.eu/tools/lotl/eu-lotl-pivot-[0-9]+\.xml$"#, options: .regularExpression) != nil
    }
}
