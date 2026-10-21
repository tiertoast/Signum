import Foundation

/// An observation extracted from XML, before XML signature verification.
/// The SHA-256 digest is supplied by the caller and is NOT a trust assertion.
public struct UntrustedTLRevision: Equatable, Sendable {
    public let territory: String
    public let version: Int
    public let sequenceNumber: Int
    public let issuedAt: Date
    public let nextUpdate: Date
    public let xmlSHA256: Data

    public init(document: UntrustedTLDocument, xmlSHA256: Data) throws {
        guard xmlSHA256.count == 32, document.sequenceNumber > 0,
              document.nextUpdate > document.issuedAt else {
            throw TLContinuityFailure.malformedRevision
        }
        territory = document.territory
        version = document.version
        sequenceNumber = document.sequenceNumber
        issuedAt = document.issuedAt
        nextUpdate = document.nextUpdate
        self.xmlSHA256 = xmlSHA256
    }
}

public enum TLContinuityFailure: Error, Equatable, Sendable {
    case malformedRevision
    case expired
    case issuedInFuture
    case territoryChanged
    case versionDowngrade
    case sequenceRollback
    case sequenceReusedWithDifferentContent
    case issueTimeRollback
}

/// This is a comparison of *untrusted* version metadata, not an
/// XMLDSig, ETSI, certificate-path, or eIDAS validation decision.
public enum TLContinuityDecision: Equatable, Sendable {
    case initialCandidate
    case unchangedCandidate
    case newerCandidate
    case rejected(TLContinuityFailure)
}

public enum TLContinuityPolicy {
    /// No state is persisted or promoted to trusted by this function.
    /// Caller must authenticate LOTL/TL signatures and provenance before
    /// using any returned candidate for a verified cache.
    public static func assess(
        previous: UntrustedTLRevision?,
        candidate: UntrustedTLRevision,
        now: Date,
        allowedClockSkew: TimeInterval = 300
    ) -> TLContinuityDecision {
        guard candidate.nextUpdate > candidate.issuedAt,
              candidate.sequenceNumber > 0,
              candidate.xmlSHA256.count == 32 else {
            return .rejected(.malformedRevision)
        }
        guard candidate.nextUpdate > now else { return .rejected(.expired) }
        guard allowedClockSkew >= 0,
              candidate.issuedAt <= now.addingTimeInterval(allowedClockSkew) else {
            return .rejected(.issuedInFuture)
        }
        guard let previous else { return .initialCandidate }

        guard candidate.territory == previous.territory else {
            return .rejected(.territoryChanged)
        }
        guard candidate.version >= previous.version else {
            return .rejected(.versionDowngrade)
        }
        guard candidate.sequenceNumber >= previous.sequenceNumber else {
            return .rejected(.sequenceRollback)
        }
        guard candidate.issuedAt >= previous.issuedAt else {
            return .rejected(.issueTimeRollback)
        }
        if candidate.sequenceNumber == previous.sequenceNumber {
            // Same sequence with changed bytes or metadata is not a
            // legitimate refresh, even when the XML claims a new issue date.
            return candidate == previous
                ? .unchangedCandidate
                : .rejected(.sequenceReusedWithDifferentContent)
        }
        return .newerCandidate
    }
}
