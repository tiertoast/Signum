import Foundation

public struct ExtractedCMSAttribute: Codable, Equatable, Sendable {
    public let oid: String
    public let der: Data
}
public struct EmbeddedValidationEvidence: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case ocsp, crl, certificate }
    public enum Association: String, Codable, Sendable { case signerInfo, pdfVRI, unassociated }
    public let kind: Kind
    public let source: String
    public let association: Association
    public let der: Data
    public let signatureKey: String
    public let signatureRevisionEnd: Int
    public let sourceRevisionEnd: Int
    /// Structural provenance only; crypto verification of the target certificate
    /// is still required. Unsigned attributes and VRI are not signed assertions.
    public func isBound(to signature: SignatureVerificationResult) -> Bool {
        guard let envelope = signature.evidence, !envelope.signatureValue.isEmpty,
              association != .unassociated, signatureKey == envelope.signatureKey,
              signatureRevisionEnd == (signature.signedRevisionEnd ?? 0) else { return false }
        if signature.signedRevisionEnd != nil {
            return sourceRevisionEnd >= signatureRevisionEnd && (association == .pdfVRI || association == .signerInfo)
        }
        return association == .signerInfo && sourceRevisionEnd == 0
    }
}
public struct SignatureEvidenceEnvelope: Equatable, Sendable {
    public let signatureValue: Data
    public let signatureKey: String
    public let signerIndex: Int
    public let signedAttributes: [ExtractedCMSAttribute]
    public let unsignedAttributes: [ExtractedCMSAttribute]
    public let timestampTokens: [Data]
    public let embedded: [EmbeddedValidationEvidence]
    public let issue: String
}
