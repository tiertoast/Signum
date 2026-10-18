import Foundation
import CryptoKit
import CCertificatePolicy

/// Offline document-signing policy. No CA trust, revocation, eIDAS or legal assessment.
/// The same native policy is linked into the standalone PAdES helper.
public enum CertificateEligibility {
    public enum Status: String, Sendable {
        case eligible, ineligible, indeterminate
        public var description: String {
            switch self {
            case .eligible: return "Idoneo ai controlli locali"
            case .ineligible: return "Non idoneo"
            case .indeterminate: return "Idoneità indeterminata"
            }
        }
    }
    public struct Assessment: Sendable {
        public let status: Status
        public let reasons: [String]
        public let notBefore: Date?
        public let notAfter: Date?
        public let keyUsagePresent: Bool
        public let digitalSignature: Bool
        public let contentCommitment: Bool
        public let extendedKeyUsagePresent: Bool
        public let documentSigning: Bool
        public let anyExtendedKeyUsage: Bool
        public let clientAuthentication: Bool
        public let publicKeyBits: Int
        public let certificateSHA256: String
        /// Only an affirmative local result permits a new signing operation.
        public var permitsSigning: Bool { status == .eligible }
        public var explanation: String {
            ([status.description] + reasons).joined(separator: " · ")
        }
        public var usageDescription: String {
            let usages = [digitalSignature ? "digitalSignature" : nil,
                          contentCommitment ? "contentCommitment" : nil].compactMap { $0 }
            return usages.isEmpty ? "Uso di firma non accertato" : usages.joined(separator: ", ")
        }
    }
    public static let scope = "Controlli locali: attendibilità CA, revoca, qualificazione eIDAS e validità giuridica non valutate."

    public static func evaluate(certificateDER: Data, at date: Date = Date()) -> Assessment {
        let result = certificateDER.withUnsafeBytes {
            sg_certificate_assess($0.bindMemory(to: UInt8.self).baseAddress, $0.count, date.timeIntervalSince1970)
        }
        let malformed = result.reasons & UInt32(SG_CERT_MALFORMED) != 0
        let reasons = (0..<32).compactMap { bit -> String? in
            let flag = UInt32(1) << bit
            guard result.reasons & flag != 0 else { return nil }
            return String(cString: sg_certificate_reason_message(flag))
        }
        return Assessment(status: result.status == SG_CERT_ELIGIBLE ? .eligible :
                            result.status == SG_CERT_INELIGIBLE ? .ineligible : .indeterminate,
                          reasons: reasons,
                          notBefore: malformed ? nil : Date(timeIntervalSince1970: result.not_before),
                          notAfter: malformed ? nil : Date(timeIntervalSince1970: result.not_after),
                          keyUsagePresent: result.key_usage_present != 0,
                          digitalSignature: result.digital_signature != 0,
                          contentCommitment: result.content_commitment != 0,
                          extendedKeyUsagePresent: result.eku_present != 0,
                          documentSigning: result.document_signing != 0,
                          anyExtendedKeyUsage: result.any_extended_key_usage != 0,
                          clientAuthentication: result.client_authentication != 0,
                          publicKeyBits: Int(result.public_key_bits),
                          certificateSHA256: certificateDER.count <= 65536 ? SHA256.hash(data: certificateDER).map { String(format: "%02x", $0) }.joined() : "")
    }

    /// Re-evaluate fresh DER at the operation boundary. An approved certificate
    /// is bound by its complete bytes, never by label, subject name or CKA_ID alone.
    @discardableResult
    public static func requireEligible(certificateDER: Data, expectedCertificateDER: Data? = nil,
                                       at date: Date = Date()) throws -> Assessment {
        if let expectedCertificateDER, certificateDER != expectedCertificateDER {
            throw SignumError.module("Il certificato è cambiato. Ricarica i certificati e seleziona nuovamente il firmatario.")
        }
        let assessment = evaluate(certificateDER: certificateDER, at: date)
        guard assessment.permitsSigning else { throw SignumError.module(assessment.explanation) }
        return assessment
    }
}
