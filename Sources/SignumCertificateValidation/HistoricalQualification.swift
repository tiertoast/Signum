import Foundation
import SignumTrustCore
import SignumTrustAuthentication

/// Release coverage, not a trust source. Every identity still needs authenticated
/// TL provenance and a cryptographic path; other EU/EEA lists remain cacheable.
public enum EuropeanQualificationPolicy {
    public static let testedCountries: Set<String> = ["IT","AT","DE","BE","FR","ES"]
    public static let identifier = "Signum-E2-direct-CAQC-eSig-2016-v1"
}
struct HistoricalQualification {
    struct Profile: Equatable {
        let qualified: Bool
        let device: TLDeviceEvidence
        let electronicSignature: Bool
    }
    static func profile(_ qualifiers: Set<String>, material: CertificateQualificationMaterial, at: Date) -> Profile? {
        let has: (String)->Bool = { qualifiers.contains(TLQualificationRules.prefix+$0) }
        guard !(has("NotQualified") && material.qc.compliance), !has("QCQSCDManagedOnBehalf"),
              !(["QCNoQSCD","QCNoSSCD"].contains(where:has) && material.qc.sscd) else { return nil }
        let type = !has("QCForLegalPerson") && !has("QCForESeal") && !has("QCForWSA") &&
            (material.qc.types == ["0.4.0.1862.1.6.1"] || (has("QCForESig") && material.qc.types.isEmpty))
        let device = TLQualificationRules.deviceEvidence(qualifiers:qualifiers,sscd:material.qc.sscd,policies:material.policies,at:at)
        guard device != .indeterminate else { return nil }
        return .init(qualified:(material.qc.compliance || has("QCStatement")) && !has("NotQualified"),device:device,electronicSignature:type)
    }
    /// Each state evaluates its OWN criteria. Different URI sets may be equivalent
    /// for this certificate; a negative/ambiguous transition is never skipped.
    static func covers(_ events: [TLServiceEvent], service: TLService, identity: String,
                       material: CertificateQualificationMaterial, proof: Date) -> Bool {
        guard material.notBefore >= TLQualificationRules.regulationStart, material.notBefore <= proof,
              events.contains(where:{ $0.contains(material.notBefore) }),
              let last = events.first(where:{ $0.contains(proof) }),
              let finalQualifiers = TLQualificationRules.evaluate(last.extensions,material:material),
              let final = profile(finalQualifiers,material:material,at:proof) else { return false }
        let covered = events.filter { $0.start <= proof && ($0.end.map { $0 > material.notBefore } ?? true) }
        return !covered.isEmpty && covered.allSatisfy { event in
            guard event.typeURI == CertificatePathValidator.caQC, event.statusURI == CertificatePathValidator.granted,
                  TLServiceIdentityResolver.certificates(event,service:service).contains(where:{ CertificatePathValidator.hash($0) == identity }),
                  let qualifiers = TLQualificationRules.evaluate(event.extensions,material:material),
                  let value = profile(qualifiers,material:material,at:max(event.start,material.notBefore)) else { return false }
            return value == final
        }
    }
}
