#if os(macOS)
import Foundation

/// Byte coverage is distinct from signature mathematics and from PDF permissions.
/// No DocMDP/FieldMDP or DSS-only classifier is implemented by this profile.
public struct PDFRevisionCoverage: Equatable, Sendable {
    public enum State: String, Sendable { case covered, notEvaluated, notApplicable }
    public enum SubsequentMaterial: String, Sendable {
        case none
        /// Later verified signature revisions exist and the last covers the input.
        /// This does not assert that those revisions changed only signature fields.
        case signedRevisions
        /// Content, DSS/evidence, timestamps or other bytes: nature not proven.
        case unclassified
    }
    public let state: State
    public let documentByteCount: Int?
    public let lastVerifiedRevisionEnd: Int?
    public let bytesAfterLastVerifiedRevision: Int?
    public let subsequentMaterial: SubsequentMaterial
}

/// Shared text and verdict for the screen, list, CLI summary and exported overview.
public struct DocumentVerificationOutcome: Equatable, Sendable {
    public let integrity: CryptographicIntegrity
    public let title: String
    public let value: String
}

extension VerificationReport {
    public var currentRevisionCoverage: PDFRevisionCoverage {
        guard format == .pades else {
            return .init(state: .notApplicable, documentByteCount: nil, lastVerifiedRevisionEnd: nil,
                         bytesAfterLastVerifiedRevision: nil, subsequentMaterial: .none)
        }
        guard documentState == "signed", let count = documentByteCount, count > 0 else {
            return .init(state: .notEvaluated, documentByteCount: documentByteCount, lastVerifiedRevisionEnd: nil,
                         bytesAfterLastVerifiedRevision: nil, subsequentMaterial: .unclassified)
        }
        // Use only boundaries from signatures actually verified by the native
        // engine, including its binding to the historical signed PDF prefix.
        let ends = signatures.compactMap { signature -> Int? in
            guard signature.integrity == .verified, let end = signature.signedRevisionEnd,
                  (1...count).contains(end), signature.laterChanges == (end < count) else { return nil }
            return end
        }
        let last = ends.max()
        let covered = last == count
        return .init(state: covered ? .covered : .notEvaluated, documentByteCount: count,
                     lastVerifiedRevisionEnd: last, bytesAfterLastVerifiedRevision: last.map { count - $0 },
                     subsequentMaterial: covered ? (Set(ends).count > 1 ? .signedRevisions : .none) : .unclassified)
    }

    /// Aggregate signature integrity remains available as `integrity`. Consumers
    /// making a claim about the current document must use this separate verdict.
    public var documentIntegrity: CryptographicIntegrity {
        let cryptographic = integrity
        guard cryptographic == .verified else { return cryptographic }
        return format == .pades && currentRevisionCoverage.state != .covered ? .notVerifiable : .verified
    }

    public var documentOutcome: DocumentVerificationOutcome {
        let value: String
        switch documentIntegrity {
        case .invalid: value = "Firma alterata o non valida"
        case .absent: value = format == .pades ? "PDF non firmato" : "Firma assente"
        case .notVerifiable:
            if format == .pades && integrity == .verified {
                value = currentRevisionCoverage.bytesAfterLastVerifiedRevision.map { $0 > 0 } == true
                    ? "Firma precedente verificata; modifiche successive non valutate"
                    : "Firme verificate; copertura della revisione corrente non valutata"
            } else { value = "Non determinabile" }
        case .verified:
            if format == .pades {
                value = signatures.count > 1
                    ? "Verificata · ultima revisione coperta, \(signatures.count) firme valide"
                    : "Verificata · revisione corrente coperta"
            } else { value = "Verificata" }
        }
        return .init(integrity: documentIntegrity, title: "Integrità del documento", value: value)
    }

    public var revisionCoverageDescription: String {
        let coverage = currentRevisionCoverage
        switch coverage.state {
        case .notApplicable: return "Non applicabile al formato"
        case .covered:
            return coverage.subsequentMaterial == .signedRevisions
                ? "Revisione corrente coperta dall’ultima firma verificata; esiti distinti per le firme precedenti. Accettabilità DocMDP/FieldMDP non valutata."
                : "Revisione corrente coperta da una firma verificata."
        case .notEvaluated:
            if let bytes = coverage.bytesAfterLastVerifiedRevision, bytes > 0 {
                return "Non valutata: \(bytes) byte dopo l’ultima revisione verificata. Modifiche successive non valutate; natura non classificabile. Non è dimostrato che si tratti solo di firme, timestamp o DSS/evidenze benigni."
            }
            return "Non valutata: nessuna firma verificata dimostra la copertura dell’intero documento corrente."
        }
    }

    public func signatureCoverageDescription(_ signature: SignatureVerificationResult) -> String {
        guard format == .pades else { return "Non applicabile al formato" }
        guard signature.integrity == .verified else { return "Copertura non attestata da questa firma: integrità non verificata." }
        if let count = documentByteCount, let end = signature.signedRevisionEnd,
           count > 0, end == count, !signature.laterChanges {
            return "Firma verificata: copre la revisione corrente."
        }
        if signature.laterChanges {
            return currentRevisionCoverage.state == .covered
                ? "Firma precedente verificata; la revisione corrente è coperta da una firma successiva."
                : "Firma precedente verificata; modifiche successive non valutate."
        }
        return "Firma verificata; copertura della revisione corrente non valutata."
    }
}
#endif
