import Foundation
import SignumCore
import SignumCertificateValidation

enum VerificationTone: Equatable { case positive, negative, uncertain }
struct VerificationCheck: Equatable {
    let title: String
    let value: String
    let tone: VerificationTone
    var accessibilityLabel: String { title + ": " + value }
    var symbol: String { tone == .positive ? "checkmark.circle.fill" : tone == .negative ? "xmark.circle.fill" : "questionmark.circle" }
}
/// Maps existing motor results to labels only. No trust decision is made here.
enum VerificationPresentation {
    static func integrity(_ value: CryptographicIntegrity) -> VerificationCheck {
        .init(title: "Integrità del documento", value: value == .verified ? "Verificata" : value == .invalid ? "Firma alterata o non valida" : value == .absent ? "Firma assente" : "Non determinabile",
              tone: value == .verified ? .positive : value == .invalid ? .negative : .uncertain)
    }
    static func document(_ report: VerificationReport) -> VerificationCheck {
        let outcome = report.documentOutcome
        return .init(title: outcome.title, value: outcome.value,
                     tone: outcome.integrity == .verified ? .positive : outcome.integrity == .invalid ? .negative : .uncertain)
    }
    static func documentList(_ report: VerificationReport) -> VerificationCheck { document(report) }
    static func signatureIntegrity(_ signature: SignatureVerificationResult) -> VerificationCheck {
        let value = integrity(signature.integrity)
        return .init(title: "Integrità della firma", value: value.value, tone: value.tone)
    }
    static func provider(_ path: CertificatePathResult?) -> VerificationCheck {
        let recognized = path?.state == .verified && path?.service != nil
        return .init(title: "Certificatore", value: recognized ? "Riconosciuto nella Trusted List" : path == nil ? "Verifica in corso o non disponibile" : "Non riconosciuto", tone: recognized ? .positive : .uncertain)
    }
    static func revocation(_ state: SignatureRevocationState?) -> VerificationCheck {
        .init(title: "Revoca", value: state == .good ? "Non revocato" : state == .revoked ? "Certificato revocato" : "Indeterminata",
              tone: state == .good ? .positive : state == .revoked ? .negative : .uncertain)
    }
    static func qualification(_ value: SignatureQualificationResult?) -> VerificationCheck {
        guard let value else { return .init(title: "Qualificazione", value: "Indeterminata", tone: .uncertain) }
        let suffix = value.evaluationMode == .currentTime ? "alla data di verifica" : "all’istante comprovato"
        switch value.state {
        case .qualified: return .init(title: "Qualificazione", value: "QES · " + suffix, tone: .positive)
        case .advanced: return .init(title: "Qualificazione", value: "Firma elettronica avanzata · " + suffix, tone: .positive)
        case .electronic: return .init(title: "Qualificazione", value: "Firma elettronica · livello minimo accertato", tone: .uncertain)
        case .indeterminate: return .init(title: "Qualificazione", value: "Indeterminata", tone: .uncertain)
        }
    }
    static func timestamp(_ signature: SignatureVerificationResult, time: SignatureTimeResult?) -> VerificationCheck {
        if time?.state == .proven { return .init(title: "Marca temporale", value: "Presente e verificata", tone: .positive) }
        if time?.state == .invalid { return .init(title: "Marca temporale", value: "Non valida", tone: .negative) }
        let absent = time != nil && signature.evidence?.timestampTokens.isEmpty == true
        return .init(title: "Marca temporale", value: absent ? "Assente" : "Non determinabile", tone: .uncertain)
    }
    static func providerName(_ name: String) -> String {
        // Only names of the authenticated TL provider; never inferred from issuer/CN.
        for brand in ["InfoCamere", "InfoCert", "Aruba", "Namirial", "Actalis"] {
            if name.lowercased().hasPrefix(brand.lowercased()) { return brand }
        }
        return name
    }
    static func declaredInstant(_ raw: String) -> Date? {
        guard raw.utf8.count <= 128 else { return nil }
        if raw.range(of: #"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT\z"#, options: .regularExpression) != nil {
            let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(secondsFromGMT: 0)
            f.dateFormat = "MMM d HH:mm:ss yyyy 'GMT'"; f.isLenient = false
            return f.date(from: raw)
        }
        guard raw.range(of: #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})\z"#, options: .regularExpression) != nil else { return nil }
        let f = ISO8601DateFormatter()
        if raw.contains(".") { f.formatOptions.insert(.withFractionalSeconds) }
        return f.date(from: raw)
    }
    static func localDate(_ date: Date, zone: TimeZone = .current) -> String {
        let f = DateFormatter(); f.locale = .current; f.timeZone = zone
        f.dateStyle = .medium; f.timeStyle = .long
        return f.string(from: date)
    }
    static func declaredDate(_ raw: String) -> String {
        if let instant = declaredInstant(raw) { return localDate(instant) }
        return raw.isEmpty ? "Non disponibile" : raw + " · formato originale"
    }
}
