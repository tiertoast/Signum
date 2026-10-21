#if os(macOS)
import Foundation

public enum VerifiedDocumentFormat: String, Codable, Sendable { case cades, pades, xml, asic, unknown }
public enum CryptographicIntegrity: String, Codable, Sendable {
    case verified, invalid, notVerifiable, absent
    public var description: String {
        switch self {
        case .verified: return "Integrità crittografica verificata"
        case .invalid: return "Integrità crittografica non valida"
        case .notVerifiable: return "Impossibile verificare l'integrità"
        case .absent: return "Firma assente"
        }
    }
}
public enum UnassessedValidation: String, Codable, Sendable { case notChecked }
public struct SignerCertificateSummary: Equatable, Sendable {
    public let subject: String, issuer: String, sha256: String
}
public struct SignatureVerificationResult: Identifiable, Equatable, Sendable {
    public let id: Int
    public let integrity: CryptographicIntegrity
    public let certificate: SignerCertificateSummary?
    public let algorithm: String, declaredTime: String, reason: String
    public let signedRevisionEnd: Int?
    public let laterChanges: Bool
    public let cmsLayer: Int
    public var evidence: SignatureEvidenceEnvelope? = nil
    public var signerDER: Data? = nil
    public var embeddedCertificateDERs: [Data] = []
    public let trust = UnassessedValidation.notChecked
    public let revocation = UnassessedValidation.notChecked
    public let qualification = UnassessedValidation.notChecked
}
public struct VerificationReport: Identifiable, Sendable {
    public let id: UUID
    public let documentName: String, sha256: String
    public let format: VerifiedDocumentFormat
    public let signatures: [SignatureVerificationResult]
    public let documentState: String, issue: String
    /// Only a PDF candidate from immutable input or a fully verified CMS payload.
    /// Never written beside the source and never opened as an executable attachment.
    public let previewPDF: Data?
    public let originalContent: Data?
    public let trust = UnassessedValidation.notChecked
    public let revocation = UnassessedValidation.notChecked
    public let qualification = UnassessedValidation.notChecked
    public var unassociatedEvidence: [EmbeddedValidationEvidence] = []
    public static let scope = "Attendibilità del certificato non ancora verificata. Revoca, qualificazione eIDAS, marche temporali e LTV non valutate."
    public static let revisionScope = "Le modifiche successive sono rilevate come byte aggiunti: conformità DocMDP/FieldMDP e accettabilità delle revisioni non valutate. Sono esaminate le firme raggiungibili dall'AcroForm corrente, fino a 32."
    public var integrity: CryptographicIntegrity {
        guard documentState != "damaged", documentState != "unsupported" else { return .notVerifiable }
        if documentState == "unsigned" { return .absent }
        guard !signatures.isEmpty else { return .notVerifiable }
        if signatures.contains(where: { $0.integrity == .invalid }) { return .invalid }
        return signatures.allSatisfy { $0.integrity == .verified } ? .verified : .notVerifiable
    }
    public var summary: String {
        if documentState == "damaged" { return "Documento danneggiato o struttura non supportata" }
        if documentState == "unsupported" { return "Formato non supportato" }
        if format == .pades && integrity == .absent { return "PDF non firmato" }
        return integrity.description
    }
    public func withoutPreview() -> Self {
        var copy = Self(id: id, documentName: documentName, sha256: sha256, format: format,
              signatures: signatures, documentState: documentState, issue: issue, previewPDF: nil, originalContent: nil)
        copy.unassociatedEvidence = unassociatedEvidence
        return copy
    }
}

/// Conservative, bounded hints only. The isolated native parser determines the
/// actual format and validates its structure; filename extensions are ignored.
public enum SignatureFormatDetector {
    public static func candidate(_ bytes: Data) -> VerifiedDocumentFormat {
        let head = bytes.prefix(1024)
        if head.starts(with:[0x50,0x4b,0x03,0x04]) { return .asic }
        if head.first == 0x30 { return .cades }
        if head.range(of: Data("%PDF-".utf8)) != nil { return .pades }
        let text = String(decoding: head, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn:"\u{feff}")))
        return text.hasPrefix("<") ? .xml : .unknown
    }
}

public enum SignumVerificationService {
    public static let maximumInputBytes = SigningResourceLimits.maximumOutputBytes
    public static var bundledHelper: URL {
        let bundle = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/signum-pades-local")
        if FileManager.default.isExecutableFile(atPath: bundle.path) { return bundle }
        return URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("signum-pades-local")
    }
    private struct WireSignature: Decodable {
        let integrity: CryptographicIntegrity
        let reason, subject, issuer, fingerprint, algorithm, declaredTime: String
        let revisionEnd, layer: Int
        let laterChanges: Bool
        let signerDER: String?
        let certificateDERs: [String]?
        let signatureValue, signatureKey, evidenceIssue: String?
        let signerIndex: Int?
        let signedAttributes, unsignedAttributes: [ExtractedCMSAttribute]?
        let timestampTokens: [Data]?
        let evidence: [EmbeddedValidationEvidence]?
    }
    private struct WireReport: Decodable {
        let version: Int
        let format: VerifiedDocumentFormat
        let state, reason: String
        let signatures: [WireSignature]
        let previewablePDF: Bool
        let unassociatedEvidence: [EmbeddedValidationEvidence]?
    }
    private static func validEvidence(_ e: EmbeddedValidationEvidence, inputSize: Int) -> Bool {
        !e.der.isEmpty && e.der.count <= 1024*1024 && e.source.utf8.count <= 128 &&
        (e.signatureKey.isEmpty || (e.signatureKey.count == 64 && e.signatureKey.allSatisfy { $0.isHexDigit })) &&
        (0...inputSize).contains(e.signatureRevisionEnd) && (0...inputSize).contains(e.sourceRevisionEnd)
    }
    public static func verify(file: URL, helper: URL? = nil, timeout: TimeInterval = 30,
                              isCancelled: () -> Bool = { false }) throws -> VerificationReport {
        if isCancelled() { throw SupervisedProcess.Failure.cancelled }
        return try verify(data: CAdESVerifier.readInput(file: file), name: file.lastPathComponent,
                          helper: helper, timeout: timeout, isCancelled: isCancelled)
    }
    public static func verify(data: Data, name: String, helper: URL? = nil, timeout: TimeInterval = 30,
                              isCancelled: () -> Bool = { false }) throws -> VerificationReport {
        guard !data.isEmpty, data.count <= maximumInputBytes else { throw SignumError.module("Documento vuoto o superiore a 132 MiB.") }
        if SignatureFormatDetector.candidate(data) == .asic {
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            let report = ASiC.report(data,name:name)
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            return report
        }
        if SignatureFormatDetector.candidate(data) == .xml {
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            let report = XAdES.report(data,name:name)
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            return report
        }
        let engine = helper ?? bundledHelper
        guard FileManager.default.isExecutableFile(atPath: engine.path) else {
            throw SignumError.module("Motore di verifica non presente nel bundle. Nessun middleware o PIN è necessario.")
        }
        var input = data
        let output = try SupervisedProcess.run(executable: engine, arguments: ["--verify-stdin-v1"], input: &input,
            maximumInput: maximumInputBytes, maximumOutput: maximumInputBytes + 8*1024*1024 + 8,
            maximumResidentBytes: 1024*1024*1024,
            timeout: timeout, isCancelled: isCancelled)
        guard output.count >= 8 else { throw SupervisedProcess.Failure.protocolViolation }
        func count(_ offset: Int) -> Int { output[offset..<offset+4].reduce(0) { ($0 << 8) | Int($1) } }
        let metadataLength = count(0), contentLength = count(4)
        guard metadataLength > 0, metadataLength <= 8*1024*1024, contentLength <= maximumInputBytes,
              output.count == 8 + metadataLength + contentLength else { throw SupervisedProcess.Failure.protocolViolation }
        let wire = try JSONDecoder().decode(WireReport.self, from: output.subdata(in: 8..<8+metadataLength))
        guard wire.version == 1, ["signed","unsigned","damaged","unsupported"].contains(wire.state),
              wire.reason.utf8.count <= 8192, wire.signatures.count <= 32,
              wire.state != "signed" || !wire.signatures.isEmpty,
              wire.signatures.allSatisfy({ (1...5).contains($0.layer) && (0...data.count).contains($0.revisionEnd) &&
                  [$0.reason,$0.subject,$0.issuer,$0.algorithm,$0.declaredTime].allSatisfy({ $0.utf8.count <= 8192 }) &&
                  ($0.fingerprint.isEmpty || ($0.fingerprint.count == 64 && $0.fingerprint.allSatisfy { $0.isHexDigit })) &&
                  ($0.integrity != .verified || !$0.fingerprint.isEmpty) }) else { throw SupervisedProcess.Failure.protocolViolation }
        let records = try wire.signatures.enumerated().map { i, s in
            var record = SignatureVerificationResult(id: i, integrity: s.integrity,
                certificate: s.fingerprint.isEmpty ? nil : .init(subject: s.subject, issuer: s.issuer, sha256: s.fingerprint),
                algorithm: s.algorithm, declaredTime: s.declaredTime, reason: s.reason,
                signedRevisionEnd: s.revisionEnd == 0 ? nil : s.revisionEnd, laterChanges: s.laterChanges, cmsLayer: s.layer)
            if let encoded = s.signerDER, !encoded.isEmpty {
                guard let der = Data(base64Encoded: encoded), der.count <= 65536,
                      DocumentSnapshot.digest(der) == s.fingerprint else { throw SupervisedProcess.Failure.protocolViolation }
                record.signerDER = der
            }
            guard (s.certificateDERs?.count ?? 0) <= 64 else { throw SupervisedProcess.Failure.protocolViolation }
            record.embeddedCertificateDERs = try (s.certificateDERs ?? []).map {
                guard let der = Data(base64Encoded: $0), !der.isEmpty, der.count <= 65536 else { throw SupervisedProcess.Failure.protocolViolation }
                return der
            }
            if let encoded = s.signatureValue, !encoded.isEmpty {
                guard let value = Data(base64Encoded: encoded), !value.isEmpty, value.count <= 16384,
                      s.signatureKey == DocumentSnapshot.digest(value), let signerIndex = s.signerIndex, (0..<32).contains(signerIndex),
                      (s.signedAttributes?.count ?? 0) <= 64, (s.unsignedAttributes?.count ?? 0) <= 64,
                      (s.timestampTokens?.count ?? 0) <= 4, (s.evidence?.count ?? 0) <= 64,
                      (s.evidenceIssue?.utf8.count ?? 0) <= 8192,
                      ((s.signedAttributes ?? []) + (s.unsignedAttributes ?? [])).allSatisfy({ !$0.der.isEmpty && $0.der.count <= 1024*1024 && $0.oid.utf8.count <= 128 }),
                      (s.timestampTokens ?? []).allSatisfy({ !$0.isEmpty && $0.count <= 1024*1024 }),
                      (s.evidence ?? []).allSatisfy({ validEvidence($0, inputSize: data.count) }) else { throw SupervisedProcess.Failure.protocolViolation }
                record.evidence = .init(signatureValue: value, signatureKey: s.signatureKey!, signerIndex: signerIndex,
                    signedAttributes: s.signedAttributes ?? [], unsignedAttributes: s.unsignedAttributes ?? [],
                    timestampTokens: s.timestampTokens ?? [], embedded: s.evidence ?? [], issue: s.evidenceIssue ?? "")
            }
            return record
        }
        var preview: Data?, original: Data?
        if wire.format == .pades && ["signed","unsigned"].contains(wire.state) { preview = data }
        else if wire.format == .cades && wire.state == "signed" && records.allSatisfy({$0.integrity == .verified}) && contentLength > 0 {
            let content = output.subdata(in: 8+metadataLength..<output.count)
            original = content
            if wire.previewablePDF && SignatureFormatDetector.candidate(content) == .pades { preview = content }
        }
        guard (wire.unassociatedEvidence?.count ?? 0) <= 64,
              (wire.unassociatedEvidence ?? []).allSatisfy({ validEvidence($0, inputSize: data.count) && $0.association == .unassociated }) else { throw SupervisedProcess.Failure.protocolViolation }
        var result = VerificationReport(id: UUID(), documentName: name, sha256: DocumentSnapshot.digest(data), format: wire.format,
            signatures: records, documentState: wire.state, issue: wire.reason, previewPDF: preview, originalContent: original)
        result.unassociatedEvidence = wire.unassociatedEvidence ?? []
        return result
    }
}
#endif
