import Foundation
import SignumCore
import SignumTrustCore
import SignumTrustAuthentication

public enum SignatureQualificationState: String, Sendable {
    case electronic, advanced, qualified, indeterminate
    public var description: String {
        switch self {
        case .electronic: return "Firma elettronica (livello minimo accertato)"
        case .advanced: return "Firma elettronica avanzata"
        case .qualified: return "Firma elettronica qualificata"
        case .indeterminate: return "Indeterminata"
        }
    }
}
public enum QualificationEvidenceState: String, Sendable { case demonstrated, notDemonstrated, indeterminate }
public struct SignatureQualificationResult: Equatable, Sendable {
    public let signatureID: Int
    public let state: SignatureQualificationState
    public let qualifiedCertificate: QualificationEvidenceState
    public let qscd: QualificationEvidenceState
    public let evaluatedAt: Date?
    public let service: CertificateServiceMatch?
    public let reason: String
    public let statements: QCStatements?
    public var serviceStateFromHistory: Bool = false
}
public struct CompleteSignatureValidationResult: Equatable, Sendable {
    public let signatureID: Int
    public let path: CertificatePathResult
    public let evidence: SignatureEvidenceValidationResult
    public let qualification: SignatureQualificationResult
}
/// Consumes C's per-signature assessment in the same invocation; callers cannot
/// attach a result for another document. No new revocation or timestamp verifier.
public struct SignatureQualificationService: Sendable {
    private let evidence: SignatureEvidenceValidationService
    public init(cache: RevocationEvidenceCache? = nil) { evidence = .init(cache:cache) }
    public func validate(_ report: VerificationReport, authenticatedLists: [InterpretedTrustCatalog], mode: RevocationMode = .offline,
                         observedAt: Date = Date(), isCancelled: @escaping @Sendable () -> Bool = { false }) async -> [CompleteSignatureValidationResult] {
        let start = ProcessInfo.processInfo.systemUptime
        let assessments = await evidence.validate(report,authenticatedLists:authenticatedLists,mode:mode,observedAt:observedAt,isCancelled:isCancelled)
        var results = [CompleteSignatureValidationResult]()
        for signature in report.signatures {
            guard !isCancelled(), !Task.isCancelled, let c = assessments.first(where: { $0.signatureID == signature.id }) else { break }
            let clock = observedAt.addingTimeInterval(ProcessInfo.processInfo.systemUptime - start)
            let q = Self.assess(signature,evidence:c,lists:authenticatedLists,mode:mode,observedAt:clock,isCancelled:isCancelled)
            let path = signature.signerDER.map { CertificatePathValidator.evaluate(signer:$0,intermediates:signature.embeddedCertificateDERs,authenticatedLists:authenticatedLists,now:clock,isCancelled:isCancelled) } ?? .unavailable("Certificato DER assente.",now:clock)
            results.append(.init(signatureID:signature.id,path:path,evidence:c,qualification:q))
        }
        guard !isCancelled(), !Task.isCancelled else { return [] }
        // A finite assessment may cross a list expiration; never publish a stale positive.
        let finalClock = observedAt.addingTimeInterval(ProcessInfo.processInfo.systemUptime - start)
        if authenticatedLists.contains(where: { $0.document.nextUpdate <= finalClock }) {
            return results.map { .init(signatureID:$0.signatureID,path:$0.path,evidence:$0.evidence,qualification:.init(signatureID:$0.signatureID,state:.indeterminate,qualifiedCertificate:.indeterminate,qscd:.indeterminate,evaluatedAt:nil,service:nil,reason:"Trusted List scaduta durante la verifica.",statements:$0.qualification.statements)) }
        }
        return results
    }
    static func assess(_ signature: SignatureVerificationResult, evidence: SignatureEvidenceValidationResult, lists inputLists: [InterpretedTrustCatalog],
                       mode: RevocationMode, observedAt: Date, isCancelled: @Sendable () -> Bool = { false }) -> SignatureQualificationResult {
        let lists = inputLists.filter { EuropeanQualificationPolicy.testedCountries.contains($0.document.territory) }
        var qc: QCStatements?, service: CertificateServiceMatch?, at: Date?
        var historyUsed = false
        func result(_ reason: String, _ state: SignatureQualificationState = .indeterminate,
                    _ cert: QualificationEvidenceState = .indeterminate, _ qscd: QualificationEvidenceState = .notDemonstrated) -> SignatureQualificationResult {
            .init(signatureID:signature.id,state:state,qualifiedCertificate:cert,qscd:qscd,evaluatedAt:at,service:service,reason:reason,statements:qc,serviceStateFromHistory:historyUsed)
        }
        guard !isCancelled(), evidence.signatureID == signature.id else { return result("Valutazione annullata o evidenza non associata.") }
        guard signature.integrity == .verified else { return result("Integrità crittografica non verificata: nessuna classificazione positiva.") }
        guard let der = signature.signerDER, let material = try? CertificateQualificationMaterial(der) else { return result("Certificato o QCStatements non interpretabili.") }
        qc = material.qc
        guard evidence.time.state == .proven, let time = evidence.time.provenTime, time <= observedAt else { return result("Tempo non comprovato dalla 0.5-C; signingTime dichiarato non utilizzato.") }
        at = time
        guard time.timeIntervalSince1970 >= 1467324000 else { return result("Regime precedente al 1 luglio 2016 non supportato: qualificazione storica indeterminata.") }
        guard !lists.isEmpty, lists.count <= 32, lists.allSatisfy({ EuropeanQualificationPolicy.testedCountries.contains($0.document.territory) && $0.document.issuedAt <= observedAt && $0.document.nextUpdate > observedAt }) else { return result("Copertura TL autenticata insufficiente, obsoleta o fuori dai Paesi/profili collaudati E2.") }

        let path = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,
            identities:lists.flatMap { CertificatePathValidator.identities($0,now:time) },now:time,isCancelled:isCancelled)
        service = path.service
        guard path.state == .verified, let match = path.service else { return result("Servizio CA/QC non granted o percorso non verificato al tempo comprovato: " + path.reason) }
        guard path.path.count == 2 else { return result("Qualificazione E2 limitata al profilo di emissione diretta CA/QC; catena X.509 distinta.") }
        guard path.alternativeServices.isEmpty else { return result("Più servizi TL applicabili: qualificazione ambigua, nessuna scelta predefinita.") }
        // Select the exact event/identity of the verified anchor, including its OWN extensions.
        var applicable = [[TLServiceExtension]]()
        for list in lists where list.document.territory == match.country && list.document.sequenceNumber == match.listSequence {
            for provider in list.usableProviders where provider.name == match.provider {
                for s in provider.services where s.name == match.service {
                    guard let events = s.timeline(issuedAt:list.document.issuedAt),
                          let e = events.first(where:{ $0.contains(time) }), e.start == match.statusSince,
                          e.typeURI == CertificatePathValidator.caQC, e.statusURI == CertificatePathValidator.granted,
                          TLServiceIdentityResolver.certificates(e,service:s).contains(where:{ CertificatePathValidator.hash($0) == match.identitySHA256 }) else { continue }
                    // Issuance is correlated with its OWN state, not today's qualifiers.
                    guard let issuance = events.first(where:{ $0.contains(material.notBefore) }) else {
                        return result("Lo storico TL non copre l’emissione del certificato.")
                    }
                    guard HistoricalQualification.covers(events,service:s,identity:match.identitySHA256,material:material,proof:time) else {
                        return result("Transizione di identità, stato o qualificatori fra emissione e tempo comprovato: evidenze storiche insufficienti.")
                    }
                    historyUsed = e.fromHistory || issuance.fromHistory
                    applicable.append(e.extensions)
                }
            }
        }
        guard applicable.count == 1 else { return result("Stato/identità del servizio TL non univoci.") }
        guard evidence.revocation.state == .good else { return result(evidence.revocation.state == .revoked ? "Revoca accertata: nessuna classificazione QES." : "Revoca indeterminata: evidenze insufficienti per QES.") }
        guard let revocationPath = evidence.revocationPath, revocationPath.state == .verified, revocationPath.evaluatedAt == time,
              revocationPath.path.map(\.sha256) == path.path.map(\.sha256) else {
            return result("Revoca C non associata al percorso valutato al tempo comprovato; verifica storica indeterminata.")
        }
        guard let authority = evidence.time.authorities.first(where: { $0.state == .authorized && $0.latestTime == time }),
              authority.service.map({ EuropeanQualificationPolicy.testedCountries.contains($0.country) }) == true,
              let earliest = authority.earliestTime, earliest <= time,
              !evidence.revocation.certificates.isEmpty, evidence.revocation.certificates.allSatisfy({ $0.state == .good && ($0.thisUpdate.map { $0 <= earliest } ?? false) && ($0.nextUpdate.map { $0 >= observedAt } ?? false) }) else { return result("Evidenze di revoca non coprono l’intera finestra temporale comprovata.") }
        let earlyPath = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,identities:lists.flatMap { CertificatePathValidator.identities($0,now:earliest) },now:earliest,isCancelled:isCancelled)
        guard earlyPath.state == .verified, earlyPath.service == path.service, earlyPath.path == path.path else { return result("Percorso o stato TL variabile nella finestra di accuratezza: indeterminato.") }
        guard material.qc.unsupported.isEmpty, material.qc.issue.isEmpty else { return result("QCStatements ulteriori o malformati non supportati.") }
        guard let qualifiers = TLQualificationRules.evaluate(applicable[0],material:material) else { return result("Qualificatori, criteri o estensioni critiche TL non supportati o ambigui.") }
        let has: (String)->Bool = { qualifiers.contains(TLQualificationRules.prefix + $0) }
        guard !(has("QCStatement") && has("NotQualified")), !(has("QCWithQSCD") && has("QCNoQSCD")),
              !(["QCNoQSCD","QCNoSSCD"].contains(where:has) && material.qc.sscd), !(has("NotQualified") && material.qc.compliance),
              !has("QCQSCDManagedOnBehalf") else { return result("Evidenze TL/certificato contrastanti o QSCD gestito per conto non supportato.") }
        guard material.qc.compliance || has("QCStatement") || !material.policies.contains(where: { $0.hasPrefix("0.4.0.1456.") || $0.hasPrefix("0.4.0.194112.") }) else { return result("Determinazione mediante policy QCP/legacy non supportata; nessuna classificazione dedotta dalle sole policy.") }
        let qualified = (material.qc.compliance || has("QCStatement")) && !has("NotQualified")
        if !qualified { return result("Certificato non qualificato nel profilo supportato. Accertata solo firma elettronica; requisiti di firma avanzata non dimostrati.",.electronic,.notDemonstrated) }
        guard !has("QCForESeal"), !has("QCForWSA"), !has("QCForLegalPerson"), material.qc.types == ["0.4.0.1862.1.6.1"] || (has("QCForESig") && material.qc.types.isEmpty) else { return result("Tipo di certificato non univocamente per firma elettronica (sigillo/web/legacy non risolti).",.indeterminate,.demonstrated) }
        let device = TLQualificationRules.deviceEvidence(qualifiers:qualifiers,sscd:material.qc.sscd,policies:material.policies,at:time)
        if device == .indeterminate { return result("Evidenze SSCD/QSCD incompatibili, di altro regime o insufficienti.",.indeterminate,.demonstrated,.indeterminate) }
        guard device == .yes else { return result("Certificato qualificato per firma; QSCD non dimostrato. Nessuna classificazione QES o avanzata automatica.",.indeterminate,.demonstrated) }
        guard material.keyUsage["nonRepudiation"] == true else { return result("Profilo del certificato: Key Usage contentCommitment non dimostrato.",.indeterminate,.demonstrated,.demonstrated) }
        return result("Profilo QES verificato al limite superiore del tempo comprovato: integrità, percorso CA/QC granted, revoca, certificato per firma e QSCD. Nessuna attestazione LTV o accettabilità delle modifiche successive.",.qualified,.demonstrated,.demonstrated)
    }
}
