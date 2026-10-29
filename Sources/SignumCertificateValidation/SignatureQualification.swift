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
/// Historical E2 remains the API default; bestAvailable never treats a
/// declared signingTime as proof and resolves independently for every signer.
public enum SignatureEvaluationMode: String, Sendable {
    case historical, currentTime, bestAvailable
    func resolved(for time: SignatureTimeResult) -> Self {
        self == .bestAvailable ? (time.state == .proven ? .historical : .currentTime) : self
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
    public var evaluationMode: SignatureEvaluationMode = .historical
    public var verificationDate: Date? = nil
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
    private let cache: RevocationEvidenceCache?
    private let transport: any RevocationTransport
    private let monotonicClock: @Sendable () -> TimeInterval
    public init(cache: RevocationEvidenceCache? = nil) {
        self.init(cache: cache, transport: SystemRevocationTransport())
    }
    init(cache: RevocationEvidenceCache? = nil, transport: any RevocationTransport,
         monotonicClock: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.cache = cache; self.transport = transport; self.monotonicClock = monotonicClock
        evidence = .init(cache: cache, transport: transport)
    }
    public func validate(_ report: VerificationReport, authenticatedLists: [InterpretedTrustCatalog], mode: RevocationMode = .offline,
                         observedAt: Date = Date(), evaluationMode: SignatureEvaluationMode = .historical, isCancelled: @escaping @Sendable () -> Bool = { false }) async -> [CompleteSignatureValidationResult] {
        let start = monotonicClock()
        let session = RevocationSession(cache: cache, transport: transport, advancesClock: mode == .online)
        var assessmentAt = observedAt
        var assessments = await evidence.validate(report,authenticatedLists:authenticatedLists,mode:mode,observedAt:observedAt,
            evaluationMode:evaluationMode,isCancelled:isCancelled,session:session)
        if mode == .online, await session.requests > 0, !isCancelled(), !Task.isCancelled {
            // Acquisition is not the assessment. Freeze a later observation and
            // reauthenticate raw DER, paths, responder validity and TL at that instant.
            // No extra network requests, clock-skew allowance or future acceptance.
            assessmentAt = observedAt.addingTimeInterval(max(0, monotonicClock() - start))
            let replay = RevocationSession(cache: cache, transport: transport, localEvidence: await session.fetchedEvidence, advancesClock: false)
            assessments = await evidence.validate(report,authenticatedLists:authenticatedLists,mode:.offline,observedAt:assessmentAt,
                evaluationMode:evaluationMode,isCancelled:isCancelled,session:replay)
        }
        var results = [CompleteSignatureValidationResult]()
        for signature in report.signatures {
            guard !isCancelled(), !Task.isCancelled, let c = assessments.first(where: { $0.signatureID == signature.id }) else { break }
            // One fixed observation instant binds current path, revocation and qualification.
            let q = Self.assess(signature,evidence:c,lists:authenticatedLists,mode:mode,observedAt:assessmentAt,evaluationMode:evaluationMode,isCancelled:isCancelled)
            let path = signature.signerDER.map { CertificatePathValidator.evaluate(signer:$0,intermediates:signature.embeddedCertificateDERs,authenticatedLists:authenticatedLists,now:assessmentAt,isCancelled:isCancelled) } ?? .unavailable("Certificato DER assente.",now:assessmentAt)
            results.append(.init(signatureID:signature.id,path:path,evidence:c,qualification:q))
        }
        guard !isCancelled(), !Task.isCancelled else { return [] }
        // A finite assessment may cross a list expiration; never publish a stale positive.
        let finalClock = observedAt.addingTimeInterval(max(0, monotonicClock() - start))
        return results.map { value in
            let expired = authenticatedLists.contains { $0.document.nextUpdate <= finalClock } ||
                (value.qualification.evaluationMode == .currentTime && value.evidence.revocation.certificates.contains { ($0.nextUpdate ?? .distantPast) <= finalClock })
            guard expired else { return value }
            return .init(signatureID:value.signatureID,path:value.path,evidence:value.evidence,qualification:.init(signatureID:value.signatureID,state:.indeterminate,qualifiedCertificate:.indeterminate,qscd:.indeterminate,evaluatedAt:nil,service:nil,reason:"Trusted List o evidenza di revoca scaduta durante la verifica.",statements:value.qualification.statements,evaluationMode:value.qualification.evaluationMode,verificationDate:assessmentAt))
        }
    }
    static func assess(_ signature: SignatureVerificationResult, evidence: SignatureEvidenceValidationResult, lists inputLists: [InterpretedTrustCatalog],
                       mode: RevocationMode, observedAt: Date, evaluationMode requestedMode: SignatureEvaluationMode = .historical, isCancelled: @Sendable () -> Bool = { false }) -> SignatureQualificationResult {
        let lists = inputLists.filter { EuropeanQualificationPolicy.testedCountries.contains($0.document.territory) }
        var qc: QCStatements?, service: CertificateServiceMatch?, at: Date?
        let evaluationMode = requestedMode.resolved(for:evidence.time)
        var historyUsed = false
        func result(_ reason: String, _ state: SignatureQualificationState = .indeterminate,
                    _ cert: QualificationEvidenceState = .indeterminate, _ qscd: QualificationEvidenceState = .indeterminate) -> SignatureQualificationResult {
            .init(signatureID:signature.id,state:state,qualifiedCertificate:cert,qscd:qscd,evaluatedAt:at,service:service,reason:reason,statements:qc,serviceStateFromHistory:historyUsed,evaluationMode:evaluationMode,verificationDate:observedAt)
        }
        guard !isCancelled(), evidence.signatureID == signature.id else { return result("Valutazione annullata o evidenza non associata.") }
        guard signature.integrity == .verified else { return result("Integrità crittografica non verificata: nessuna classificazione positiva.") }
        guard let der = signature.signerDER, let material = try? CertificateQualificationMaterial(der) else { return result("Certificato o QCStatements non interpretabili.") }
        qc = material.qc
        let time: Date
        if evaluationMode == .currentTime {
            at = observedAt
            guard evidence.time.state != .invalid else { return result("Marca temporale non valida: nessuna promozione automatica alla valutazione corrente.") }
            time = observedAt
        } else {
            guard evidence.time.state == .proven, let provenTime = evidence.time.provenTime, provenTime <= observedAt else { return result("Tempo non comprovato nel profilo Signum: signingTime è dichiarato e non è una prova temporale. QCStatements del certificato: QcCompliance \(material.qc.compliance ? "presente" : "assente"), QcSSCD \(material.qc.sscd ? "presente" : "assente"). Qualificazione e QSCD della firma non determinati al tempo di apposizione.") }
            time = provenTime
            at = time
        }
        guard time.timeIntervalSince1970 >= 1467324000 else { return result("Regime precedente al 1 luglio 2016 non supportato: qualificazione storica indeterminata.") }
        guard !lists.isEmpty, lists.count <= 32, lists.allSatisfy({ EuropeanQualificationPolicy.testedCountries.contains($0.document.territory) && $0.document.issuedAt <= observedAt && $0.document.nextUpdate > observedAt }) else { return result("Copertura TL autenticata insufficiente, obsoleta o fuori dai Paesi/profili collaudati E2.") }

        let path = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,
            identities:lists.flatMap { CertificatePathValidator.identities($0,now:time) },now:time,isCancelled:isCancelled)
        service = path.service
        guard path.state == .verified, let match = path.service else { return result("Servizio CA/QC non granted o percorso non verificato all’istante valutato: " + path.reason) }
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
                        return result("Transizione di identità, stato o qualificatori fra emissione e istante valutato: evidenze storiche insufficienti.")
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
            return result("Revoca non associata allo stesso percorso e istante valutato: qualificazione indeterminata.")
        }
        if evaluationMode == .currentTime {
            guard !evidence.revocation.certificates.isEmpty,
                  evidence.revocation.certificates.count >= path.path.count - 1,
                  evidence.revocation.certificates.allSatisfy({
                      $0.state == .good && $0.evaluatedAt >= observedAt &&
                      ($0.thisUpdate.map { $0 <= observedAt } ?? false) &&
                      ($0.nextUpdate.map { $0 > observedAt } ?? false)
                  }) else { return result("Revoca corrente non dimostrata all’istante di verifica: evidenze mancanti, obsolete o non pertinenti.") }
        } else {
            guard let authority = evidence.time.authorities.first(where: { $0.state == .authorized && $0.latestTime == time }),
                  authority.service.map({ EuropeanQualificationPolicy.testedCountries.contains($0.country) }) == true,
                  let earliest = authority.earliestTime, earliest <= time,
                  !evidence.revocation.certificates.isEmpty, evidence.revocation.certificates.allSatisfy({ $0.state == .good && ($0.thisUpdate.map { $0 <= earliest } ?? false) && ($0.nextUpdate.map { $0 >= observedAt } ?? false) }) else { return result("Evidenze di revoca non coprono l’intera finestra temporale comprovata.") }
            let earlyPath = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,identities:lists.flatMap { CertificatePathValidator.identities($0,now:earliest) },now:earliest,isCancelled:isCancelled)
            guard earlyPath.state == .verified, earlyPath.service == path.service, earlyPath.path == path.path else { return result("Percorso o stato TL variabile nella finestra di accuratezza: indeterminato.") }
        }
        guard material.qc.unsupported.isEmpty, material.qc.issue.isEmpty else { return result("QCStatements ulteriori o malformati non supportati.") }
        guard let qualifiers = TLQualificationRules.evaluate(applicable[0],material:material) else { return result("Qualificatori, criteri o estensioni critiche TL non supportati o ambigui.") }
        let has: (String)->Bool = { qualifiers.contains(TLQualificationRules.prefix + $0) }
        guard !(has("QCStatement") && has("NotQualified")), !(has("QCWithQSCD") && has("QCNoQSCD")),
              !(["QCNoQSCD","QCNoSSCD"].contains(where:has) && material.qc.sscd), !(has("NotQualified") && material.qc.compliance),
              !has("QCQSCDManagedOnBehalf") else { return result("Evidenze TL/certificato contrastanti o QSCD gestito per conto non supportato.") }
        guard material.qc.compliance || has("QCStatement") || !material.policies.contains(where: { $0.hasPrefix("0.4.0.1456.") || $0.hasPrefix("0.4.0.194112.") }) else { return result("Determinazione mediante policy QCP/legacy non supportata; nessuna classificazione dedotta dalle sole policy.") }
        let qualified = (material.qc.compliance || has("QCStatement")) && !has("NotQualified")
        if !qualified { return result("Certificato non qualificato nel profilo supportato. Accertata solo firma elettronica; requisiti di firma avanzata non dimostrati.",.electronic,.notDemonstrated,.notDemonstrated) }
        guard !has("QCForESeal"), !has("QCForWSA"), !has("QCForLegalPerson"), material.qc.types == ["0.4.0.1862.1.6.1"] || (has("QCForESig") && material.qc.types.isEmpty) else { return result("Tipo di certificato non univocamente per firma elettronica (sigillo/web/legacy non risolti).",.indeterminate,.demonstrated) }
        let device = TLQualificationRules.deviceEvidence(qualifiers:qualifiers,sscd:material.qc.sscd,policies:material.policies,at:time)
        if device == .indeterminate { return result("Evidenze SSCD/QSCD incompatibili, di altro regime o insufficienti.",.indeterminate,.demonstrated,.indeterminate) }
        guard device == .yes else { return result("Certificato qualificato per firma; QSCD non dimostrato. Nessuna classificazione QES o avanzata automatica.",.indeterminate,.demonstrated,.notDemonstrated) }
        guard material.keyUsage["nonRepudiation"] == true else { return result("Profilo del certificato: Key Usage contentCommitment non dimostrato.",.indeterminate,.demonstrated,.demonstrated) }
        return result((evaluationMode == .currentTime ? "Profilo QES verificato alla data corrente di verifica, senza attestazione dell’istante di apposizione: " : "Profilo QES verificato al limite superiore del tempo comprovato: ") + " integrità, percorso CA/QC granted, revoca, certificato per firma e QSCD. Nessuna attestazione LTV o accettabilità delle modifiche successive.",.qualified,.demonstrated,.demonstrated)
    }
}
