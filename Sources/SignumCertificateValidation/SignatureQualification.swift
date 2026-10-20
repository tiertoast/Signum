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
    public func validate(_ report: VerificationReport, authenticatedLists: [AuthenticatedTL], mode: RevocationMode = .offline,
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
    static func assess(_ signature: SignatureVerificationResult, evidence: SignatureEvidenceValidationResult, lists: [AuthenticatedTL],
                       mode: RevocationMode, observedAt: Date, isCancelled: @Sendable () -> Bool = { false }) -> SignatureQualificationResult {
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
        guard mode == .online else { return result("Modalità offline: qualificazione indeterminata; i risultati locali di integrità, catena, revoca e tempo restano separati.") }
        guard evidence.time.state == .proven, let time = evidence.time.provenTime, time <= observedAt else { return result("Tempo non comprovato dalla 0.5-C; signingTime dichiarato non utilizzato.") }
        at = time
        guard time.timeIntervalSince1970 >= 1467324000 else { return result("Regime precedente al 1 luglio 2016 non supportato: qualificazione storica indeterminata.") }
        guard !lists.isEmpty, lists.count <= 32, lists.allSatisfy({ $0.document.territory == "IT" && $0.document.issuedAt <= observedAt && $0.document.nextUpdate > observedAt }) else { return result("Copertura TL autenticata insufficiente o obsoleta: profilo attuale limitato all’Italia.") }

        let path = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,
            identities:lists.flatMap { CertificatePathValidator.identities($0.document,now:time) },now:time,isCancelled:isCancelled)
        service = path.service
        guard path.state == .verified, let match = path.service else { return result("Servizio CA/QC non granted o percorso non verificato al tempo comprovato: " + path.reason) }
        guard path.alternativeServices.isEmpty else { return result("Più servizi TL applicabili: qualificazione ambigua, nessuna scelta predefinita.") }
        // Select the exact event/identity of the verified anchor, including its OWN extensions.
        struct Event { let start: Date; let type: String, status: String; let certs: [Data]; let extensions: [TLServiceExtension] }
        var applicable = [[TLServiceExtension]]()
        for list in lists where list.document.territory == match.country && list.document.sequenceNumber == match.listSequence {
            for provider in list.document.providers where provider.name == match.provider {
                for s in provider.services where s.name == match.service {
                    var events = s.history.map { Event(start:$0.statusSince,type:$0.typeURI,status:$0.statusURI,certs:$0.certificateDERs,extensions:$0.extensions) }
                    events.append(.init(start:s.statusSince,type:s.typeURI,status:s.statusURI,certs:s.certificateDERs,extensions:s.extensions))
                    guard Set(events.map(\.start)).count == events.count else { continue }
                    events.sort { $0.start < $1.start }
                    guard let e = events.last(where: { $0.start <= time }), e.start == match.statusSince,
                          e.type == CertificatePathValidator.caQC, e.status == CertificatePathValidator.granted,
                          e.certs.contains(where: { CertificatePathValidator.hash($0) == match.identitySHA256 }) else { continue }
                    // Conservative subset: no inference across a service/identity/qualifier transition.
                    // Issuance and proof must be covered by this same authenticated event.
                    guard material.notBefore >= e.start else { return result("Lo storico TL non copre emissione e tempo comprovato nello stesso stato del servizio; profilo storico non supportato.") }
                    historyUsed = e.start < s.statusSince
                    applicable.append(e.extensions)
                }
            }
        }
        guard applicable.count == 1 else { return result("Stato/identità del servizio TL non univoci.") }
        guard evidence.revocation.state == .good else { return result(evidence.revocation.state == .revoked ? "Revoca accertata: nessuna classificazione QES." : "Revoca indeterminata: evidenze insufficienti per QES.") }
        let currentPath = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,authenticatedLists:lists,now:observedAt,isCancelled:isCancelled)
        guard currentPath.state == .verified, currentPath.path.map(\.sha256) == path.path.map(\.sha256) else { return result("Revoca C e percorso al tempo comprovato non coprono lo stesso percorso; verifica storica indeterminata.") }
        guard let authority = evidence.time.authorities.first(where: { $0.state == .authorized && $0.latestTime == time }),
              let earliest = authority.earliestTime, earliest <= time,
              !evidence.revocation.certificates.isEmpty, evidence.revocation.certificates.allSatisfy({ $0.state == .good && ($0.thisUpdate.map { $0 <= earliest } ?? false) && ($0.nextUpdate.map { $0 >= observedAt } ?? false) }) else { return result("Evidenze di revoca non coprono l’intera finestra temporale comprovata.") }
        let earlyPath = CertificatePathValidator.evaluate(signer:der,intermediates:signature.embeddedCertificateDERs,identities:lists.flatMap { CertificatePathValidator.identities($0.document,now:earliest) },now:earliest,isCancelled:isCancelled)
        guard earlyPath.state == .verified, earlyPath.service == path.service, earlyPath.path == path.path else { return result("Percorso o stato TL variabile nella finestra di accuratezza: indeterminato.") }
        guard material.qc.unsupported.isEmpty, material.qc.issue.isEmpty else { return result("QCStatements ulteriori o malformati non supportati.") }
        guard let qualifiers = TLQualificationRules.evaluate(applicable[0],material:material) else { return result("Qualificatori, criteri o estensioni critiche TL non supportati o ambigui.") }
        let has: (String)->Bool = { qualifiers.contains(TLQualificationRules.prefix + $0) }
        guard !(has("QCStatement") && has("NotQualified")), !(has("QCWithQSCD") && has("QCNoQSCD")),
              !(has("QCNoQSCD") && material.qc.sscd), !(has("NotQualified") && material.qc.compliance),
              !has("QCQSCDManagedOnBehalf") else { return result("Evidenze TL/certificato contrastanti o QSCD gestito per conto non supportato.") }
        guard material.qc.compliance || has("QCStatement") || !material.policies.contains(where: { $0.hasPrefix("0.4.0.1456.") || $0.hasPrefix("0.4.0.194112.") }) else { return result("Determinazione mediante policy QCP/legacy non supportata; nessuna classificazione dedotta dalle sole policy.") }
        let qualified = (material.qc.compliance || has("QCStatement")) && !has("NotQualified")
        if !qualified { return result("Certificato non qualificato nel profilo supportato. Accertata solo firma elettronica; requisiti di firma avanzata non dimostrati.",.electronic,.notDemonstrated) }
        guard !has("QCForESeal"), !has("QCForWSA"), material.qc.types == ["0.4.0.1862.1.6.1"] || (has("QCForESig") && material.qc.types.isEmpty) else { return result("Tipo di certificato non univocamente per firma elettronica (sigillo/web/legacy non risolti).",.indeterminate,.demonstrated) }
        let qscd = material.qc.sscd || has("QCWithQSCD")
        guard qscd, !has("QCNoQSCD") else { return result("Certificato qualificato per firma; QSCD non dimostrato. Nessuna classificazione QES o avanzata automatica.",.indeterminate,.demonstrated) }
        guard material.keyUsage["nonRepudiation"] == true else { return result("Profilo del certificato: Key Usage contentCommitment non dimostrato.",.indeterminate,.demonstrated,.demonstrated) }
        return result("Profilo QES verificato al limite superiore del tempo comprovato: integrità, percorso CA/QC granted, revoca, certificato per firma e QSCD. Nessuna attestazione LTV o accettabilità delle modifiche successive.",.qualified,.demonstrated,.demonstrated)
    }
}

enum TLQualificationRules {
    static let tl = "http://uri.etsi.org/02231/v2#"
    static let sie = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
    static let xades = "http://uri.etsi.org/01903/v1.3.2#"
    static let prefix = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/"
    static func evaluate(_ extensions: [TLServiceExtension], material: CertificateQualificationMaterial) -> Set<String>? {
        var output = Set<String>()
        let known = Set(["QCStatement","NotQualified","QCForESig","QCForESeal","QCForWSA","QCWithQSCD","QCNoQSCD","QCQSCDStatusAsInCert","QCQSCDManagedOnBehalf"].map { prefix+$0 })
        for ext in extensions {
            guard ext.namespace == tl, ext.name == "Extension", ext.children.count == 1,
                  ["true","false","1","0"].contains(ext.attributes["Critical"] ?? "") else { return nil }
            let child = ext.children[0]
            if child.namespace == sie && child.name == "Qualifications" {
                guard !child.children.isEmpty else { return nil }
                for rule in child.children {
                    guard rule.namespace == sie, rule.name == "QualificationElement", rule.children.count == 2,
                          rule.children[0].namespace == sie, rule.children[0].name == "Qualifiers",
                          rule.children[1].namespace == sie, rule.children[1].name == "CriteriaList" else { return nil }
                    guard let applies = criteria(rule.children[1],material:material,depth:0) else { return nil }
                    var values = [String]()
                    for q in rule.children[0].children {
                        guard q.namespace == sie, q.name == "Qualifier", q.children.isEmpty, let uri = q.attributes["uri"], known.contains(uri) else { return nil }; values.append(uri)
                    }
                    guard !values.isEmpty else { return nil }
                    if applies { output.formUnion(values) }
                }
            } else if child.namespace == tl && child.name == "AdditionalServiceInformation" {
                guard child.children.count == 1, child.children[0].namespace == tl, child.children[0].name == "URI",
                      child.children[0].text == prefix+"ForeSignatures" else { return nil }
            } else if ["true","1"].contains(ext.attributes["Critical"] ?? "") { return nil }
        }
        if output.contains(prefix+"QCQSCDStatusAsInCert") && ["QCWithQSCD","QCNoQSCD","QCQSCDManagedOnBehalf"].contains(where: { output.contains(prefix+$0) }) { return nil }
        return output
    }
    static func criteria(_ node: TLServiceExtension, material: CertificateQualificationMaterial, depth: Int) -> Bool? {
        guard depth <= 12, node.namespace == sie, node.name == "CriteriaList", let assertion = node.attributes["assert"], ["all","atLeastOne","none"].contains(assertion) else { return nil }
        var matches = [Bool]()
        for child in node.children {
            guard child.namespace == sie else { return nil }
            switch child.name {
            case "CriteriaList": guard let r = criteria(child,material:material,depth:depth+1) else { return nil }; matches.append(r)
            case "Description": continue
            case "KeyUsage":
                guard !child.children.isEmpty, !material.keyUsage.isEmpty else { return nil }
                var bits = Set<String>(), ok = true
                for bit in child.children {
                    guard bit.namespace == sie, bit.name == "KeyUsageBit", let name = bit.attributes["name"], let actual = material.keyUsage[name], bits.insert(name).inserted, ["true","1","false","0"].contains(bit.text) else { return nil }
                    ok = ok && actual == ["true","1"].contains(bit.text)
                }; matches.append(ok)
            case "PolicySet":
                guard !child.children.isEmpty else { return nil }
                var policies = [String]()
                for p in child.children {
                    guard p.namespace == sie, p.name == "PolicyIdentifier", let id = p.children.first,
                          id.namespace == xades, id.name == "Identifier", id.attributes["Qualifier"] == "OIDAsURI", id.text.hasPrefix("urn:oid:") else { return nil }
                    policies.append(String(id.text.dropFirst(8)))
                }
                matches.append(policies.allSatisfy { material.policies.contains($0) })
            default: return nil
            }
        }
        guard !matches.isEmpty else { return nil }
        switch assertion { case "all": return matches.allSatisfy { $0 }; case "atLeastOne": return matches.contains(true); default: return !matches.contains(true) }
    }
}
