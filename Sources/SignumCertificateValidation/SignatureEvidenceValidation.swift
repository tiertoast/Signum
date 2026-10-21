import Foundation
import SignumCore
import SignumTrustAuthentication

public enum EvidenceAssociationState: String, Sendable { case associated, unassociated }
public struct EvidenceAssociationResult: Equatable, Sendable {
    public let sha256: String, source: String
    public let state: EvidenceAssociationState
    public let reason: String
}
public enum SignatureRevocationState: String, Sendable { case good, revoked, indeterminate }
public struct SignatureRevocationResult: Equatable, Sendable {
    public let state: SignatureRevocationState
    public let reason: String
    public let certificates: [RevocationEvidenceResult]
}
public enum SignatureTimeState: String, Sendable { case proven, notProven, invalid, indeterminate }
public struct SignatureTimeResult: Equatable, Sendable {
    public let state: SignatureTimeState
    public let declaredSigningTime: String
    public let provenTime: Date?
    public let reason: String
    public let authorities: [TSAAuthorizationResult]
}
public struct SignatureEvidenceValidationResult: Equatable, Sendable {
    public let signatureID: Int
    public let revocation: SignatureRevocationResult
    public let time: SignatureTimeResult
    public let associations: [EvidenceAssociationResult]
    /// Exact path whose certificates were checked; prevents reusing a good result on another path.
    public var revocationPath: CertificatePathResult? = nil
}
/// Off-main, caller-owned, finite validation. No scheduler and no GUI coupling.
/// New assessments do not modify legacy integrity/trust/qualification fields.
public struct SignatureEvidenceValidationService: Sendable {
    private let cache: RevocationEvidenceCache?
    private let transport: any RevocationTransport
    public init(cache: RevocationEvidenceCache? = nil) { self.cache = cache;self.transport = SystemRevocationTransport() }
    init(cache: RevocationEvidenceCache? = nil,transport: any RevocationTransport) { self.cache = cache;self.transport = transport }
    public func validate(_ report: VerificationReport, authenticatedLists: [InterpretedTrustCatalog],mode: RevocationMode = .offline,
                         observedAt: Date = Date(),isCancelled: @escaping @Sendable () -> Bool = { false }) async -> [SignatureEvidenceValidationResult] {
        let startedAt = ProcessInfo.processInfo.systemUptime
        let session = RevocationSession(cache: cache,transport: transport)
        let listsCurrent = !authenticatedLists.isEmpty && authenticatedLists.count <= 32 && authenticatedLists.allSatisfy {
            $0.document.territory != "EU" && $0.document.issuedAt <= observedAt && $0.document.nextUpdate > observedAt
        }
        let tlCertificates = listsCurrent ? authenticatedLists.flatMap { $0.usableProviders.flatMap { $0.services.flatMap { $0.certificateDERs + $0.history.flatMap(\.certificateDERs) } } } : []
        var output = [SignatureEvidenceValidationResult]()
        for signature in report.signatures {
            if isCancelled() || Task.isCancelled { break }
            var associations = [EvidenceAssociationResult](), bound = [RevocationEvidence]()
            let raw = (signature.evidence?.embedded ?? []) + report.unassociatedEvidence
            func structurallyBound(_ e: EmbeddedValidationEvidence) -> Bool {
                e.isBound(to: signature) && (report.format != .pades || signature.integrity == .verified)
            }
            let extraCertificates = raw.filter { $0.kind == .certificate && structurallyBound($0) }.map(\.der)
            let signerPath = signature.signerDER.map { CertificatePathValidator.evaluate(signer: $0,
                intermediates: signature.embeddedCertificateDERs + extraCertificates,authenticatedLists: authenticatedLists,
                now: observedAt,isCancelled: isCancelled) }
            var authorities = [TSAAuthorizationResult](), proven = [Date](), invalid = false
            for token in signature.evidence?.timestampTokens ?? [] {
                guard let envelope = signature.evidence, report.format != .pades || signature.integrity == .verified else { continue }
                let material = TimestampMaterial.inspect(token: token,value: envelope.signatureValue)
                associations.append(.init(sha256: CertificatePathValidator.hash(token),source: "signatureTimeStamp",
                    state: material.code == 1 ? .associated : .unassociated,
                    reason: material.code == 1 ? "Impronta corrispondente alla SignatureValue di questo SignerInfo." : "Non associata: impronta errata, token malformato o profilo non interpretabile."))
                let authority = TSAAuthorization.evaluate(token: token,signatureValue: envelope.signatureValue,
                    authenticatedLists: authenticatedLists,observedAt: observedAt,isCancelled: isCancelled)
                authorities.append(authority)
                if authority.state == .invalid { invalid = true }
            }
            let pool = (signature.signerDER.map { [$0] } ?? []) + signature.embeddedCertificateDERs + extraCertificates +
                tlCertificates + authorities.flatMap(\.certificates)
            let certMap = Dictionary(pool.map { (CertificatePathValidator.hash($0),$0) },uniquingKeysWith: { a,_ in a })
            var historicalPaths = [Date:CertificatePathResult]()
            if listsCurrent, let signer = signature.signerDER {
                for authority in authorities.prefix(8) where authority.state == .authorized {
                    if let at = authority.latestTime {
                        historicalPaths[at] = CertificatePathValidator.evaluate(signer:signer,
                            intermediates:signature.embeddedCertificateDERs+extraCertificates,
                            identities:authenticatedLists.flatMap { CertificatePathValidator.identities($0,now:at) },now:at,isCancelled:isCancelled)
                    }
                }
            }
            var targets = Set<String>()
            for path in historicalPaths.values where path.state == .verified { targets.formUnion(path.path.dropLast().map(\.sha256)) }
            if let path = signerPath, path.state == .verified { targets.formUnion(path.path.dropLast().map(\.sha256)) }
            for authority in authorities where authority.state == .authorized {
                if let path = authority.path {
                    targets.formUnion(path.path.count == 1 ? path.path.map(\.sha256) : path.path.dropLast().map(\.sha256))
                }
            }
            let pairs: [(Data,Data)] = targets.compactMap { fingerprint in
                guard let cert = certMap[fingerprint], let issuer = pool.first(where: {
                    CertificatePathValidator.hash($0) != fingerprint && CertificateEvidenceMaterial.issued(cert,by: $0)
                }) else { return nil }; return (cert,issuer)
            }
            for evidence in raw {
                let value = evidence.kind == .certificate ? nil : RevocationEvidence(kind: evidence.kind == .ocsp ? .ocsp : .crl,der: evidence.der)
                let applies = value.map { v in pairs.contains { CertificateEvidenceMaterial.applies(v,to: $0.0,issuer: $0.1) } } ?? true
                let linked = structurallyBound(evidence) && applies
                associations.append(.init(sha256: CertificatePathValidator.hash(evidence.der),source: evidence.source,state: linked ? .associated : .unassociated,
                    reason: linked ? "Collegata al SignerInfo/revisione e al certificato destinatario; autenticazione dell’evidenza separata." : "Non associata a questo SignerInfo, revisione o certificato destinatario; non utilizzata."))
                if linked, let value { bound.append(value) }
            }
            var revocation = SignatureRevocationResult(state: .indeterminate,reason: "Percorso del firmatario non verificato o certificato assente.",certificates: [])
            var assessedPath: CertificatePathResult?
            if let path = signerPath, path.state == .verified {
                assessedPath = path
                revocation = await Self.checkPath(path,pool: pool,bound: bound,forceLeaf: false,session: session,
                    mode: mode,now: observedAt,covering: nil,isCancelled: isCancelled)
            }
            for authority in authorities where authority.state == .authorized {
                guard let earliest = authority.earliestTime, let latest = authority.latestTime, let path = authority.path else { continue }
                let tsaRevocation = await Self.checkPath(path,pool: pool,bound: bound,forceLeaf: true,
                    session: session,mode: mode,now: observedAt,covering: (earliest,latest),isCancelled: isCancelled)
                if tsaRevocation.state == .good { proven.append(latest) }
            }
            if let at = proven.min(), let historical = historicalPaths[at], historical.state == .verified,
               let authority = authorities.first(where:{ $0.state == .authorized && $0.latestTime == at }), let earliest = authority.earliestTime {
                // A current good statement alone is insufficient: its authenticated window
                // must cover the complete proof interval AND the observation time.
                revocation = await Self.checkPath(historical,pool:pool,bound:bound,forceLeaf:false,
                    session:session,mode:mode,now:observedAt,covering:(earliest,at),isCancelled:isCancelled)
                assessedPath = historical
            }
            var time: SignatureTimeResult
            if let first = proven.min() {
                time = .init(state: .proven,declaredSigningTime: signature.declaredTime,provenTime: first,
                    reason: "SignatureValue comprovata entro il limite superiore della finestra di accuratezza del token: impronta, firma/ESS, percorso e autorizzazione TSA TL e revoca verificati. Non è un verdetto globale sulla firma.",authorities: authorities)
            } else if !(signature.evidence?.timestampTokens.isEmpty ?? true) {
                time = .init(state: invalid ? .invalid : .indeterminate,declaredSigningTime: signature.declaredTime,provenTime: nil,
                    reason: "Tempo non comprovato: token non valido, TSA non autorizzata o evidenze di revoca/copertura temporale insufficienti. " + (authorities.last?.reason ?? signature.evidence?.issue ?? ""),authorities: authorities)
            } else {
                time = .init(state: .notProven,declaredSigningTime: signature.declaredTime,provenTime: nil,
                    reason: "Nessuna signature-time-stamp utilizzabile. signingTime è soltanto dichiarato. " + (signature.evidence?.issue ?? ""),authorities: [])
            }
            let finishedAt = observedAt.addingTimeInterval(ProcessInfo.processInfo.systemUptime-startedAt)
            if listsCurrent && authenticatedLists.contains(where: { $0.document.nextUpdate <= finishedAt }) {
                revocation = .init(state: .indeterminate,reason: "Trusted List scaduta durante la verifica.",certificates: revocation.certificates)
                time = .init(state: .indeterminate,declaredSigningTime: signature.declaredTime,provenTime: nil,
                    reason: "Trusted List scaduta durante la verifica; nessuna promozione del tempo.",authorities: authorities)
            }
            guard !isCancelled(), !Task.isCancelled else { break }
            output.append(.init(signatureID: signature.id,revocation: revocation,time: time,associations: associations,revocationPath:assessedPath))
        }
        return output
    }
    private static func checkPath(_ path: CertificatePathResult,pool: [Data],bound: [RevocationEvidence],forceLeaf: Bool,
                                  session: RevocationSession,mode: RevocationMode,now: Date,covering time: (earliest: Date,latest: Date)?,
                                  isCancelled: @escaping @Sendable () -> Bool) async -> SignatureRevocationResult {
        let map = Dictionary(pool.map { (CertificatePathValidator.hash($0),$0) },uniquingKeysWith: { a,_ in a })
        var relevant = Array(path.path.dropLast())
        if forceLeaf && relevant.isEmpty, let first = path.path.first { relevant = [first] }
        guard !relevant.isEmpty else { return .init(state: .indeterminate,reason: "Nessun certificato di percorso valutabile.",certificates: []) }
        var all = [RevocationEvidenceResult](), missing = false, reasons = [String]()
        for item in relevant {
            guard !isCancelled(), !Task.isCancelled, let cert = map[item.sha256],
                  let issuer = pool.first(where: { CertificatePathValidator.hash($0) != item.sha256 && CertificateEvidenceMaterial.issued(cert,by: $0) }) else { missing = true;continue }
            let result = await session.check(certificate: cert,issuer: issuer,evidence: bound,mode: mode,now: now,isCancelled: isCancelled)
            all += result.results;reasons.append(result.reason)
            let current = result.results.filter(\.authenticated)
            if current.contains(where: { $0.state == .revoked }) {
                return .init(state: .revoked,reason: "Revoca autenticata per un certificato del percorso.",certificates: all)
            }
            if !current.contains(where: { evidence in
                evidence.state == .good && (time.map { t in (evidence.thisUpdate ?? .distantFuture) <= t.earliest && (evidence.nextUpdate ?? .distantPast) >= max(now,t.latest) && t.latest <= now } ?? true)
            }) { missing = true }
        }
        if isCancelled() || Task.isCancelled { missing = true }
        return .init(state: missing ? .indeterminate : .good,reason: missing ? "Evidenze correnti insufficienti per tutto il percorso o per il tempo del token. " + reasons.joined(separator: " ") : "Stato non revocato verificato per tutti i certificati pertinenti del percorso; ancora TL distinta.",certificates: all)
    }
}
