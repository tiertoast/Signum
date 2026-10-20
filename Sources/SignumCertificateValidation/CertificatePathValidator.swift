import Foundation
import Security
import SignumTrustCore
import SignumTrustAuthentication
import CCertificatePath

public enum CertificatePathState: String, Codable, Sendable { case verified, invalid, notVerifiable }
public struct CertificatePathElement: Equatable, Sendable {
    public let sha256: String
    public let subject: String
}
public struct CertificateServiceMatch: Equatable, Sendable {
    public let provider: String, service: String, country: String, status: String
    public let statusSince: Date
    public let listSequence: Int
    public let historical: Bool
    public let identitySHA256: String
}
public struct CertificatePathResult: Equatable, Sendable {
    public let state: CertificatePathState
    public let evaluatedAt: Date
    public let path: [CertificatePathElement]
    /// For an invalid path this is an attempted TL anchor, not a verified signer association.
    public let service: CertificateServiceMatch?
    public let alternativeServices: [CertificateServiceMatch]
    public let reason: String
    public static func unavailable(_ reason: String, now: Date = Date()) -> Self {
        .init(state: .notVerifiable, evaluatedAt: now, path: [], service: nil, alternativeServices: [], reason: reason)
    }
}

/// A local-clock path assessment, independent of signature integrity, revocation and eIDAS.
/// The application supplies only current catalogs reauthenticated by the A.2 service.
public enum CertificatePathValidator {
    static let caQC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    static let granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    struct Identity {
        let match: CertificateServiceMatch
        let der: Data
        let eligible: Bool
    }
    static func hash(_ data: Data) -> String { TLAuthenticator.sha256(data).map { String(format: "%02x", $0) }.joined() }
    static func identities(_ document: UntrustedTLDocument, now: Date) -> [Identity] {
        var result: [Identity] = []
        for provider in document.providers {
            for service in provider.services {
                // Each historical state carries its OWN identity. Never borrow today's key.
                var events = service.history.map { ($0.statusSince, $0.typeURI, $0.statusURI, $0.certificateDERs) }
                events.append((service.statusSince, service.typeURI, service.statusURI, service.certificateDERs))
                guard Set(events.map { $0.0 }).count == events.count,
                      service.statusSince <= document.issuedAt,
                      service.history.allSatisfy({ $0.statusSince < service.statusSince }) else { continue }
                events.sort { $0.0 < $1.0 }
                for (index, event) in events.enumerated() where event.1 == caQC && event.0 <= now {
                    let end = index + 1 < events.count ? events[index + 1].0 : nil
                    let historical = end.map { $0 <= now } ?? false
                    for der in event.3 {
                        let match = CertificateServiceMatch(provider: provider.name, service: service.name, country: document.territory,
                            status: event.2, statusSince: event.0, listSequence: document.sequenceNumber, historical: historical, identitySHA256: hash(der))
                        result.append(.init(match: match, der: der, eligible: !historical && event.2 == granted))
                    }
                }
            }
        }
        return result
    }
    public static func evaluate(signer: Data, intermediates: [Data], authenticatedLists: [AuthenticatedTL], now: Date = Date(), isCancelled: @Sendable () -> Bool = { false }) -> CertificatePathResult {
        guard authenticatedLists.count <= 32,
              authenticatedLists.allSatisfy({ $0.document.territory != "EU" && $0.document.issuedAt <= now && $0.document.nextUpdate > now }) else {
            return .unavailable("Trusted Lists assenti, obsolete o fuori dal periodo valutato.", now: now)
        }
        return evaluate(signer: signer, intermediates: intermediates,
                        identities: authenticatedLists.flatMap { identities($0.document, now: now) }, now: now, isCancelled: isCancelled)
    }
    // Internal synthetic identities bypass only TL acquisition, never X.509 validation.
    static func evaluate(signer: Data, intermediates: [Data], identities: [Identity], now: Date, timestampPurpose: Bool = false, isCancelled: @Sendable () -> Bool = { false }) -> CertificatePathResult {
        guard !signer.isEmpty, signer.count <= 65536, intermediates.count <= 64, identities.count <= 2048 else {
            return .unavailable("Limiti dei certificati o delle identità TL superati.", now: now)
        }
        var seen = Set<Data>(), certificates = [Data]()
        for der in [signer] + intermediates where seen.insert(der).inserted {
            guard !der.isEmpty, der.count <= 65536 else { return .unavailable("Certificati intermedi fuori dai limiti.", now: now) }
            certificates.append(der)
        }
        guard certificates.reduce(0, { $0 + $1.count + 4 }) <= 2 * 1024 * 1024 else { return .unavailable("Certificati oltre il limite di memoria.", now: now) }
        var packed = Data()
        for der in certificates {
            let n = UInt32(der.count)
            packed.append(contentsOf: [UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)])
            packed.append(der)
        }
        let certificateMap = Dictionary(certificates.map { (hash($0), $0) }, uniquingKeysWith: { first, _ in first })
        var successes: [(CertificateServiceMatch, [CertificatePathElement])] = []
        var invalid: (CertificateServiceMatch?, String, [CertificatePathElement])?
        var unsupported: String?
        var inactive: CertificateServiceMatch?
        var limited = false
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        for identity in identities {
            if isCancelled() { return .unavailable("Valutazione annullata.", now: now) }
            if ProcessInfo.processInfo.systemUptime > deadline { unsupported = "Limite di tempo della ricerca raggiunto."; limited = true; break }
            var hashes = [CChar](repeating: 0, count: 1024), message = [CChar](repeating: 0, count: 512)
            let state = packed.withUnsafeBytes { bytes in identity.der.withUnsafeBytes { anchor in
                signum_path_validate_purpose(bytes.bindMemory(to: UInt8.self).baseAddress, packed.count,
                    anchor.bindMemory(to: UInt8.self).baseAddress, identity.der.count, Int64(now.timeIntervalSince1970), timestampPurpose ? 1 : 0,
                    &hashes, hashes.count, &message, message.count)
            }}
            let reason = String(cString: message)
            var available = certificateMap
            available[identity.match.identitySHA256] = identity.der
            let path = String(cString: hashes).split(separator: "\n").map { fingerprint -> CertificatePathElement in
                let der = available[String(fingerprint)]
                let cert = der.flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
                return .init(sha256: String(fingerprint), subject: cert.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "Certificato")
            }
            if state == 1 {
                if identity.eligible {
                    successes.append((identity.match, path))
                } else { inactive = identity.match }
            } else if state < 0, identity.eligible { invalid = (path.last?.sha256 == identity.match.identitySHA256 ? identity.match : nil, reason, path) }
            else if state == 0 { unsupported = reason }
        }
        if let first = successes.first {
            return .init(state: .verified, evaluatedAt: now, path: first.1, service: first.0,
                         alternativeServices: Array(successes.dropFirst().map { $0.0 }),
                         reason: timestampPurpose ? "Percorso TSA verificato verso l’identità del servizio autenticato; revoca separata." : "Percorso crittografico valido fino al servizio CA/QC autenticato. Revoca e qualificazione non valutate.")
        }
        if limited { return .unavailable(unsupported!, now: now) }
        if let inactive { return .init(state: .notVerifiable, evaluatedAt: now, path: [], service: inactive, alternativeServices: [], reason: inactive.historical ? "Identità del servizio individuata solo in un periodo storico. Non si attribuisce attendibilità alla data dichiarata dal firmatario." : "Servizio individuato, ma stato TL non ammesso nel periodo valutato (ritirato o non supportato).") }
        if let invalid { return .init(state: .invalid, evaluatedAt: now, path: invalid.2, service: invalid.0, alternativeServices: [], reason: invalid.1) }
        return .unavailable(unsupported ?? "Servizio CA/QC non trovato nelle Trusted Lists autenticate disponibili o intermedi mancanti.", now: now)
    }
}
