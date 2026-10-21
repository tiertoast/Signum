import Foundation
import CCertificatePath
import SignumTrustAuthentication

public enum TSAAuthorizationState: String, Sendable { case authorized, notAuthorized, invalid, indeterminate }
public struct TSAAuthorizationResult: Equatable, Sendable {
    public let state: TSAAuthorizationState
    public let reason: String
    public let tokenTime: Date?
    public let earliestTime: Date?
    public let latestTime: Date?
    public let service: CertificateServiceMatch?
    public let path: CertificatePathResult?
    public let certificates: [Data]
}
struct TimestampMaterial {
    let code: Int32, time: Date?, accuracy: TimeInterval, certificates: [Data]
    static func inspect(token: Data, value: Data) -> Self {
        var bytes = [UInt8](repeating: 0, count: 1024*1024), used = 0, at: Int64 = 0, accuracy: Int64 = 0
        let code = token.withUnsafeBytes { t in value.withUnsafeBytes { v in
            signum_timestamp_inspect(t.bindMemory(to: UInt8.self).baseAddress,t.count,
                v.bindMemory(to: UInt8.self).baseAddress,v.count,&at,&accuracy,&bytes,bytes.count,&used)
        } }
        var certificates = [Data](), offset = 0
        while code == 1, offset + 4 <= used {
            let n = bytes[offset..<offset+4].reduce(0) { ($0 << 8) | Int($1) };offset += 4
            guard n > 0, n <= 65536, n <= used-offset, certificates.count < 17 else { return .init(code: -1,time: nil,accuracy: 0,certificates: []) }
            certificates.append(Data(bytes[offset..<offset+n]));offset += n
        }
        return .init(code: code,time: code == 1 ? Date(timeIntervalSince1970: Double(at)) : nil,accuracy: Double(accuracy)/1000000,certificates: certificates)
    }
}
public enum TSAAuthorization {
    public static func evaluate(token: Data, signatureValue: Data, authenticatedLists: [InterpretedTrustCatalog], observedAt: Date = Date(),
                                isCancelled: @Sendable () -> Bool = { false }) -> TSAAuthorizationResult {
        let material = TimestampMaterial.inspect(token: token,value: signatureValue)
        func result(_ state: TSAAuthorizationState,_ reason: String, time: Date? = nil, path: CertificatePathResult? = nil) -> TSAAuthorizationResult {
            .init(state: state,reason: reason,tokenTime: time,earliestTime: time?.addingTimeInterval(-material.accuracy),latestTime: time?.addingTimeInterval(material.accuracy),service: path?.service,path: path,certificates: material.certificates)
        }
        guard material.code == 1, let at = material.time, let signer = material.certificates.first else {
            return result(material.code < 0 ? .invalid : .indeterminate,"Token malformato, impronta non corrispondente o profilo non supportato.")
        }
        let first = at.addingTimeInterval(-material.accuracy), last = at.addingTimeInterval(material.accuracy)
        guard last <= observedAt else { return result(.indeterminate,"Tempo del token futuro rispetto all’osservazione.") }
        guard !authenticatedLists.isEmpty, authenticatedLists.count <= 32,
              authenticatedLists.allSatisfy({ $0.document.territory != "EU" && $0.document.issuedAt <= observedAt && $0.document.nextUpdate > observedAt }) else {
            return result(.indeterminate,"Trusted Lists autenticate assenti o obsolete al momento dell’osservazione.")
        }
        var identities = [CertificatePathValidator.Identity]()
        for list in authenticatedLists {
            for provider in list.usableProviders { for service in provider.services {
                var events = service.history.map { ($0.statusSince,$0.typeURI,$0.statusURI,$0.certificateDERs) }
                events.append((service.statusSince,service.typeURI,service.statusURI,service.certificateDERs))
                guard Set(events.map { $0.0 }).count == events.count, service.statusSince <= list.document.issuedAt,
                      service.history.allSatisfy({ $0.statusSince < service.statusSince }) else { continue }
                events.sort { $0.0 < $1.0 }
                guard let index = events.lastIndex(where: { $0.0 <= at }) else { continue }
                let event = events[index]
                guard event.0 <= first, (index+1 == events.count || events[index+1].0 > last), ["http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST","http://uri.etsi.org/TrstSvc/Svctype/TSA/TST"].contains(event.1),
                      event.2 == CertificatePathValidator.granted else { continue }
                for der in event.3 {
                    identities.append(.init(match: .init(provider: provider.name,service: service.name,country: list.document.territory,
                        status: event.2,statusSince: event.0,listSequence: list.document.sequenceNumber,historical: index < events.count-1,
                        identitySHA256: CertificatePathValidator.hash(der)),der: der,eligible: true))
                }
            } }
        }
        guard identities.count <= 2048 else { return result(.indeterminate,"Limite delle identità TSA superato.") }
        guard !identities.isEmpty else { return result(.notAuthorized,"Nessun servizio TSA autorizzato dalla TL nel periodo del token.") }
        let path = CertificatePathValidator.evaluate(signer: signer,intermediates: material.certificates,identities: identities,
            now: at,timestampPurpose: true,isCancelled: isCancelled)
        guard path.state == .verified, let match = path.service,
              let anchor = identities.first(where: { $0.match == match })?.der else {
            return result(path.state == .invalid ? .invalid : .notAuthorized,"Percorso TSA verso un’identità TL non verificato: " + path.reason)
        }
        if isCancelled() { return result(.indeterminate,"Verifica TSA annullata.") }
        let tokenResult = TimestampEvidenceVerifier.verify(token: token,signatureValue: signatureValue,explicitTSAIdentity: anchor,observedAt: observedAt)
        guard tokenResult.state == .authenticatedToken else {
            return result(tokenResult.state == .invalid ? .invalid : .indeterminate,tokenResult.reason)
        }
        for boundary in [first,last] {
            let checked = CertificatePathValidator.evaluate(signer: signer,intermediates: material.certificates,
                identities: identities.filter { $0.match == match },now: boundary,timestampPurpose: true,isCancelled: isCancelled)
            guard checked.state == .verified else { return result(.indeterminate,"Finestra di accuratezza del token non coperta dal percorso TSA.") }
        }
        if isCancelled() { return result(.indeterminate,"Verifica TSA annullata.") }
        return result(.authorized,"Firma, ESS, impronta e percorso TSA verificati verso il servizio TL nel periodo del token; revoca da valutare separatamente.",time: tokenResult.tokenTime,path: path)
    }
}
