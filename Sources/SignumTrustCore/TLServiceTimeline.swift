import Foundation

/// Raw temporal view; authority comes only from an InterpretedTrustCatalog.
public struct TLServiceEvent: Sendable {
    public let start: Date, end: Date?
    public let typeURI: String, statusURI: String
    public let certificateDERs: [Data], subjectKeyIdentifiers: [Data]
    public let subjectNames: [String]
    public let extensions: [TLServiceExtension]
    public let fromHistory: Bool
    public func contains(_ date: Date) -> Bool { start <= date && (end.map { date < $0 } ?? true) }
}
public extension TLService {
    /// Verify the signed order BEFORE normalizing. Equal dates are never repaired by sorting.
    func timeline(issuedAt: Date) -> [TLServiceEvent]? {
        let dates = [statusSince] + history.map(\.statusSince)
        guard statusSince <= issuedAt, zip(dates,dates.dropFirst()).allSatisfy({ $0 > $1 }) else { return nil }
        var result = [TLServiceEvent]()
        for (i,h) in history.enumerated().reversed() {
            result.append(.init(start:h.statusSince,end:dates[i],typeURI:h.typeURI,statusURI:h.statusURI,
                certificateDERs:h.certificateDERs,subjectKeyIdentifiers:h.subjectKeyIdentifiers,subjectNames:h.subjectNames,
                extensions:h.extensions,fromHistory:true))
        }
        result.append(.init(start:statusSince,end:nil,typeURI:typeURI,statusURI:statusURI,certificateDERs:certificateDERs,
            subjectKeyIdentifiers:subjectKeyIdentifiers,subjectNames:subjectNames,extensions:extensions,fromHistory:false))
        return result
    }
}
