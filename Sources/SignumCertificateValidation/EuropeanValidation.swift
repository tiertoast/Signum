import Foundation
import SignumCore
import SignumTrustCore
import SignumTrustAuthentication

public struct EuropeanValidationResult: Sendable {
    public let catalog: EuropeanCatalogView?
    public let requestedCountries: Set<String>
    public let signatures: [CompleteSignatureValidationResult]
    public let warning: String?
}
public extension SignatureQualificationService {
    /// Selection is only a bounded download hint. No name/country/AKI becomes trust.
    /// Existing validation performs all cryptographic and semantic checks afterwards.
    func validate(_ report: VerificationReport, catalog service: EuropeanTrustCatalogService,
                  countries: Set<String> = [], mode: RevocationMode = .offline, observedAt: Date = Date(),
                  evaluationMode: SignatureEvaluationMode = .historical,
                  isCancelled: @escaping @Sendable () -> Bool = { false }) async -> EuropeanValidationResult {
        let startedAt = ProcessInfo.processInfo.systemUptime
        let certificates = report.signatures.flatMap { s in
            (s.signerDER.map { [$0] } ?? []) + s.embeddedCertificateDERs +
            (s.evidence?.timestampTokens.prefix(8).flatMap { TimestampMaterial.inspect(token:$0,value:s.evidence!.signatureValue).certificates } ?? [])
        }
        var requested = countries
        var view: EuropeanCatalogView?
        var warning: String?
        do {
            // This reads only installed national envelopes; it never expands to all LOTL countries.
            let local = try? await service.cached(now:observedAt)
            if requested.isEmpty {
                if let local {
                    for (country,catalog) in local.catalogs {
                        let anchors = catalog.usableProviders.flatMap { $0.services.flatMap { $0.certificateDERs + $0.history.flatMap(\.certificateDERs) } }
                        if certificates.contains(where:{ cert in anchors.contains { $0 == cert || CertificateEvidenceMaterial.issued(cert,by:$0) } }) { requested.insert(country) }
                    }
                }
                // Issuer country can request at most two official lists; it proves nothing.
                let hints = Set(certificates.prefix(64).flatMap(Self.issuerCountryHints)).intersection(EUTrustPolicy.countries)
                if requested.isEmpty { requested = Set(hints.sorted().prefix(2)) }
            }
            guard !isCancelled(), !Task.isCancelled else { throw CancellationError() }
            if mode == .online { view = try await service.refresh(countries:requested,now:observedAt) }
            else { view = try await service.cached(countries:requested,now:observedAt) }
        } catch { warning = String(describing:error) }
        if isCancelled() || Task.isCancelled { return .init(catalog:nil,requestedCountries:requested,signatures:[],warning:"Annullato") }
        let lists = view.map { $0.catalogs.sorted { $0.key < $1.key }.map(\.value) } ?? []
        let assessmentAt = mode == .online ? observedAt.addingTimeInterval(ProcessInfo.processInfo.systemUptime - startedAt) : observedAt
        let values = await validate(report,authenticatedLists:lists,mode:mode,observedAt:assessmentAt,evaluationMode:evaluationMode,isCancelled:isCancelled)
        return .init(catalog:view,requestedCountries:requested,signatures:values,warning:warning)
    }
    private static func issuerCountryHints(_ der: Data) -> [String] {
        guard let cert = try? QualificationDER(der).children(), cert.count == 3,
              let tbs = try? cert[0].children() else { return [] }
        let offset = tbs.first?.tag == 0xa0 ? 1 : 0
        guard tbs.count > offset+2, let rdns = try? tbs[offset+2].children() else { return [] }
        var result = [String]()
        for rdn in rdns {
            guard let entries = try? rdn.children(0x31) else { continue }
            for entry in entries {
                guard let fields = try? entry.children(), fields.count == 2,
                      (try? fields[0].oid()) == "2.5.4.6", [12,19].contains(fields[1].tag),
                      let country = String(bytes:fields[1].bytes,encoding:.utf8), country.count == 2 else { continue }
                result.append(country == "GR" ? "EL" : country)
            }
        }
        return result
    }
}
