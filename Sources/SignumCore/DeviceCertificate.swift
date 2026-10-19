#if os(macOS)
import Foundation

/// An observed route, never a claim of unique physical hardware identity.
/// Slot is a locator, and is included in the selection key so a changed slot
/// requires a fresh choice; serial/model/manufacturer alone cannot merge tokens.
public struct DeviceCertificateRoute: Identifiable, Sendable {
    public let id: String
    public let providerID: String, providerName: String, providerPath: String
    public let origin: MiddlewareOrigin
    public let moduleIdentity: MiddlewareFileIdentity
    public let token: SignumToken
    public let certificate: SignumCertificate
    public let der: Data
    public let assessment: CertificateEligibility.Assessment
    public let identity: SignumCertificateIdentity?
    public var certificateFingerprint: String { assessment.certificateSHA256 }
    public var title: String { identity?.fullName ?? "Titolare non disponibile" }
    public var deviceDescription: String { [token.label, token.model].filter { !$0.isEmpty }.joined(separator: " · ") }
    public var purpose: String {
        if assessment.permitsSigning { return "Firma documentale · idoneo ai controlli locali" }
        if assessment.clientAuthentication && !assessment.documentSigning && !assessment.anyExtendedKeyUsage {
            return "Certificato di autenticazione · non idoneo alla firma documentale"
        }
        return assessment.status.description
    }
    init(provider: DiscoveredMiddleware, token: SignumToken, certificate: IsolatedPKCS11Client.Certificate,
         inspection: MiddlewareFileSecurity.Inspection, at date: Date) {
        providerID = provider.definition.id; providerName = provider.definition.name
        providerPath = inspection.canonicalPath; moduleIdentity = inspection.identity; origin = provider.origin
        self.token = token; self.certificate = certificate.certificate; der = certificate.der
        assessment = CertificateEligibility.evaluate(certificateDER: der, at: date)
        identity = try? SignumCertificateIdentity(certificateDER: der)
        // Structured encoding prevents ambiguous concatenation of vendor strings.
        let components = [provider.id, providerPath, moduleIdentity.moduleKey,
                          String(token.slot), token.serial, token.manufacturer, token.model,
                          token.reader, self.certificate.id, assessment.certificateSHA256]
        id = DocumentSnapshot.digest(Data(components.map { "\($0.utf8.count):\($0)" }.joined().utf8))
    }
    /// Call off-main immediately before approval. Refreshing never substitutes a
    /// different route, and existing engines re-read/bind the approved DER.
    public func requireCurrentModule() throws {
        let current = try MiddlewareFileSecurity.inspect(providerPath, automatic: origin == .known)
        guard current.canonicalPath == providerPath, current.identity == moduleIdentity else { throw MiddlewareFileSecurity.Failure.changed }
    }
    public enum AvailabilityFailure: Error, LocalizedError {
        case unavailable
        public var errorDescription:String? { "Dispositivo o certificato non più disponibile. Cerca nuovamente prima di approvare." }
    }
    /// Public revalidation off-main before consent. Proves the observed token,
    /// CKA_ID and DER are still available, without claiming access to a private
    /// object hidden until login. Existing signing engines prove that key later.
    public func requireCurrentCredential(client:IsolatedPKCS11Client = .init(), isCancelled: () -> Bool = { Task.isCancelled }) throws {
        do {
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            try requireCurrentModule()
            let automatic=origin == .known
            let scan=try client.scan(provider:providerPath,timeout:8,expectedModule:moduleIdentity,automatic:automatic,isCancelled:isCancelled)
            guard scan.provider == providerPath, scan.tokens.contains(where: {
                $0.slot == token.slot && $0.serial == token.serial && $0.manufacturer == token.manufacturer &&
                $0.model == token.model && $0.reader == token.reader
            }) else {throw AvailabilityFailure.unavailable}
            let actual=try client.certificates(provider:providerPath,slot:token.slot,timeout:8,expectedModule:moduleIdentity,automatic:automatic,isCancelled:isCancelled)
            guard actual.contains(where: {$0.certificate.identifier == certificate.identifier && $0.der == der}) else {
                throw AvailabilityFailure.unavailable
            }
            try requireCurrentModule()
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            try CertificateEligibility.requireEligible(certificateDER:der)
        } catch {
            if isCancelled() || error as? SupervisedProcess.Failure == .cancelled { throw SupervisedProcess.Failure.cancelled }
            throw AvailabilityFailure.unavailable
        }
    }

}

/// Same DER groups *certificates*, not physical tokens. All routes remain visible
/// and independently selectable, including within one provider.
public struct DeviceCertificate: Identifiable, Sendable {
    public let id: String
    public let routes: [DeviceCertificateRoute]
    public static func collect(_ providers: [DiscoveredMiddleware], at date: Date = Date()) -> [DeviceCertificate] {
        var groups: [String: [DeviceCertificateRoute]] = [:], order: [String] = []
        for provider in providers {
            guard let inspection = provider.inspection, [.ready, .partial].contains(provider.status) else { continue }
            for token in provider.tokens {
                for certificate in token.certificates {
                    let route = DeviceCertificateRoute(provider: provider, token: token.token,
                                                       certificate: certificate, inspection: inspection, at: date)
                    let key = route.certificateFingerprint
                    if groups[key] == nil { order.append(key) }
                    // Deduplicate identical observations, retain different routes.
                    if groups[key]?.contains(where: { $0.id == route.id }) != true { groups[key, default: []].append(route) }
                }
            }
        }
        return order.compactMap { key in groups[key].map { .init(id: key, routes: $0) } }
            .sorted { ($0.routes[0].assessment.permitsSigning ? 0 : 1) < ($1.routes[0].assessment.permitsSigning ? 0 : 1) }
    }
}
#endif
