import Foundation
import SignumTrustCore

public enum TLInterpretationState: String, Sendable { case complete, partial, blocked }
public struct TLUsableProvider: Sendable {
    public let name: String
    public let services: [TLService]
}
public struct TLExcludedService: Sendable {
    public let providerIndex: Int, serviceIndex: Int
    public let provider: String, service: String, reason: String
}

/// The only TL capability accepted by B/C/D. Raw provenance cannot construct one.
public struct InterpretedTrustCatalog: Sendable {
    public let source: AuthenticatedTLDocument
    /// Raw, signed metadata for diagnostics/continuity. Not the service authorization view.
    public var document: UntrustedTLDocument { source.document }
    public var signerSHA256: Data { source.signerSHA256 }
    public var revision: UntrustedTLRevision { source.revision }
    public var schemeInformationURIs: [String] { source.schemeInformationURIs }
    public let usableProviders: [TLUsableProvider]
    public let excludedServices: [TLExcludedService]
    public let interpretationState: TLInterpretationState
    public let interpretationReason: String?
    public let interpretationPolicy = "Signum-TL-Interpretation-E1S-v1"
    public var usableServiceCount: Int { usableProviders.reduce(0) { $0 + $1.services.count } }
    fileprivate init(source: AuthenticatedTLDocument, providers: [TLUsableProvider], excluded: [TLExcludedService], blocked: String?) {
        self.source = source; usableProviders = providers; excludedServices = excluded
        interpretationState = blocked != nil ? .blocked : excluded.isEmpty ? .complete : .partial
        interpretationReason = blocked
    }
}

public enum TLInterpreter {
    public static func interpret(_ source: AuthenticatedTLDocument) -> InterpretedTrustCatalog {
        let blocked = source.unscopedCriticalContent ? "Critical content outside an isolatable service scope" : nil
        var providers = [TLUsableProvider](), excluded = [TLExcludedService]()
        for (pi, provider) in source.document.providers.enumerated() {
            var services = [TLService]()
            for (si, service) in provider.services.enumerated() {
                // One unknown event still excludes the service; siblings remain independent.
                let dates = service.timeline(issuedAt:source.document.issuedAt)
                let identityUnsupported = ([service.subjectKeyIdentifiers] + service.history.map(\.subjectKeyIdentifiers)).joined().contains { $0.isEmpty || $0.count > 128 }
                    || ([service.subjectNames] + service.history.map(\.subjectNames)).joined().contains { $0.isEmpty }
                let reason = blocked ?? (dates == nil ? "Inconsistent service timeline (order, duplicate or future date)" : nil)
                    ?? (identityUnsupported ? "Unsupported or empty service identity representation" : nil)
                    ?? unsupported(service.extensions,typeURI:service.typeURI) ?? service.history.compactMap { unsupported($0.extensions,typeURI:$0.typeURI) }.first
                if let reason { excluded.append(.init(providerIndex: pi, serviceIndex: si, provider: provider.name, service: service.name, reason: reason)) }
                else { services.append(service) }
            }
            if !services.isEmpty { providers.append(.init(name: provider.name, services: services)) }
        }
        return .init(source: source, providers: providers, excluded: excluded, blocked: blocked)
    }
    private static func unsupported(_ extensions: [TLServiceExtension], typeURI: String) -> String? {
        let tl = TLQualificationRules.tl, sie = TLQualificationRules.sie
        for ext in extensions {
            let critical = ["true", "1"].contains(ext.attributes["Critical"] ?? "")
            guard ext.namespace == tl, ext.name == "Extension", ext.children.count == 1,
                  ["true","false","1","0"].contains(ext.attributes["Critical"] ?? "") else {
                return "Unsupported extension structure or criticality"
            }
            let node = ext.children[0]
            if node.namespace == sie && node.name == "Qualifications" {
                guard typeURI == "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" else { return "Qualifications extension outside CA/QC context" }
                guard TLQualificationRules.supports([ext]) else {
                    return "Unsupported qualification criterion or qualifier (including legacy semantics)"
                }
            } else if node.namespace == tl && node.name == "AdditionalServiceInformation" {
                let known = ["ForeSignatures","ForeSeals","ForWebSiteAuthentication","RootCA-QC"].map { TLQualificationRules.prefix + $0 }
                guard node.children.count == 1, node.children[0].namespace == tl, node.children[0].name == "URI",
                      known.contains(node.children[0].text) else {
                    if critical { return "Unknown critical additional service information" }
                    continue
                }
            } else if critical {
                return "Unsupported critical extension: {\(node.namespace)}\(node.name)"
            }
        }
        return nil
    }
}
