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
    public let interpretationPolicy = "Signum-TL-Interpretation-E1R-v1"
    public var usableServiceCount: Int { usableProviders.reduce(0) { $0 + $1.services.count } }
    fileprivate init(source: AuthenticatedTLDocument, providers: [TLUsableProvider], excluded: [TLExcludedService], blocked: String?) {
        self.source = source; usableProviders = providers; excludedServices = excluded
        interpretationState = blocked != nil ? .blocked : excluded.isEmpty ? .complete : .partial
        interpretationReason = blocked
    }
}

public enum TLInterpreter {
    // A syntax pass through the SAME existing D rule evaluator. Values are deliberately
    // meaningless: only nil (unsupported syntax), never the boolean match, is consumed.
    private struct SyntaxFacts: TLQualificationMaterial {
        let policies: Set<String> = []
        let keyUsage = Dictionary(uniqueKeysWithValues: ["digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","crlSign","encipherOnly","decipherOnly"].map { ($0, false) })
    }
    public static func interpret(_ source: AuthenticatedTLDocument) -> InterpretedTrustCatalog {
        let blocked = source.unscopedCriticalContent ? "Critical content outside an isolatable service scope" : nil
        var providers = [TLUsableProvider](), excluded = [TLExcludedService]()
        for (pi, provider) in source.document.providers.enumerated() {
            var services = [TLService]()
            for (si, service) in provider.services.enumerated() {
                // Until historical interpretation is implemented, one unknown event excludes
                // this whole service, never independently interpretable sibling services.
                let reason = blocked ?? unsupported(service.extensions) ?? service.history.compactMap { unsupported($0.extensions) }.first
                if let reason { excluded.append(.init(providerIndex: pi, serviceIndex: si, provider: provider.name, service: service.name, reason: reason)) }
                else { services.append(service) }
            }
            if !services.isEmpty { providers.append(.init(name: provider.name, services: services)) }
        }
        return .init(source: source, providers: providers, excluded: excluded, blocked: blocked)
    }
    private static func unsupported(_ extensions: [TLServiceExtension]) -> String? {
        let tl = TLQualificationRules.tl, sie = TLQualificationRules.sie
        for ext in extensions {
            let critical = ["true", "1"].contains(ext.attributes["Critical"] ?? "")
            guard ext.namespace == tl, ext.name == "Extension", ext.children.count == 1,
                  ["true","false","1","0"].contains(ext.attributes["Critical"] ?? "") else {
                return "Unsupported extension structure or criticality"
            }
            let node = ext.children[0]
            if node.namespace == sie && node.name == "Qualifications" {
                guard TLQualificationRules.evaluate([ext], material: SyntaxFacts()) != nil else {
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
