import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif

/// Raw ETSI Trusted List fields. Parsing does NOT establish authenticity,
/// integrity, issuer authority, trust, revocation, or qualification.
public struct UntrustedTLDocument: Sendable {
    public let version: Int
    public let sequenceNumber: Int
    public let territory: String
    public let issuedAt: Date
    public let nextUpdate: Date
    public let providers: [TLProvider]
    public let pointers: [TLPointer]
    /// Presence of an enveloped ds:Signature, NOT successful verification.
    public let containsSignatureElement: Bool
}

public struct TLProvider: Sendable {
    public let name: String
    public let services: [TLService]
}

/// Bounded, namespace-preserving extension tree. Authenticity is established separately.
public struct TLServiceExtension: Sendable {
    public let name: String, namespace: String, text: String
    public let attributes: [String: String]
    public let children: [TLServiceExtension]
}

public struct TLService: Sendable {
    public let name: String
    public let typeURI: String
    public let statusURI: String
    public let statusSince: Date
    public let certificateDERs: [Data]
    public let history: [TLServiceHistory]
    public var extensions: [TLServiceExtension] = []
}

public struct TLServiceHistory: Sendable {
    public var extensions: [TLServiceExtension] = []
    public let certificateDERs: [Data]
    public let typeURI: String
    public let statusURI: String
    public let statusSince: Date
}

public struct TLPointer: Sendable {
    /// Untrusted input: do not fetch or authorize using this URL until LOTL validation.
    public let location: String
    public let territory: String?
    public let signingCertificateDERs: [Data]
    public var mimeType: String? = nil
}

public enum TLParseError: Error, Equatable {
    case tooLarge
    case invalidUTF8
    case forbiddenDTD
    case invalidXML
    case invalidRoot
    case invalidStructure
    case unsupportedVersion
    case resourceLimit
}

/// Safe, bounded ingestion for an *untrusted* TL/LOTL XML document.
/// This does not perform ETSI schema or XMLDSig/XAdES validation.
public enum UntrustedTLParser {
    public static let maximumInputBytes = 64 * 1024 * 1024

    public static func parse(_ xml: Data) throws -> UntrustedTLDocument {
        guard xml.count <= maximumInputBytes else { throw TLParseError.tooLarge }
        guard let text = String(data: xml, encoding: .utf8) else { throw TLParseError.invalidUTF8 }
        // Do not permit DTD declarations or custom entities in this ingestion path.
        // The XML parser also has external entity resolution disabled.
        let upper = text.uppercased()
        guard !upper.contains("<!DOCTYPE"), !upper.contains("<!ENTITY") else {
            throw TLParseError.forbiddenDTD
        }
        let delegate = Collector()
        let parser = XMLParser(data: xml)
        parser.delegate = delegate
        parser.shouldProcessNamespaces = true
        parser.shouldResolveExternalEntities = false
        guard parser.parse() else { throw delegate.failure ?? .invalidXML }
        return try delegate.document()
    }
}

private final class Collector: NSObject, XMLParserDelegate {
    private static let tlNS = "http://uri.etsi.org/02231/v2#"
    private static let dsNS = "http://www.w3.org/2000/09/xmldsig#"
    private static let maximumNodes = 500_000
    private static let maximumDepth = 64

    struct ProviderDraft {
        var name = ""
        var services: [TLService] = []
    }
    struct ServiceDraft {
        var name = ""
        var type = ""
        var status = ""
        var date = ""
        var certs: [Data] = []
        var history: [TLServiceHistory] = []
        var extensions: [TLServiceExtension] = []
    }
    struct HistoryDraft {
        var extensions: [TLServiceExtension] = []
        var certs: [Data] = []
        var type = ""
        var status = ""
        var date = ""
    }
    struct PointerDraft {
        var mimeType: String?
        var location = ""
        var territory: String?
        var certs: [Data] = []
    }

    struct ExtensionDraft {
        let name: String, namespace: String, attributes: [String:String]
        var children: [TLServiceExtension] = []
    }
    private var extensionStack: [ExtensionDraft] = []
    var failure: TLParseError?
    private var stack: [String] = []
    private var namespaceStack: [String] = []
    private var content: [String] = []
    private var nodes = 0
    private var version: Int?
    private var sequence: Int?
    private var territory: String?
    private var issue: String?
    private var next: String?
    private var signature = false
    private var providers: [TLProvider] = []
    private var pointers: [TLPointer] = []
    private var provider: ProviderDraft?
    private var service: ServiceDraft?
    private var history: HistoryDraft?
    private var pointer: PointerDraft?

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?,
                attributes attributeDict: [String: String] = [:]) {
        nodes += 1
        let ns = namespaceURI ?? ""
        if nodes > Self.maximumNodes || stack.count >= Self.maximumDepth {
            failure = .resourceLimit
            parser.abortParsing()
            return
        }
        if stack.isEmpty && (elementName != "TrustServiceStatusList" || ns != Self.tlNS) {
            failure = .invalidRoot
            parser.abortParsing()
            return
        }
        stack.append(elementName)
        namespaceStack.append(ns)
        content.append("")
        if ns == Self.tlNS {
            if matches(["TrustServiceProviderList", "TrustServiceProvider"]) { provider = ProviderDraft() }
            if matches(["TSPServices", "TSPService"]) { service = ServiceDraft() }
            if matches(["ServiceHistory", "ServiceHistoryInstance"]) { history = HistoryDraft() }
            if matches(["PointersToOtherTSL", "OtherTSLPointer"]) { pointer = PointerDraft() }
        }
        if !extensionStack.isEmpty || matches(["ServiceInformation", "ServiceInformationExtensions"]) || matches(["ServiceHistoryInstance", "ServiceInformationExtensions"]) {
            extensionStack.append(.init(name: elementName, namespace: ns, attributes: attributeDict))
        }
        if stack.count == 2 && elementName == "Signature" && ns == Self.dsNS { signature = true }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard !content.isEmpty else { return }
        content[content.count - 1] += string
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        guard !content.isEmpty, let string = String(data: CDATABlock, encoding: .utf8) else { return }
        content[content.count - 1] += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?) {
        guard !stack.isEmpty, !content.isEmpty else { return }
        let value = content.removeLast().trimmingCharacters(in: .whitespacesAndNewlines)
        let ns = namespaceStack.last
        if let draft = extensionStack.popLast() {
            let node = TLServiceExtension(name: draft.name, namespace: draft.namespace, text: value, attributes: draft.attributes, children: draft.children)
            if extensionStack.isEmpty {
                if history != nil { history?.extensions = node.children } else { service?.extensions = node.children }
            } else { extensionStack[extensionStack.count - 1].children.append(node) }
        }
        if namespaceStack == Array(repeating: Self.tlNS, count: 6) + ["http://uri.etsi.org/02231/v2/additionaltypes#"],
           stack == ["TrustServiceStatusList", "SchemeInformation", "PointersToOtherTSL", "OtherTSLPointer", "AdditionalInformation", "OtherInformation", "MimeType"] {
            if pointer?.mimeType != nil { failure = .invalidStructure }
            pointer?.mimeType = value
        }
        if ns == Self.tlNS {
            if matches(["SchemeInformation", "TSLVersionIdentifier"]) { version = Int(value) }
            if matches(["SchemeInformation", "TSLSequenceNumber"]) { sequence = Int(value) }
            if matches(["SchemeInformation", "SchemeTerritory"]) { territory = value }
            if matches(["SchemeInformation", "ListIssueDateTime"]) { issue = value }
            if matches(["SchemeInformation", "NextUpdate", "dateTime"]) { next = value }

            if pointer != nil {
                if matches(["OtherTSLPointer", "TSLLocation"]) { pointer?.location = value }
                if matches(["OtherTSLPointer", "AdditionalInformation", "OtherInformation", "SchemeTerritory"]) {
                    pointer?.territory = value
                }
                if matches(["OtherTSLPointer", "ServiceDigitalIdentities", "ServiceDigitalIdentity", "DigitalId", "X509Certificate"]) {
                    appendCertificate(value, toPointer: true)
                }
            }
            if provider != nil && matches(["TSPInformation", "TSPName", "Name"]) { provider?.name = value }
            if service != nil {
                if matches(["ServiceInformation", "ServiceName", "Name"]) { service?.name = value }
                if matches(["ServiceInformation", "ServiceTypeIdentifier"]) { service?.type = value }
                if matches(["ServiceInformation", "ServiceStatus"]) { service?.status = value }
                if matches(["ServiceInformation", "StatusStartingTime"]) { service?.date = value }
                if matches(["ServiceInformation", "ServiceDigitalIdentity", "DigitalId", "X509Certificate"]) {
                    appendCertificate(value, toPointer: false)
                }
                if history != nil {
                    if matches(["ServiceHistoryInstance", "ServiceDigitalIdentity", "DigitalId", "X509Certificate"]) { appendCertificate(value, toPointer: false, toHistory: true) }
                    if matches(["ServiceHistoryInstance", "ServiceTypeIdentifier"]) { history?.type = value }
                    if matches(["ServiceHistoryInstance", "ServiceStatus"]) { history?.status = value }
                    if matches(["ServiceHistoryInstance", "StatusStartingTime"]) { history?.date = value }
                }
                if matches(["ServiceHistory", "ServiceHistoryInstance"]) {
                    if let h = history, let date = Self.date(h.date), !h.type.isEmpty, !h.status.isEmpty {
                        service?.history.append(TLServiceHistory(extensions: h.extensions, certificateDERs: h.certs, typeURI: h.type, statusURI: h.status, statusSince: date))
                    } else { failure = .invalidStructure }
                    history = nil
                }
                if matches(["TSPServices", "TSPService"]) {
                    if let s = service, let date = Self.date(s.date), !s.type.isEmpty, !s.status.isEmpty {
                        provider?.services.append(TLService(name: s.name, typeURI: s.type,
                            statusURI: s.status, statusSince: date, certificateDERs: s.certs, history: s.history, extensions: s.extensions))
                    } else { failure = .invalidStructure }
                    service = nil
                }
            }
            if matches(["TrustServiceProviderList", "TrustServiceProvider"]) {
                if let p = provider, !p.name.isEmpty {
                    providers.append(TLProvider(name: p.name, services: p.services))
                } else { failure = .invalidStructure }
                provider = nil
            }
            if matches(["PointersToOtherTSL", "OtherTSLPointer"]) {
                if let p = pointer, !p.location.isEmpty {
                    pointers.append(TLPointer(location: p.location, territory: p.territory,
                                              signingCertificateDERs: p.certs, mimeType: p.mimeType))
                } else { failure = .invalidStructure }
                pointer = nil
            }
        }
        stack.removeLast()
        namespaceStack.removeLast()
        if failure != nil { parser.abortParsing() }
    }

    private func matches(_ path: [String]) -> Bool {
        // Absolute paths are essential: ds:Signature/ds:Object is excluded
        // from an enveloped root signature and can contain attacker-controlled
        // XML. Never let suffix matches in that subtree overwrite TL records.
        let root = ["TrustServiceStatusList"]
        let provider = root + ["TrustServiceProviderList", "TrustServiceProvider"]
        let service = provider + ["TSPServices", "TSPService"]
        let prefix: [String]
        switch path.first {
        case "SchemeInformation", "TrustServiceProviderList": prefix = root
        case "TSPInformation", "TSPServices": prefix = provider
        case "ServiceInformation", "ServiceHistory": prefix = service
        case "ServiceHistoryInstance": prefix = service + ["ServiceHistory"]
        case "PointersToOtherTSL": prefix = root + ["SchemeInformation"]
        case "OtherTSLPointer": prefix = root + ["SchemeInformation", "PointersToOtherTSL"]
        default: return false
        }
        return stack == prefix + path && namespaceStack.allSatisfy { $0 == Self.tlNS }

    }

    private func appendCertificate(_ raw: String, toPointer: Bool, toHistory: Bool = false) {
        let compact = raw.filter { !$0.isWhitespace }
        guard !compact.isEmpty, compact.utf8.count <= 128 * 1024,
              let cert = Data(base64Encoded: compact), cert.count <= 96 * 1024 else {
            failure = .invalidStructure
            return
        }
        if toPointer { pointer?.certs.append(cert) }
        else if toHistory { history?.certs.append(cert) }
        else { service?.certs.append(cert) }
    }

    private static func date(_ text: String) -> Date? {
        let date = ISO8601DateFormatter()
        date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let parsed = date.date(from: text) { return parsed }
        date.formatOptions = [.withInternetDateTime]
        return date.date(from: text)
    }

    func document() throws -> UntrustedTLDocument {
        if let failure { throw failure }
        guard let v = version, (v == 5 || v == 6) else { throw TLParseError.unsupportedVersion }
        guard let s = sequence, s > 0, let t = territory, t.count == 2,
              let i = issue.flatMap(Self.date), let n = next.flatMap(Self.date),
              n > i else { throw TLParseError.invalidStructure }
        return UntrustedTLDocument(version: v, sequenceNumber: s, territory: t,
            issuedAt: i, nextUpdate: n, providers: providers, pointers: pointers,
            containsSignatureElement: signature)
    }
}
