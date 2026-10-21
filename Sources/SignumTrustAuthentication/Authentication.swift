import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import CryptoKit
import CXMLSecurity
import SignumTrustCore

public enum TLAuthenticationError: Error, CustomStringConvertible {
    case rejected(String)
    public var description: String { if case .rejected(let message) = self { return message }; return "rejected" }
}

/// Only establishes signed TL provenance, never certificate qualification.
/// Construction is private: consumers cannot promote raw parser output themselves.
public struct AuthenticatedTL: Sendable {
    public let document: UntrustedTLDocument
    public let signerSHA256: Data
    public let revision: UntrustedTLRevision
    public let schemeInformationURIs: [String]
    fileprivate init(document: UntrustedTLDocument, signer: Data, revision: UntrustedTLRevision, uris: [String]) {
        self.document = document; signerSHA256 = signer; self.revision = revision; schemeInformationURIs = uris
    }
}

public enum TLAuthenticator {
    // xmlsec initialization/verification serialized; no process-global parser callbacks changed.
    private static let lock = NSLock()
    static func schemeURIs(in xml: Data) throws -> [String] {
        let fields = AuthenticationFields()
        let parser = XMLParser(data: xml)
        parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = fields
        guard parser.parse() else { throw TLAuthenticationError.rejected("invalid pivot discovery XML") }
        return fields.uris
    }
    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    /// Anchors are supplied by a trusted policy, never derived from this document.
    public static func authenticate(_ xml: Data, authorizedCertificateSHA256: Set<Data>,
                                    territory: String, now: Date,
                                    previous: AuthenticatedTL? = nil) throws -> AuthenticatedTL {
        _ = try UntrustedTLParser.parse(xml) // bounded UTF-8, no DTD, bounded depth/nodes
        let fields = AuthenticationFields()
        let parser = XMLParser(data: xml)
        parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = fields
        guard parser.parse(), fields.certificates.count == 1,
              let cert = Data(base64Encoded: fields.certificates[0].filter { !$0.isWhitespace }),
              authorizedCertificateSHA256.contains(sha256(cert)) else {
            throw TLAuthenticationError.rejected("signer not authorized by external anchor")
        }
        guard let schema = Bundle.module.url(forResource: "validation", withExtension: "xsd", subdirectory: "Schemas") else { throw TLAuthenticationError.rejected("missing bundled schema") }
        var error = [CChar](repeating: 0, count: 512)
        lock.lock()
        let ok = xml.withUnsafeBytes { x in cert.withUnsafeBytes { c in
            signum_xml_verify(x.bindMemory(to: UInt8.self).baseAddress, xml.count,
                              c.bindMemory(to: UInt8.self).baseAddress, cert.count, schema.path, &error, error.count)
        }}
        lock.unlock()
        guard ok == 1 else { throw TLAuthenticationError.rejected(String(cString: error)) }
        // Parse the exact authenticated bytes. No reserialization between verification and consumption.
        let parsed = try UntrustedTLParser.parse(xml)
        guard parsed.version == 6, parsed.territory == territory else {
            throw TLAuthenticationError.rejected("TLv6/territory required")
        }
        let revision = try UntrustedTLRevision(document: parsed, xmlSHA256: sha256(xml))
        if case .rejected(let reason) = TLContinuityPolicy.assess(previous: previous?.revision, candidate: revision, now: now) {
            throw TLAuthenticationError.rejected("continuity: \(reason)")
        }
        return AuthenticatedTL(document: parsed, signer: sha256(cert), revision: revision, uris: fields.uris)
    }

    /// Select machine-readable national lists solely from an authenticated, current LOTL.
    /// Country hints select acquisition; only the signed certificate identities authorize it.
    public static func nationalPointer(country: String, lotl: AuthenticatedTL, now: Date) throws -> TLPointer {
        guard EUTrustPolicy.countries.contains(country), lotl.document.territory == "EU",
              lotl.document.issuedAt <= now.addingTimeInterval(300), lotl.document.nextUpdate > now else {
            throw TLAuthenticationError.rejected("current EU LOTL and EU/EEA territory required")
        }
        let pointers = lotl.document.pointers.filter {
            $0.territory == country && $0.mimeType == "application/vnd.etsi.tsl+xml"
        }
        guard pointers.count == 1, !pointers[0].signingCertificateDERs.isEmpty,
              let url = URL(string: pointers[0].location),
              ["http", "https"].contains(url.scheme), url.host != nil,
              url.user == nil, url.password == nil, url.fragment == nil,
              url.port == nil || url.port == (url.scheme == "https" ? 443 : 80) else {
            throw TLAuthenticationError.rejected("unique authenticated national XML pointer required")
        }
        return pointers[0]
    }
    public static func authenticateNational(_ xml: Data, country: String, lotl: AuthenticatedTL,
                                            now: Date, previous: AuthenticatedTL? = nil) throws -> AuthenticatedTL {
        let pointer = try nationalPointer(country: country, lotl: lotl, now: now)
        return try authenticate(xml, authorizedCertificateSHA256: Set(pointer.signingCertificateDERs.map(sha256)),
                                territory: country, now: now, previous: previous)
    }

    public static func authenticateItaly(_ xml: Data, lotl: AuthenticatedTL, now: Date,
                                         previous: AuthenticatedTL? = nil) throws -> AuthenticatedTL {
        let pointer = try italyPointer(lotl: lotl, now: now)
        return try authenticate(xml, authorizedCertificateSHA256: Set(pointer.signingCertificateDERs.map(sha256)), territory: "IT", now: now, previous: previous)
    }
    public static func italyPointer(lotl: AuthenticatedTL, now: Date) throws -> TLPointer {
        guard lotl.document.territory == "EU", lotl.document.issuedAt <= now.addingTimeInterval(300), lotl.document.nextUpdate > now else {
            throw TLAuthenticationError.rejected("current authenticated EU LOTL required")
        }
        let pointers = lotl.document.pointers.filter { $0.territory == "IT" && $0.location == EUTrustPolicy.italyLocation }
        guard pointers.count == 1, !pointers[0].signingCertificateDERs.isEmpty else {
            throw TLAuthenticationError.rejected("unique authenticated Italian XML pointer required")
        }
        return pointers[0]
    }

}

public enum EUTrustPolicy {
    /// EU + EEA, using the Commission's EL territory code; UK is intentionally excluded.
    public static let countries: Set<String> = Set("AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IS IT LI LT LU LV MT NL NO PL PT RO SE SI SK".split(separator: " ").map(String.init))
    public static let location = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
    public static let italyLocation = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
    public static let journal = "https://eur-lex.europa.eu/eli/C/2026/1944/oj"
    /// OJ C/2026/1944, 15 April 2026, section 1. SHA-1 intentionally unused.
    public static let journalAnchors: Set<Data> = Set([
        "wGQcT31WxDGxySR0Lbf86cHu99f9ISETonaEhrOrzcU=",
        "4KYg+7Z0c2K7kzrEQWnWdqVTREcWz18xYF8SoiuDlrE=",
        "334pNgw0srjW1fQDJcHU0SyZIs7NM7dAdnSnSys8oeU=",
        "tj1BZ0TnCYv57CyqWWqTvCRo43+ChLpl7MBhcRvLqhg=",
        "I2ED8DqAMa6PR/kFm/jeOFZM2/6+3eSll9UPiYCqZTs=",
        "0gZP3XD2mC3MUWuG2dXFauqTlBfGJLLkeMCyneVPhHQ="
    ].map { Data(base64Encoded: $0)! })
}

private final class AuthenticationFields: NSObject, XMLParserDelegate {
    private var stack: [String] = []
    private var text: [String] = []
    var certificates: [String] = []
    var uris: [String] = []
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes: [String: String]) {
        stack.append((namespaceURI ?? "") + "|" + elementName); text.append("")
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { if !text.isEmpty { text[text.count-1] += string } }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        let value = text.removeLast().trimmingCharacters(in: .whitespacesAndNewlines)
        let t = "http://uri.etsi.org/02231/v2#|", d = "http://www.w3.org/2000/09/xmldsig#|"
        if stack == [t+"TrustServiceStatusList",d+"Signature",d+"KeyInfo",d+"X509Data",d+"X509Certificate"] { certificates.append(value) }
        if stack == [t+"TrustServiceStatusList",t+"SchemeInformation",t+"SchemeInformationURI",t+"URI"] { uris.append(value) }
        stack.removeLast()
    }
}
