import Foundation
import SignumTrustCore

/// Resolve an event's SKI against full certificates already authenticated in the
/// SAME service. A certificate supplied by a document is never promoted by its SKI.
enum TLServiceIdentityResolver {
    static func certificates(_ event: TLServiceEvent, service: TLService) -> [Data] {
        let pool = event.certificateDERs.isEmpty ? service.certificateDERs + service.history.flatMap(\.certificateDERs) : event.certificateDERs
        let skis = Set(event.subjectKeyIdentifiers)
        guard skis.count <= 1, !pool.isEmpty, !event.certificateDERs.isEmpty || skis.count == 1 else { return [] }
        let names = event.subjectNames.compactMap(distinguishedName)
        guard names.count == event.subjectNames.count else { return [] }
        var matches = [(Data,Data)](), seen = Set<Data>()
        for der in pool where seen.insert(der).inserted {
            guard let facts = try? CertificateQualificationMaterial(der) else { continue }
            if let ski = skis.first, facts.subjectKeyIdentifier != ski { continue }
            if !names.allSatisfy({ $0 == facts.subjectDN }) { continue }
            matches.append((der,facts.identityKey))
        }
        // Aliases may carry different validity windows, but not different keys/names.
        guard !matches.isEmpty, Set(matches.map(\.1)).count == 1,
              event.certificateDERs.isEmpty || matches.count == seen.count else { return [] }
        return matches.map(\.0)
    }
    private static func attribute(_ oid: String,_ value: String) -> String {
        oid + ":" + Data(value.precomposedStringWithCanonicalMapping.utf8).base64EncodedString()
    }
    static func subject(_ node: QualificationDER) throws -> [[String]] {
        try node.children().map { set in
            let values = try set.children(0x31).map { pair -> String in
                let fields = try pair.children(); guard fields.count == 2 else { throw QualificationDER.Failure.malformed }
                return attribute(try fields[0].oid(),try string(fields[1]))
            }
            guard !values.isEmpty else { throw QualificationDER.Failure.malformed }
            return values.sorted()
        }
    }
    private static func string(_ node: QualificationDER) throws -> String {
        let encoding: String.Encoding
        switch node.tag {
        case 12: encoding = .utf8
        case 19,22: encoding = .ascii
        case 20: encoding = .isoLatin1
        case 30: encoding = .utf16BigEndian
        default: throw QualificationDER.Failure.unsupported
        }
        guard let value = String(data:Data(node.bytes),encoding:encoding), !value.contains("\0") else { throw QualificationDER.Failure.malformed }
        return value
    }
    /// Conservative RFC4514 textual correspondence: numeric OIDs/common X.500
    /// aliases, escaped separators/UTF8 hex, quoted values and multi-valued RDNs.
    /// Unsupported syntax does not authorize an identity by display name.
    static func distinguishedName(_ text: String) -> [[String]]? {
        let aliases = ["CN":"2.5.4.3","C":"2.5.4.6","L":"2.5.4.7","ST":"2.5.4.8","O":"2.5.4.10","OU":"2.5.4.11",
            "SERIALNUMBER":"2.5.4.5","STREET":"2.5.4.9","TITLE":"2.5.4.12","SN":"2.5.4.4","SURNAME":"2.5.4.4",
            "GIVENNAME":"2.5.4.42","GN":"2.5.4.42","DC":"0.9.2342.19200300.100.1.25","UID":"0.9.2342.19200300.100.1.1",
            "EMAILADDRESS":"1.2.840.113549.1.9.1","E":"1.2.840.113549.1.9.1","ORGANIZATIONIDENTIFIER":"2.5.4.97"]
        func split(_ s: String,_ separator: Character) -> [String]? {
            var pieces = [String](), value = "", quoted = false, escaped = false
            for c in s {
                if escaped { value.append(c); escaped = false; continue }
                if c == "\\" { escaped = true; value.append(c); continue }
                if c == "\"" { quoted.toggle(); value.append(c); continue }
                if c == separator && !quoted { pieces.append(value);value = "" } else { value.append(c) }
            }
            guard !quoted, !escaped else { return nil }; pieces.append(value);return pieces
        }
        func decode(_ raw: String) -> String? {
            var value = raw.trimmingCharacters(in:.whitespaces)
            if value.hasPrefix("\"") && value.hasSuffix("\"") { value = String(value.dropFirst().dropLast()) }
            if value.hasPrefix("#") {
                let hex = Array(value.dropFirst());guard hex.count.isMultiple(of:2) else { return nil }
                var bytes = [UInt8]();for i in stride(from:0,to:hex.count,by:2) { guard let b = UInt8(String(hex[i...i+1]),radix:16) else { return nil };bytes.append(b) }
                return (try? QualificationDER(Data(bytes))).flatMap { try? string($0) }
            }
            let chars = Array(value);var i = 0, bytes = [UInt8]()
            while i < chars.count {
                if chars[i] == "\\" {
                    i += 1;guard i < chars.count else { return nil }
                    if i+1 < chars.count, let b = UInt8(String(chars[i...i+1]),radix:16) { bytes.append(b);i += 2;continue }
                    guard ",+\"\\<>;=# ".contains(chars[i]) else { return nil }
                } else if chars[i] == "\"" { return nil }
                bytes.append(contentsOf:String(chars[i]).utf8);i += 1
            }
            return String(bytes:bytes,encoding:.utf8)
        }
        guard let rdns = split(text,",") else { return nil }
        var result = [[String]]()
        for rdn in rdns.reversed() {
            guard let pairs = split(rdn,"+") else { return nil };var attributes = [String]()
            for pair in pairs {
                guard let equal = pair.firstIndex(of:"=") else { return nil }
                let name = pair[..<equal].trimmingCharacters(in:.whitespaces)
                let oid = aliases[name.uppercased()] ?? (name.hasPrefix("OID.") ? String(name.dropFirst(4)) : name)
                guard oid.split(separator:".").count >= 2, oid.allSatisfy({ $0.isNumber || $0 == "." }),
                      let value = decode(String(pair[pair.index(after:equal)...])) else { return nil }
                attributes.append(attribute(oid,value))
            }
            result.append(attributes.sorted())
        }
        return result
    }
}
