import Foundation

/// Human-readable fields taken from the public X.509 certificate.
/// These are informational only; they do NOT indicate trust or eIDAS qualification.
public struct SignumCertificateIdentity: Equatable, Sendable {
    public let fullName: String
    public let fiscalCode: String?
    /// Complete personal Subject givenName + surname; CN alone is not proof of a personal name.
    public let personalName: String?
    public let issuer: String?
    public let organization: String?

    /// Display identity and expected-certificate binding can share these exact
    /// public DER bytes; this does not evaluate eligibility or trust.
    public init(certificateDER: Data) throws {
        self = try CertificateIdentityReader.read(certificateDER)
    }

    init(fullName: String, fiscalCode: String?, issuer: String?, organization: String? = nil, personalName: String? = nil) {
        self.personalName = personalName
        self.fullName = fullName
        self.fiscalCode = fiscalCode
        self.issuer = issuer
        self.organization = organization
    }

    public var title: String {
        guard let fiscalCode else { return fullName }
        return "\(fullName) (\(fiscalCode))"
    }
}

enum CertificateIdentityReader {
    // X.520 AttributeType object identifiers, stored as DER OID content octets.
    private static let commonName = Data([0x55, 0x04, 0x03])   // 2.5.4.3
    private static let surname = Data([0x55, 0x04, 0x04])      // 2.5.4.4
    private static let serialNumber = Data([0x55, 0x04, 0x05]) // 2.5.4.5
    private static let givenName = Data([0x55, 0x04, 0x2A])    // 2.5.4.42
    private static let country = Data([0x55, 0x04, 0x06]) // 2.5.4.6
    private static let organization = Data([0x55, 0x04, 0x0A]) // 2.5.4.10

    static func read(_ certificate: Data) throws -> SignumCertificateIdentity {
        let bytes = [UInt8](certificate)
        guard !bytes.isEmpty && bytes.count <= 65_536 else {
            throw SignumError.invalidCertificate
        }

        var cursor = 0
        let outer = try DER.read(bytes, at: &cursor, limit: bytes.count)
        guard outer.tag == 0x30, cursor == bytes.count else {
            throw SignumError.invalidCertificate
        }

        cursor = outer.contents.lowerBound
        let tbs = try DER.read(bytes, at: &cursor, limit: outer.contents.upperBound)
        guard tbs.tag == 0x30 else { throw SignumError.invalidCertificate }
        cursor = tbs.contents.lowerBound

        var serial = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        if serial.tag == 0xA0 {
            serial = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        }
        guard serial.tag == 0x02 else { throw SignumError.invalidCertificate }
        let algorithm = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        guard algorithm.tag == 0x30 else { throw SignumError.invalidCertificate }
        let issuerNode = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        let validityNode = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        let subjectNode = try DER.read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        guard issuerNode.tag == 0x30, validityNode.tag == 0x30, subjectNode.tag == 0x30 else {
            throw SignumError.invalidCertificate
        }

        let subject = try readName(subjectNode, bytes: bytes)
        let issuer = try readName(issuerNode, bytes: bytes)
        let first = subject[givenName]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let last = subject[surname]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let composedName = [first, last].filter { !$0.isEmpty }.joined(separator: " ")
        let name = !composedName.isEmpty ? composedName : (subject[commonName] ?? "Certificato X.509")

        // Only structured personal identifiers: never scan arbitrary CN/organization text.
        let subjectSerial = subject[serialNumber]?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() ?? ""
        let italian = subject[country]?.uppercased() == "IT"
        let candidate = subjectSerial.hasPrefix("TINIT-") ? String(subjectSerial.dropFirst(6)) : (italian ? subjectSerial : "")
        var code = fiscalCode(in: candidate)
        // Existing CNS profile: CF/DEVICE-ID in CN, with a complete personal name.
        if code == nil, subject[serialNumber] == nil, !first.isEmpty, !last.isEmpty,
           let cn = subject[commonName], cn.contains("/") {
            code = fiscalCode(in: String(cn.split(separator:"/",omittingEmptySubsequences:false)[0]).uppercased())
        }

        return SignumCertificateIdentity(
            fullName: name,
            fiscalCode: code,
            issuer: issuer[commonName], organization: subject[organization],
            personalName: first.isEmpty || last.isEmpty ? nil : composedName
        )
    }

    private static func readName(_ name: DER.Node, bytes: [UInt8]) throws -> [Data: String] {
        var result = [Data: String]()
        var ambiguous = Set<Data>()
        var cursor = name.contents.lowerBound
        while cursor < name.contents.upperBound {
            let rdn = try DER.read(bytes, at: &cursor, limit: name.contents.upperBound)
            guard rdn.tag == 0x31 else { throw SignumError.invalidCertificate }
            var rdnCursor = rdn.contents.lowerBound
            while rdnCursor < rdn.contents.upperBound {
                let attribute = try DER.read(bytes, at: &rdnCursor, limit: rdn.contents.upperBound)
                guard attribute.tag == 0x30 else { throw SignumError.invalidCertificate }
                var attributeCursor = attribute.contents.lowerBound
                let type = try DER.read(bytes, at: &attributeCursor, limit: attribute.contents.upperBound)
                let value = try DER.read(bytes, at: &attributeCursor, limit: attribute.contents.upperBound)
                guard type.tag == 0x06, attributeCursor == attribute.contents.upperBound else {
                    throw SignumError.invalidCertificate
                }
                let oid = Data(bytes[type.contents])
                if let string = decodeString(value, bytes: bytes) {
                    if let previous=result[oid], previous != string { ambiguous.insert(oid) }
                    result[oid] = ambiguous.contains(oid) ? "" : string
                }
            }
        }
        return result
    }

    private static func decodeString(_ node: DER.Node, bytes: [UInt8]) -> String? {
        let octets = Data(bytes[node.contents])
        switch node.tag {
        case 0x0C, 0x13, 0x16: // UTF8String, PrintableString, IA5String
            return String(data: octets, encoding: .utf8)
        case 0x14: // TeletexString; best-effort fallback
            return String(data: octets, encoding: .isoLatin1)
        case 0x1E: // BMPString, UTF-16 big endian
            guard octets.count.isMultiple(of: 2) else { return nil }
            let units = stride(from: 0, to: octets.count, by: 2).map {
                UInt16(octets[$0]) << 8 | UInt16(octets[$0 + 1])
            }
            return String(decoding: units, as: UTF16.self)
        default:
            return nil
        }
    }

    private static func fiscalCode(in candidate: String) -> String? {
        // Italian personal CF including omocodia substitutions; this is identifier
        // extraction, not a registry/checksum attestation. VAT/NTR identifiers excluded.
        let pattern = #"\A[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]\z"#
        guard candidate.range(of: pattern, options: .regularExpression) != nil else { return nil }
        return candidate
    }
}
