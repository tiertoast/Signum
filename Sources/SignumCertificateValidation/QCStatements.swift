import Foundation
import SignumTrustCore

public struct QCLimitValue: Equatable, Sendable {
    public let currency: String
    public let amount: Int64, exponent: Int64
}
public struct QCPDS: Equatable, Sendable {
    public let url: String, language: String
}
public struct QCStatements: Equatable, Sendable {
    public internal(set) var compliance = false, sscd = false
    public internal(set) var types: [String] = []
    public internal(set) var limitValue: QCLimitValue?
    public internal(set) var retentionPeriod: Int64?
    public internal(set) var pds: [QCPDS] = []
    public internal(set) var unsupported: [String] = []
    public internal(set) var issue = ""
    public static func parse(certificate: Data) -> Self {
        do { return try CertificateQualificationMaterial(certificate).qc }
        catch { var r = Self(); r.issue = "QCStatements o certificato DER non interpretabili: \(error)"; return r }
    }
}

/// Strict DER ingestion only. Certificate signatures and RFC 5280 remain in the B engine.
struct QualificationDER {
    enum Failure: Error { case malformed, unsupported }
    let tag: UInt8, bytes: [UInt8]
    init(_ data: Data) throws { var i = 0; self = try Self.read(Array(data), &i); guard i == data.count else { throw Failure.malformed } }
    private init(tag: UInt8, bytes: [UInt8]) { self.tag = tag; self.bytes = bytes }
    static func read(_ data: [UInt8], _ i: inout Int) throws -> Self {
        guard i + 2 <= data.count else { throw Failure.malformed }
        let tag = data[i]; i += 1
        guard tag & 31 != 31 else { throw Failure.unsupported }
        var n = Int(data[i]); i += 1
        if n & 128 != 0 {
            let count = n & 127
            guard count > 0, count <= 3, i + count <= data.count, data[i] != 0 else { throw Failure.malformed }
            n = 0
            for _ in 0..<count { n = n * 256 + Int(data[i]); i += 1 }
            guard n >= 128 else { throw Failure.malformed }
        }
        guard n <= 65536, n <= data.count - i else { throw Failure.malformed }
        defer { i += n }; return .init(tag: tag, bytes: Array(data[i..<i+n]))
    }
    func children(_ expected: UInt8 = 0x30) throws -> [Self] {
        guard tag == expected else { throw Failure.malformed }
        var i = 0, r = [Self]()
        while i < bytes.count { guard r.count < 128 else { throw Failure.unsupported }; r.append(try Self.read(bytes, &i)) }
        return r
    }
    func oid() throws -> String {
        guard tag == 6, !bytes.isEmpty else { throw Failure.malformed }
        var values = [UInt64](), value: UInt64 = 0, start = true
        for b in bytes {
            guard !(start && b == 128), value <= UInt64.max >> 7 else { throw Failure.malformed }
            value = value << 7 | UInt64(b & 127); start = false
            if b & 128 == 0 { values.append(value); value = 0; start = true }
        }
        guard start, let first = values.first else { throw Failure.malformed }
        return ([min(first / 40,2),first - min(first / 40,2)*40] + values.dropFirst()).map(String.init).joined(separator: ".")
    }
    func integer() throws -> Int64 {
        guard tag == 2, !bytes.isEmpty, bytes.count <= 8 else { throw Failure.malformed }
        if bytes.count > 1 {
            guard !(bytes[0] == 0 && bytes[1] < 128), !(bytes[0] == 255 && bytes[1] >= 128) else { throw Failure.malformed }
        }
        var n: Int64 = bytes[0] & 128 == 0 ? 0 : -1
        for b in bytes { n = n &<< 8 | Int64(b) }; return n
    }
    func string(_ expected: UInt8) throws -> String {
        guard tag == expected, bytes.allSatisfy({ $0 >= 32 && $0 < 127 }), let s = String(bytes: bytes,encoding: .ascii) else { throw Failure.malformed }; return s
    }
    func date() throws -> Date {
        let format: String
        switch tag { case 23: format = "yyMMddHHmmss'Z'"; case 24: format = "yyyyMMddHHmmss'Z'"; default: throw Failure.malformed }
        let s = try string(tag)
        guard s.count == (tag == 23 ? 13 : 15), s.last == "Z", s.dropLast().allSatisfy(\.isNumber) else { throw Failure.malformed }
        let f = DateFormatter(); f.locale = Locale(identifier:"en_US_POSIX"); f.timeZone = TimeZone(secondsFromGMT:0); f.dateFormat = format; f.isLenient = false
        // RFC 5280 UTCTime pivot: 1950...2049.
        f.twoDigitStartDate = ISO8601DateFormatter().date(from:"1950-01-01T00:00:00Z")
        guard let d = f.date(from:s) else { throw Failure.malformed }; return d
    }
}
struct CertificateQualificationMaterial {
    var qc = QCStatements()
    var policies = Set<String>()
    var keyUsage: [String:Bool] = [:]
    let notBefore: Date
    init(_ certificate: Data) throws {
        guard certificate.count <= 65536 else { throw QualificationDER.Failure.unsupported }
        let cert = try QualificationDER(certificate).children(); guard cert.count == 3 else { throw QualificationDER.Failure.malformed }
        let tbs = try cert[0].children(); let offset = tbs.first?.tag == 0xa0 ? 1 : 0
        guard tbs.count >= offset + 6 else { throw QualificationDER.Failure.malformed }
        let validity = try tbs[offset+3].children(); guard validity.count == 2 else { throw QualificationDER.Failure.malformed }
        notBefore = try validity[0].date()
        let containers = tbs.dropFirst(offset+6).filter { $0.tag == 0xa3 }
        guard containers.count <= 1 else { throw QualificationDER.Failure.malformed }
        guard let container = containers.first else { return }
        let sequence = try container.children(0xa3); guard sequence.count == 1 else { throw QualificationDER.Failure.malformed }
        var seen = Set<String>()
        for ext in try sequence[0].children() {
            let fields = try ext.children(); guard fields.count == 2 || fields.count == 3 else { throw QualificationDER.Failure.malformed }
            let oid = try fields[0].oid(); guard seen.insert(oid).inserted, let value = fields.last, value.tag == 4 else { throw QualificationDER.Failure.malformed }
            if fields.count == 3 { guard fields[1].tag == 1, fields[1].bytes == [255] else { throw QualificationDER.Failure.malformed } }
            if oid == "1.3.6.1.5.5.7.1.3" { qc = try Self.statements(Data(value.bytes)) }
            if oid == "2.5.29.32" {
                for p in try QualificationDER(Data(value.bytes)).children() { let v = try p.children(); guard !v.isEmpty else { throw QualificationDER.Failure.malformed }; policies.insert(try v[0].oid()) }
            }
            if oid == "2.5.29.15" {
                let bits = try QualificationDER(Data(value.bytes)); guard bits.tag == 3, bits.bytes.count >= 2, bits.bytes.count <= 3, bits.bytes[0] <= 7 else { throw QualificationDER.Failure.malformed }
                guard (bits.bytes.count-1)*8-Int(bits.bytes[0]) <= 9,
                      bits.bytes.last! & UInt8((1 << Int(bits.bytes[0])) - 1) == 0 else { throw QualificationDER.Failure.malformed }
                let names = ["digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","crlSign","encipherOnly","decipherOnly"]
                for (i,name) in names.enumerated() { keyUsage[name] = 1+i/8 < bits.bytes.count && bits.bytes[1+i/8] & (128 >> (i%8)) != 0 }
            }
        }
    }
    static func statements(_ data: Data) throws -> QCStatements {
        var r = QCStatements(), seen = Set<String>()
        let statements = try QualificationDER(data).children(); guard !statements.isEmpty, statements.count <= 32 else { throw QualificationDER.Failure.malformed }
        for statement in statements {
            let fields = try statement.children(); guard fields.count == 1 || fields.count == 2 else { throw QualificationDER.Failure.malformed }
            let oid = try fields[0].oid(); guard seen.insert(oid).inserted else { throw QualificationDER.Failure.malformed }
            switch oid {
            case "0.4.0.1862.1.1", "0.4.0.1862.1.4":
                guard fields.count == 1 else { throw QualificationDER.Failure.malformed }
                if oid.hasSuffix(".1") { r.compliance = true } else { r.sscd = true }
            case "0.4.0.1862.1.6":
                guard fields.count == 2 else { throw QualificationDER.Failure.malformed }
                r.types = try fields[1].children().map { try $0.oid() }
                guard !r.types.isEmpty, Set(r.types).count == r.types.count else { throw QualificationDER.Failure.malformed }
            case "0.4.0.1862.1.2":
                guard fields.count == 2 else { throw QualificationDER.Failure.malformed }
                let v = try fields[1].children(); guard v.count == 3 else { throw QualificationDER.Failure.malformed }
                let currency: String
                if v[0].tag == 2 { let n = try v[0].integer(); guard (1...999).contains(n) else { throw QualificationDER.Failure.malformed }; currency = String(n) }
                else { currency = try v[0].string(19); guard currency.count == 3, currency.utf8.allSatisfy({ (65...90).contains($0) }) else { throw QualificationDER.Failure.malformed } }
                let amount = try v[1].integer(); guard amount >= 0 else { throw QualificationDER.Failure.malformed }
                r.limitValue = .init(currency:currency,amount:amount,exponent:try v[2].integer())
            case "0.4.0.1862.1.3":
                guard fields.count == 2 else { throw QualificationDER.Failure.malformed }; let n = try fields[1].integer(); guard n >= 0 else { throw QualificationDER.Failure.malformed }; r.retentionPeriod = n
            case "0.4.0.1862.1.5":
                guard fields.count == 2 else { throw QualificationDER.Failure.malformed }
                for entry in try fields[1].children() {
                    let v = try entry.children(); guard v.count == 2 else { throw QualificationDER.Failure.malformed }
                    let url = try v[0].string(22), language = try v[1].string(19)
                    guard url.count <= 2048, language.count == 2, language.utf8.allSatisfy({ (97...122).contains($0) }) else { throw QualificationDER.Failure.malformed }
                    r.pds.append(.init(url:url,language:language)) // Informational only; never fetched.
                }
                guard !r.pds.isEmpty else { throw QualificationDER.Failure.malformed }
            default: r.unsupported.append(oid)
            }
        }
        return r
    }
}

// Shared interpretation rules; certificate decoding remains in this module.
extension CertificateQualificationMaterial: TLQualificationMaterial {}
