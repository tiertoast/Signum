import Foundation

/// Informational certificate text only. Never participates in trust or qualification.
public struct CertificatePolicyPresentation: Sendable {
    public struct Policy: Sendable {
        public let oid: String
        public let notices: [String]
        public let cps: [String]
    }
    public let policies: [Policy]
    public let available: Bool
    public var agidDeclared: Bool {
        policies.contains { policy in
            policy.oid == "1.3.76.16.6" && policy.notices.contains { text in
                let normalized = text.lowercased().split(whereSeparator: \.isWhitespace).joined(separator: " ")
                return normalized.range(of: #"^questo certificato rispetta le raccomandazioni previste dalla determinazione agid n\. ?121/2019\.?$"#, options: .regularExpression) != nil
            }
        }
    }
    public var summary: String {
        agidDeclared ? "Raccomandazioni AgID: dichiarate dal certificatore" : "Raccomandazioni AgID: non valutate"
    }
    public static let reference = "Determinazione AgID 121/2019, rettificata dalla 147/2019 (OID 1.3.76.16.6). Dichiarazione del certificatore, non verifica autonoma di conformità. Distinta dalla Determinazione 189/2017, che modifica la Deliberazione 45/2009."
    public init(certificate: Data?) {
        do {
            guard let certificate, certificate.count <= 65536 else { throw PolicyDER.Failure.invalid }
            let outer = try PolicyDER(certificate).children()
            guard outer.count == 3 else { throw PolicyDER.Failure.invalid }
            let tbs = try outer[0].children()
            let extensions = tbs.filter { $0.tag == 0xa3 }
            guard extensions.count <= 1 else { throw PolicyDER.Failure.invalid }
            var result = [Policy](), seen = false
            if let ext = extensions.first {
                let wrapper = try ext.children(0xa3)
                guard wrapper.count == 1 else { throw PolicyDER.Failure.invalid }
                for item in try wrapper[0].children() {
                    let fields = try item.children()
                    guard (2...3).contains(fields.count), fields.last?.tag == 4 else { throw PolicyDER.Failure.invalid }
                    guard try fields[0].oid() == "2.5.29.32" else { continue }
                    guard !seen else { throw PolicyDER.Failure.invalid }; seen = true
                    for policy in try PolicyDER(Data(fields.last!.bytes)).children() {
                        let parts = try policy.children()
                        guard (1...2).contains(parts.count) else { throw PolicyDER.Failure.invalid }
                        let oid = try parts[0].oid()
                        var notices = [String](), cps = [String]()
                        if parts.count == 2 {
                            for qualifier in try parts[1].children() {
                                let q = try qualifier.children()
                                guard q.count == 2 else { throw PolicyDER.Failure.invalid }
                                switch try q[0].oid() {
                                case "1.3.6.1.5.5.7.2.1": cps.append(try q[1].string())
                                case "1.3.6.1.5.5.7.2.2":
                                    let notice = try q[1].children()
                                    // ExplicitText is the last DisplayText, never NoticeReference.
                                    if let text = notice.last, text.tag != 0x30 { notices.append(try text.string()) }
                                default: break
                                }
                            }
                        }
                        result.append(.init(oid: oid, notices: notices, cps: cps))
                    }
                }
            }
            policies = result; available = true
        } catch { policies = []; available = false }
    }
}

/// Bounded, presentation-only DER reader; rejects indefinite/nonminimal lengths.
private struct PolicyDER {
    enum Failure: Error { case invalid }
    let tag: UInt8, bytes: [UInt8]
    init(_ data: Data) throws {
        var i = 0; self = try Self.read(Array(data), &i)
        guard i == data.count else { throw Failure.invalid }
    }
    private init(_ tag: UInt8, _ bytes: [UInt8]) { self.tag = tag; self.bytes = bytes }
    private static func read(_ b: [UInt8], _ i: inout Int) throws -> Self {
        guard i + 2 <= b.count, b[i] & 31 != 31 else { throw Failure.invalid }
        let tag = b[i]; i += 1
        var n = Int(b[i]); i += 1
        if n & 128 != 0 {
            let count = n & 127
            guard count > 0, count <= 3, i + count <= b.count, b[i] != 0 else { throw Failure.invalid }
            n = 0
            for _ in 0..<count { n = n * 256 + Int(b[i]); i += 1 }
            guard n >= 128 else { throw Failure.invalid }
        }
        guard n <= 65536, n <= b.count - i else { throw Failure.invalid }
        defer { i += n }; return .init(tag, Array(b[i..<i+n]))
    }
    func children(_ expected: UInt8 = 0x30) throws -> [Self] {
        guard tag == expected else { throw Failure.invalid }
        var i = 0, result = [Self]()
        while i < bytes.count {
            guard result.count < 128 else { throw Failure.invalid }
            result.append(try Self.read(bytes, &i))
        }
        return result
    }
    func oid() throws -> String {
        guard tag == 6, !bytes.isEmpty else { throw Failure.invalid }
        var values = [UInt64](), value: UInt64 = 0, start = true
        for b in bytes {
            guard !(start && b == 128), value <= UInt64.max >> 7 else { throw Failure.invalid }
            value = value << 7 | UInt64(b & 127); start = false
            if b & 128 == 0 { values.append(value); value = 0; start = true }
        }
        guard start, let first = values.first else { throw Failure.invalid }
        return ([min(first / 40, 2), first - min(first / 40, 2) * 40] + values.dropFirst()).map(String.init).joined(separator: ".")
    }
    func string() throws -> String {
        let encoding: String.Encoding
        switch tag { case 12, 19, 22, 26: encoding = .utf8; case 30: encoding = .utf16BigEndian; default: throw Failure.invalid }
        guard let text = String(data: Data(bytes), encoding: encoding) else { throw Failure.invalid }
        return text
    }
}
