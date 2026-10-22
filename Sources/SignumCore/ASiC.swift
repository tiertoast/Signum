#if os(macOS)
import Foundation
import CXMLSecurity

public enum ASiC {
    public enum Kind: String, Sendable { case simple = "asics", extended = "asice"
        public var mime: String { "application/vnd.etsi.asic-" + (self == .simple ? "s" : "e") + "+zip" }
        public var title: String { self == .simple ? "ASiC-S" : "ASiC-E" }
    }
    public struct Payload: Equatable, Sendable {
        public let name: String, data: Data
        public init(name: String,data: Data) { self.name = name; self.data = data }
    }
    public struct Verified: Sendable {
        public let kind: Kind
        public let payloads: [Payload]
        public let signature: XAdES.Verified
    }
    public static let maximumPayloads = 4
    public static let maximumPayloadBytes = 16 * 1024 * 1024
    static let signatureName = "META-INF/signatures.xml", manifestName = "META-INF/manifest.xml"
    static func nameKey(_ name: String) -> String { name.folding(options:[.caseInsensitive],locale:Locale(identifier:"en_US_POSIX")) }
    static func safePayloadName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 96, name.utf8.elementsEqual(name.precomposedStringWithCanonicalMapping.utf8),
              !name.hasPrefix("."), !name.hasPrefix(" "), !name.hasSuffix("."), !name.hasSuffix(" "), !name.contains(".."),
              name.rangeOfCharacter(from:CharacterSet(charactersIn:"/\\:%?#<>\"|*").union(.controlCharacters).union(.newlines).union(CharacterSet(charactersIn:"\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}"))) == nil else { return false }
        let stem = nameKey(name.components(separatedBy:".")[0])
        let reserved = ["mimetype","meta-inf","con","prn","aux","nul"] + (1...9).flatMap { ["com\($0)","lpt\($0)"] }
        return !reserved.contains(stem)
    }
    static func safeEntryName(_ name: String) -> Bool { ["mimetype",signatureName,manifestName].contains(name) || safePayloadName(name) }
    static func uri(_ name: String) -> String {
        let allowed = CharacterSet(charactersIn:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")
        return name.addingPercentEncoding(withAllowedCharacters:allowed)!
    }
    static func checked(_ payloads: [Payload],kind: Kind) throws -> [Payload] {
        try ASiCZIP.require(kind == .simple ? payloads.count == 1 : (2...maximumPayloads).contains(payloads.count))
        var names = Set<String>(), total = 0
        for p in payloads {
            try ASiCZIP.require(safePayloadName(p.name) && names.insert(nameKey(p.name)).inserted && !p.data.isEmpty && p.data.count <= ASiCZIP.maximumFile)
            total += p.data.count; try ASiCZIP.require(total <= maximumPayloadBytes)
        }
        return payloads.sorted { $0.name.utf8.lexicographicallyPrecedes($1.name.utf8) }
    }
    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of:"&",with:"&amp;").replacingOccurrences(of:"<",with:"&lt;").replacingOccurrences(of:"\"",with:"&quot;")
    }
    /// ODF 1.2 metadata subset; exact bytes are included in the XAdES references.
    static func manifest(_ payloads: [Payload]) -> Data {
        let entries = (["<manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"application/vnd.etsi.asic-e+zip\"/>"] +
            payloads.map { "<manifest:file-entry manifest:full-path=\""+escape($0.name)+"\" manifest:media-type=\"application/octet-stream\"/>" }).joined()
        return Data(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\" manifest:version=\"1.2\">"+entries+"</manifest:manifest>").utf8)
    }
    public static func unsignedArchive(kind: Kind,payloads: [Payload]) throws -> Data {
        let payloads = try checked(payloads,kind:kind)
        var entries = [ASiCZIP.Entry(name:"mimetype",data:Data(kind.mime.utf8))] + payloads.map { .init(name:$0.name,data:$0.data) }
        if kind == .extended { entries.append(.init(name:manifestName,data:manifest(payloads))) }
        return try ASiCZIP.write(entries)
    }
    struct Contents { let kind: Kind; let payloads: [Payload]; let entries: [ASiCZIP.Entry]; let signature: Data? }
    static func contents(_ archive: Data,signed: Bool) throws -> Contents {
        let entries = try ASiCZIP.read(archive)
        guard let mime = entries.first, let kind = [Kind.simple,.extended].first(where:{ Data($0.mime.utf8) == mime.data }) else { throw ASiCZIP.Failure.unsafeArchive }
        let payloads = try checked(entries.filter { !$0.name.hasPrefix("META-INF/") && $0.name != "mimetype" }.map { .init(name:$0.name,data:$0.data) },kind:kind)
        let signature = entries.first { $0.name == signatureName }?.data
        try ASiCZIP.require(signed ? signature != nil : signature == nil)
        let metadata = entries.filter { $0.name.hasPrefix("META-INF/") }
        try ASiCZIP.require(metadata.count == (kind == .extended ? 1 : 0) + (signed ? 1 : 0))
        let result = Contents(kind:kind,payloads:payloads,entries:entries,signature:signature)
        if kind == .extended {
            guard let data = entries.first(where:{ $0.name == manifestName })?.data else { throw ASiCZIP.Failure.unsafeArchive }
            // Structural manifest checks need names only, not copies of every payload.
            let objects = packed(result,includePayloadBytes:false)
            let valid = data.withUnsafeBytes { d in objects.withUnsafeBytes { o in
                signum_asic_manifest(d.bindMemory(to:UInt8.self).baseAddress,data.count,o.bindMemory(to:UInt8.self).baseAddress,objects.count)
            } }
            try ASiCZIP.require(valid == 1)
        }
        return result
    }
    static func packed(_ contents: Contents,includePayloadBytes: Bool = true) -> Data {
        var output = Data()
        let objects = contents.payloads.map { ($0.name,"application/octet-stream",includePayloadBytes ? $0.data : Data([0])) } +
            (contents.kind == .extended ? [(manifestName,"application/xml",includePayloadBytes ? contents.entries.first { $0.name == manifestName }!.data : Data([0]))] : [])
        func append(_ value: Data) {
            let count = UInt32(value.count)
            output.append(contentsOf:[UInt8(count >> 24),UInt8((count >> 16)&255),UInt8((count >> 8)&255),UInt8(count&255)])
            output.append(value)
        }
        let count = UInt32(objects.count);output.append(contentsOf:[0,0,0,UInt8(count)])
        for (name,mime,data) in objects { append(Data(uri(name).utf8));append(Data(mime.utf8));append(data) }
        return output
    }
    public static func payloadNames(in unsignedArchive: Data) throws -> [String] {
        try contents(unsignedArchive,signed:false).payloads.map(\.name)
    }
    public struct Prepared: Sendable {
        public let attributesToSign: Data
        let template: Data
        private let unsigned: Data, objects: Data
        public init(unsignedArchive: Data,certificateDER: Data,declaredTime: Date = Date()) throws {
            let contents = try ASiC.contents(unsignedArchive,signed:false), objects = ASiC.packed(contents)
            var r = signum_xades_result();defer { signum_xades_dispose(&r) }
            let time = ISO8601DateFormatter().string(from:declaredTime)
            let ok = objects.withUnsafeBytes { o in certificateDER.withUnsafeBytes { c in
                signum_xades_detached_prepare(o.bindMemory(to:UInt8.self).baseAddress,objects.count,c.bindMemory(to:UInt8.self).baseAddress,certificateDER.count,time,&r)
            } }
            guard ok == 1 else { throw SignumError.module(XAdES.reason(r)) }
            self.unsigned = unsignedArchive;self.objects = objects;self.template = XAdES.bytes(r.document,r.document_size)
            self.attributesToSign = XAdES.bytes(r.signed_info,r.signed_info_size)
        }
        public func finish(signature: Data) throws -> Data {
            var r = signum_xades_result();defer { signum_xades_dispose(&r) }
            let ok = template.withUnsafeBytes { d in objects.withUnsafeBytes { o in signature.withUnsafeBytes { s in
                signum_xades_detached_finish(d.bindMemory(to:UInt8.self).baseAddress,template.count,o.bindMemory(to:UInt8.self).baseAddress,objects.count,
                    s.bindMemory(to:UInt8.self).baseAddress,signature.count,&r)
            } } }
            guard ok == 1 else { throw SignumError.module(XAdES.reason(r)) }
            let entries = try ASiC.contents(unsigned,signed:false).entries + [.init(name:ASiC.signatureName,data:XAdES.bytes(r.document,r.document_size))]
            return try ASiCZIP.write(entries)
        }
    }
    public static func verify(_ archive: Data) throws -> Verified {
        let contents = try contents(archive,signed:true), objects = packed(contents), xml = contents.signature!
        var r = signum_xades_result();defer { signum_xades_dispose(&r) }
        let ok = xml.withUnsafeBytes { d in objects.withUnsafeBytes { o in
            signum_xades_detached_verify(d.bindMemory(to:UInt8.self).baseAddress,xml.count,o.bindMemory(to:UInt8.self).baseAddress,objects.count,&r)
        } }
        guard ok == 1 else { if ok == -1 { throw SignumError.invalidSignature };throw SignumError.module(XAdES.reason(r)) }
        return .init(kind:contents.kind,payloads:contents.payloads,signature:XAdES.verifiedResult(r))
    }
    static func report(_ archive: Data,name: String) -> VerificationReport {
        do {
            let v = try verify(archive)
            return XAdES.verifiedReport(v.signature,name:name,digest:DocumentSnapshot.digest(archive),format:.asic,
                reason:v.kind.title+": firma XAdES-B, associazione e copertura integrale di \(v.payloads.count) documenti verificate. " + v.payloads.map(\.name).joined(separator:", ")+". Attendibilità separata.")
        } catch {
            let invalid: Bool
            if case SignumError.invalidSignature = error { invalid = true } else { invalid = false }
            let signatures: [SignatureVerificationResult] = invalid ? [.init(id:0,integrity:.invalid,certificate:nil,algorithm:"ASiC · XAdES-B",declaredTime:"",reason:"Integrità del contenuto o della firma non valida.",signedRevisionEnd:nil,laterChanges:false,cmsLayer:1)] : []
            return .init(id:UUID(),documentName:name,sha256:DocumentSnapshot.digest(archive),format:.asic,signatures:signatures,documentState:invalid ? "signed" : "unsupported",
                issue:invalid ? "" : "ASiC non verificabile: archivio o profilo non supportato, riferimenti o copertura dei documenti non validi.",previewPDF:nil,originalContent:nil)
        }
    }
}
#endif
