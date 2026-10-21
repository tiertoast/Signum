#if os(macOS)
import Foundation
import CXMLSecurity

/// Strict ZIP32 reader: nothing is extracted to the filesystem. Central/local
/// records must describe exactly the same contiguous entries, before inflation.
enum ASiCZIP {
    static let maximumArchive = 24 * 1024 * 1024
    static let maximumFile = 8 * 1024 * 1024
    static let maximumExpanded = 16 * 1024 * 1024 + 128 * 1024
    static let maximumEntries = 7
    static func maximumBytes(for name: String) -> Int {
        switch name {
        case "mimetype": return 64
        case "META-INF/signatures.xml": return 128*1024
        case "META-INF/manifest.xml": return 16*1024
        default: return maximumFile
        }
    }
    struct Entry: Equatable, Sendable { let name: String; let data: Data }
    enum Failure: Error { case unsafeArchive }
    static func require(_ condition: Bool) throws {
        guard condition else { throw Failure.unsafeArchive }
    }
    static func crc(_ data: Data) -> UInt32 {
        data.withUnsafeBytes { UInt32(signum_zip_crc($0.bindMemory(to:UInt8.self).baseAddress,data.count)) }
    }
    static func read(_ bytes: Data) throws -> [Entry] {
        try require(bytes.count >= 22 && bytes.count <= maximumArchive)
        func number(_ at: Int,_ size: Int) throws -> Int {
            try require(at >= 0 && at <= bytes.count && size <= bytes.count-at)
            return (0..<size).reduce(0) { $0 | (Int(bytes[at+$1]) << (8*$1)) }
        }
        func u16(_ at: Int) throws -> Int { try number(at,2) }
        func u32(_ at: Int) throws -> Int { try number(at,4) }
        let end = bytes.count-22
        try require(try u32(end) == 0x06054b50 && u16(end+4) == 0 && u16(end+6) == 0 && u16(end+20) == 0)
        let count = try u16(end+10), central = try u32(end+16), centralSize = try u32(end+12)
        try require(count >= 2 && count <= maximumEntries && (try u16(end+8)) == count && central+centralSize == end)
        struct Record { let name: String; let offset: Int; let compressed: Int; let expanded: Int; let method: Int; let crc: UInt32 }
        var records = [Record](), cursor = central, nextLocal = 0, total = 0, names = Set<String>()
        for i in 0..<count {
            try require(try u32(cursor) == 0x02014b50)
            let flags = try u16(cursor+8), method = try u16(cursor+10), version = try u16(cursor+6)
            let sum = try u32(cursor+16), compressed = try u32(cursor+20), expanded = try u32(cursor+24)
            let nameSize = try u16(cursor+28), extra = try u16(cursor+30), comment = try u16(cursor+32)
            let local = try u32(cursor+42), external = try u32(cursor+38)
            try require((version == 10 || version == 20) && (flags == 0 || flags == 0x800) && (method == 0 || method == 8))
            try require(extra == 0 && comment == 0 && (try u16(cursor+34)) == 0 && nameSize > 0 && nameSize <= 256)
            try require(expanded > 0 && expanded <= maximumFile && compressed > 0 && compressed <= maximumArchive)
            try require(expanded <= compressed*100 && (method != 0 || compressed == expanded))
            try require((external & 0x10) == 0 && ((external >> 16) & 0xf000 == 0 || (external >> 16) & 0xf000 == 0x8000))
            try require(cursor+46+nameSize <= end && local == nextLocal && local+30 <= central)
            let nameBytes = bytes.subdata(in:cursor+46..<cursor+46+nameSize)
            guard let name = String(data:nameBytes,encoding:.utf8) else { throw Failure.unsafeArchive }
            try require(flags == 0x800 || nameBytes.allSatisfy { $0 < 128 })
            try require(ASiC.safeEntryName(name) && names.insert(ASiC.nameKey(name)).inserted && expanded <= maximumBytes(for:name))
            try require(try u32(local) == 0x04034b50 && u16(local+4) == version && u16(local+6) == flags && u16(local+8) == method)
            try require(try u16(local+10) == u16(cursor+12) && u16(local+12) == u16(cursor+14))
            try require(try u32(local+14) == sum && u32(local+18) == compressed && u32(local+22) == expanded)
            try require(try u16(local+26) == nameSize && u16(local+28) == 0)
            let payload = local+30+nameSize
            try require(payload+compressed <= central && bytes.subdata(in:local+30..<payload) == nameBytes)
            if i == 0 { try require(name == "mimetype" && local == 0 && method == 0) }
            total += expanded; try require(total <= maximumExpanded)
            records.append(.init(name:name,offset:payload,compressed:compressed,expanded:expanded,method:method,crc:UInt32(sum)))
            nextLocal = payload+compressed;cursor += 46+nameSize
        }
        try require(cursor == end && nextLocal == central)
        // Allocation and inflation happen only after every record passes bounds/identity checks.
        return try records.map { r in
            let compressed = bytes.subdata(in:r.offset..<r.offset+r.compressed)
            var data: Data
            if r.method == 0 { data = compressed }
            else {
                data = Data(count:r.expanded)
                let valid = data.withUnsafeMutableBytes { out in compressed.withUnsafeBytes { input in
                    signum_zip_inflate(input.bindMemory(to:UInt8.self).baseAddress,compressed.count,
                                       out.bindMemory(to:UInt8.self).baseAddress,r.expanded)
                } }
                try require(valid == 1)
            }
            try require(crc(data) == r.crc)
            return .init(name:r.name,data:data)
        }
    }
    static func write(_ entries: [Entry]) throws -> Data {
        try require(entries.count >= 2 && entries.count <= maximumEntries && entries.first?.name == "mimetype")
        var output = Data(), directory = Data(), names = Set<String>(), total = 0
        func append(_ value: Int,_ size: Int,to bytes: inout Data) {
            for i in 0..<size { bytes.append(UInt8((value >> (8*i)) & 255)) }
        }
        for entry in entries {
            try require(ASiC.safeEntryName(entry.name) && names.insert(ASiC.nameKey(entry.name)).inserted)
            try require(!entry.data.isEmpty && entry.data.count <= maximumBytes(for:entry.name))
            total += entry.data.count;try require(total <= maximumExpanded)
            let name = Data(entry.name.utf8), offset = output.count, checksum = Int(crc(entry.data))
            for (n,size) in [(0x04034b50,4),(20,2),(0x800,2),(0,2),(0,2),(33,2),(checksum,4),(entry.data.count,4),(entry.data.count,4),(name.count,2),(0,2)] { append(n,size,to:&output) }
            output.append(name);output.append(entry.data)
            for (n,size) in [(0x02014b50,4),(0x314,2),(20,2),(0x800,2),(0,2),(0,2),(33,2),(checksum,4),(entry.data.count,4),(entry.data.count,4),(name.count,2),(0,2),(0,2),(0,2),(0,2),(0x81a40000,4),(offset,4)] { append(n,size,to:&directory) }
            directory.append(name)
        }
        let central = output.count;output.append(directory)
        for (n,size) in [(0x06054b50,4),(0,2),(0,2),(entries.count,2),(entries.count,2),(directory.count,4),(central,4),(0,2)] { append(n,size,to:&output) }
        try require(output.count <= maximumArchive)
        return output
    }
}
#endif
