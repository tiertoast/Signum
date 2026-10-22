#if os(macOS)
import Foundation
import Darwin

extension ASiC {
    /// Capture every original through the existing coherent snapshot mechanism,
    /// then freeze one unsigned container. Original URLs are never reopened to sign.
    static func capture(sources: [URL],kind: Kind,isCancelled: @escaping () -> Bool = { false }) throws -> DocumentSnapshot {
        guard kind == .simple ? sources.count == 1 : (2...maximumPayloads).contains(sources.count), let first = sources.first else {
            throw SignumError.module("ASiC-S richiede un documento; ASiC-E da 2 a 4 documenti nella stessa selezione.")
        }
        var snapshots = [DocumentSnapshot](), payloads = [Payload](), total = 0
        defer { snapshots.forEach { $0.close() } }
        for source in sources {
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            let snapshot = try DocumentSnapshot.capture(source:source,format:kind == .simple ? .asics : .asice,isCancelled:isCancelled)
            snapshots.append(snapshot)
            let bytes = try snapshot.verifiedBytes();total += bytes.count
            guard bytes.count <= ASiCZIP.maximumFile, total <= maximumPayloadBytes else { throw SignumError.module("ASiC: massimo 8 MiB per documento, 16 MiB complessivi.") }
            payloads.append(.init(name:source.lastPathComponent.precomposedStringWithCanonicalMapping,data:bytes))
        }
        let archive = try unsignedArchive(kind:kind,payloads:payloads)
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        let directory = root.appendingPathComponent("signum-asic-acquire-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at:directory) }
        let file = directory.appendingPathComponent("unsigned."+kind.rawValue)
        let fd = Darwin.open(file.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd >= 0 else { throw SignumError.module("Area privata ASiC non disponibile.") }
        let handle = FileHandle(fileDescriptor:fd,closeOnDealloc:true)
        try handle.write(contentsOf:archive);try handle.close()
        let label = first.deletingLastPathComponent().appendingPathComponent(first.deletingPathExtension().lastPathComponent+"-contenuti."+kind.rawValue)
        return try DocumentSnapshot.capture(source:file,format:kind == .simple ? .asics : .asice,privateRoot:root,presentationSource:label,isCancelled:isCancelled)
    }
}
#endif
