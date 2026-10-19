#if os(macOS)
import Foundation
import CryptoKit
import Darwin

public enum SigningFormat: String, Sendable {
    case cades, pades
    public var maximumDocumentBytes: Int { SigningResourceLimits.maximumDocumentBytes }
}

/// A private CoW acquisition, immutable approved bytes and a retained descriptor.
/// Never reopens the original after capture. Only macOS file cloning is accepted;
/// there is deliberately no unsafe streaming-copy fallback on unsupported volumes.
public final class DocumentSnapshot: @unchecked Sendable {
    public struct Identity: Equatable, Sendable {
        public let id: UUID
        public let sha256: String
        public let byteCount: Int
    }
    public let identity: Identity
    public let originalURL: URL // Display/destination suggestion only, never a signing input.
    /// Immutable acquisition hint for legacy callers/limits, not the pending signing choice.
    public let format: SigningFormat
    public let fileURL: URL // Private helper input; the helper must verify identity.sha256.
    public var approvedBytes: Data { bytes } // Value semantics, no mapped mutable file.
    private let bytes: Data
    private let lock = NSLock()
    private var closed = false
    private let root: Int32, directory: Int32, descriptor: Int32
    private let directoryName: String
    private let directoryIdentity: stat, fileIdentity: stat
    private static let prefix = ".signum-snapshot-"
    private static let payload = "document"

    struct CaptureIO {
        var sourceOpened: (Int32) throws -> Void = { _ in }
        var clone: (Int32, Int32, String) -> Int32 = { fclonefileat($0, $1, $2, UInt32(CLONE_NOOWNERCOPY)) }
        var read: (Int32, UnsafeMutableRawPointer, Int) -> Int = { Darwin.read($0, $1, $2) }
        var clock: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    }

    public static func capture(source: URL, format: SigningFormat, timeout: TimeInterval = 30,
                               isCancelled: @escaping () -> Bool = { false }) throws -> DocumentSnapshot {
        try capture(source: source, format: format,
                    privateRoot: FileManager.default.temporaryDirectory, io: CaptureIO(), timeout: timeout, isCancelled: isCancelled)
    }

    static func capture(source: URL, format: SigningFormat, privateRoot: URL,
                        io: CaptureIO = CaptureIO(), timeout: TimeInterval = 30,
                        isCancelled: @escaping () -> Bool = { false }) throws -> DocumentSnapshot {
        let deadline = io.clock() + max(0, timeout)
        let check = {
            if isCancelled() { throw DocumentAcquisitionFailure(.cancelled, "capture cancellation") }
            if io.clock() >= deadline { throw DocumentAcquisitionFailure(.timeout, "capture deadline") }
        }
        try check()
        guard source.isFileURL, !source.lastPathComponent.isEmpty else { throw error("Sorgente non valido.") }
        let original = nativeURL(source)
        let privateRoot = nativeURL(privateRoot)
        guard !original.pathComponents.contains(".."), !original.pathComponents.contains(".") else {
            throw error("Seleziona un percorso senza componenti relativi.")
        }
        // O_NOFOLLOW_ANY also rejects symlinks in ancestors. Pin the parent and
        // file separately, then check the path still denotes that inode.
        let parent = Darwin.open(original.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard parent >= 0 else { throw DocumentAcquisitionFailure.system("open source parent") }
        defer { Darwin.close(parent) }
        let sourceFD = openat(parent, original.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard sourceFD >= 0 else { throw DocumentAcquisitionFailure.system("open source") }
        defer { Darwin.close(sourceFD) }
        let watch = try AcquisitionWatch(sourceFD)
        var sourceIdentity = stat()
        guard fstat(sourceFD, &sourceIdentity) == 0 else { throw DocumentAcquisitionFailure.system("stat source") }
        guard sourceIdentity.st_mode & S_IFMT == S_IFREG, sourceIdentity.st_size > 0 else { throw DocumentAcquisitionFailure(.read, "source is empty or not regular") }
        guard sourceIdentity.st_size <= format.maximumDocumentBytes else { throw DocumentAcquisitionFailure(.tooLarge, "source exceeds \(format.maximumDocumentBytes) bytes") }
        guard sourceIdentity.st_flags & UInt32(UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND) == 0 else {
            throw error("Il file ha flag che impediscono la pulizia della copia. Crea una copia locale e riselezionala.")
        }
        let root = Darwin.open(privateRoot.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard root >= 0 else { throw error("Area privata non disponibile.") }
        var keep = false
        defer { if !keep { Darwin.close(root) } }
        var rootInfo = stat()
        guard fstat(root, &rootInfo) == 0, rootInfo.st_uid == getuid(), rootInfo.st_mode & 0o077 == 0 else {
            throw error("L'area dello snapshot deve essere privata dell'utente.")
        }
        guard sourceIdentity.st_dev == rootInfo.st_dev else {
            throw error("Snapshot coerente non disponibile su questa unità. Copia il documento sull'unità locale dell'area privata e riselezionalo.")
        }
        recover(in: root)
        let name = prefix + UUID().uuidString
        guard mkdirat(root, name, 0o700) == 0 else { throw DocumentAcquisitionFailure.system("create private snapshot directory") }
        var createdDirectory = stat()
        guard fstatat(root, name, &createdDirectory, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw error("Impossibile identificare la cartella privata.")
        }
        defer { if !keep { remove(in: root, name: name, identity: createdDirectory, flags: AT_REMOVEDIR) } }
        let directory = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw error("Impossibile aprire lo snapshot privato.") }
        defer { if !keep { Darwin.close(directory) } }
        var directoryIdentity = stat()
        guard fstat(directory, &directoryIdentity) == 0,
              directoryIdentity.st_dev == createdDirectory.st_dev, directoryIdentity.st_ino == createdDirectory.st_ino,
              flock(directory, LOCK_EX | LOCK_NB) == 0 else {
            throw error("Impossibile bloccare lo snapshot privato.")
        }
        var fileIdentity: stat?
        defer {
            if !keep {
                if let fileIdentity { remove(in: directory, name: payload, identity: fileIdentity, flags: 0) }
                remove(in: root, name: name, identity: directoryIdentity, flags: AT_REMOVEDIR)
            }
        }
        guard let emptyACL = acl_init(0) else { throw error("Impossibile preparare i permessi privati.") }
        defer { acl_free(UnsafeMutableRawPointer(emptyACL)) }
        guard acl_set_fd(directory, emptyACL) == 0, fchmod(directory, 0o700) == 0 else {
            throw error("Impossibile rimuovere ACL ereditate dall'area privata.")
        }
        try io.sourceOpened(sourceFD)
        try check()
        guard io.clone(sourceFD, directory, payload) == 0 else {
            throw DocumentAcquisitionFailure.system("fclonefileat")
        }
        var clonedIdentity = stat()
        guard fstatat(directory, payload, &clonedIdentity, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw error("Snapshot non disponibile dopo il clone.")
        }
        fileIdentity = clonedIdentity
        let fd = openat(directory, payload, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw error("Snapshot non disponibile dopo l'acquisizione.") }
        defer { if !keep { Darwin.close(fd) } }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw error("Impossibile identificare lo snapshot.") }
        guard info.st_dev == clonedIdentity.st_dev, info.st_ino == clonedIdentity.st_ino,
              info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
              info.st_ino != sourceIdentity.st_ino, fchmod(fd, 0o400) == 0 else {
            throw error("Identità o permessi dello snapshot non validi.")
        }
        let content = try readBounded(fd, maximum: format.maximumDocumentBytes, read: io.read, check: check)
        var after = stat()
        guard fstat(sourceFD, &after) == 0 else { throw DocumentAcquisitionFailure.system("stat source after clone") }
        guard sameContentAttributes(sourceIdentity, after), same(in: parent, name: original.lastPathComponent, identity: sourceIdentity) else {
            throw DocumentAcquisitionFailure(.changed, "source identity/size/mtime or pathname changed")
        }
        // A ctime-only change needs corroboration, not blind timestamp omission.
        // Read the original through the pinned descriptor and compare with CoW.
        if !unchanged(sourceIdentity, after) {
            let current = try readBounded(sourceFD, maximum: format.maximumDocumentBytes, check: check)
            guard current == content else { throw DocumentAcquisitionFailure(.changed, "source bytes differ from coherent clone") }
        }
        try watch.requireUnchanged()
        try check()
        let result = DocumentSnapshot(source: original, format: format, bytes: content, root: root,
                                      directory: directory, fd: fd, name: name,
                                      directoryIdentity: directoryIdentity, fileIdentity: info, privateRoot: privateRoot)
        keep = true
        return result
    }

    private init(source: URL, format: SigningFormat, bytes: Data, root: Int32, directory: Int32,
                 fd: Int32, name: String, directoryIdentity: stat, fileIdentity: stat, privateRoot: URL) {
        self.originalURL = source; self.format = format; self.bytes = bytes
        self.identity = Identity(id: UUID(), sha256: Self.digest(bytes), byteCount: bytes.count)
        self.root = root; self.directory = directory; self.descriptor = fd; self.directoryName = name
        self.directoryIdentity = directoryIdentity; self.fileIdentity = fileIdentity
        self.fileURL = privateRoot.appendingPathComponent(name).appendingPathComponent(Self.payload)
    }

    /// Revalidate both descriptor contents and the helper pathname. Always return
    /// the immutable bytes shown by the preview, never a new version of the source.
    public func verifiedBytes() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !closed, Self.same(in: root, name: directoryName, identity: directoryIdentity),
              Self.same(in: directory, name: Self.payload, identity: fileIdentity) else {
            throw Self.error("Snapshot mancante o sostituito. Riseleziona il documento.")
        }
        let check = try Self.readBounded(descriptor, maximum: format.maximumDocumentBytes)
        guard check == bytes, Self.digest(check) == identity.sha256 else {
            throw Self.error("Snapshot corrotto. Nessuna firma autorizzata: riseleziona il documento.")
        }
        return bytes
    }

    /// Idempotent, identity-bound unlink, with no recursion and no source writes.
    /// This removes private copies, not a forensic/SSD secure-erasure guarantee.
    public func close() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }; closed = true
        Self.remove(in: directory, name: Self.payload, identity: fileIdentity, flags: 0)
        Self.remove(in: root, name: directoryName, identity: directoryIdentity, flags: AT_REMOVEDIR)
        Darwin.close(descriptor); Darwin.close(directory); Darwin.close(root)
    }
    deinit { close() }

    // Foundation canonicalization rewrites /private/var back to /var. Accept
    // only the three fixed, root-owned macOS aliases, then use O_NOFOLLOW_ANY
    // on the resulting path. Never resolve arbitrary document symlinks.
    private static func nativeURL(_ url: URL) -> URL {
        let path = url.path
        for alias in ["var", "tmp", "etc"] where path.hasPrefix("/" + alias + "/") {
            var info = stat(), link = [CChar](repeating: 0, count: 128)
            let name = "/" + alias
            let n = readlink(name, &link, link.count)
            if lstat(name, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFLNK, n > 0, n < link.count {
                let target = String(decoding: link.prefix(n).map { UInt8(bitPattern: $0) }, as: UTF8.self)
                if target == "private/" + alias || target == "/private/" + alias {
                    return URL(fileURLWithPath: "/private" + path)
                }
            }
        }
        return url
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func error(_ text: String) -> SignumError { .module(text) }
    private static func unchanged(_ a: stat, _ b: stat) -> Bool {
        sameContentAttributes(a, b) &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    private static func sameContentAttributes(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
    }
    private static func readBounded(_ fd: Int32, maximum: Int,
                                    read: (Int32, UnsafeMutableRawPointer, Int) -> Int = { Darwin.read($0, $1, $2) },
                                    check: () throws -> Void = {}) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw DocumentAcquisitionFailure.system("stat capture input") }
        guard info.st_size <= maximum else { throw DocumentAcquisitionFailure(.tooLarge, "capture input exceeds \(maximum) bytes") }
        guard info.st_size > 0, lseek(fd, 0, SEEK_SET) == 0 else { throw DocumentAcquisitionFailure.system("seek capture input") }
        var result = Data(), chunk = [UInt8](repeating: 0, count: 65536)
        result.reserveCapacity(Int(info.st_size)) // Validated bound; avoid growth copies for large files.
        while true {
            try check()
            let count = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, count <= chunk.count else { throw DocumentAcquisitionFailure.system("read capture input") }
            if count == 0 { break }
            guard count <= maximum - result.count else { throw DocumentAcquisitionFailure(.tooLarge, "capture input grew beyond limit") }
            result.append(contentsOf: chunk.prefix(count))
        }
        var after = stat()
        guard fstat(fd, &after) == 0 else { throw DocumentAcquisitionFailure.system("stat capture input after read") }
        guard unchanged(info, after), result.count == info.st_size else {
            throw DocumentAcquisitionFailure(.changed, "capture input changed or short read")
        }
        return result
    }
    private static func same(in directory: Int32, name: String, identity: stat) -> Bool {
        var value = stat()
        return fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) == 0 &&
            value.st_dev == identity.st_dev && value.st_ino == identity.st_ino
    }
    private static func remove(in directory: Int32, name: String, identity: stat, flags: Int32) {
        if same(in: directory, name: name, identity: identity) { _ = unlinkat(directory, name, flags) }
    }
    private static func names(in fd: Int32) -> [String]? {
        let scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard scan >= 0 else { return nil }
        guard let dir = fdopendir(scan) else { Darwin.close(scan); return nil }
        defer { closedir(dir) }
        var result: [String] = []
        while true {
            errno = 0
            guard let item = readdir(dir) else { return errno == 0 ? result : nil }
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(item.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { result.append(name) }
        }
    }

    private static func recover(in root: Int32) {
        guard let entries = names(in: root) else { return }
        for name in entries where name.hasPrefix(prefix) && UUID(uuidString: String(name.dropFirst(prefix.count))) != nil {
            let dir = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard dir >= 0 else { continue }; defer { Darwin.close(dir) }
            var info = stat()
            guard fstat(dir, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700,
                  flock(dir, LOCK_EX | LOCK_NB) == 0, let layout = names(in: dir), layout.isEmpty || layout == [payload] else { continue }
            var file = stat()
            if fstatat(dir, payload, &file, AT_SYMLINK_NOFOLLOW) == 0,
               file.st_mode & S_IFMT == S_IFREG, file.st_uid == getuid(), file.st_mode & 0o7000 == 0, file.st_nlink == 1 {
                remove(in: dir, name: payload, identity: file, flags: 0)
            }
            remove(in: root, name: name, identity: info, flags: AT_REMOVEDIR)
        }
    }
}
#endif
