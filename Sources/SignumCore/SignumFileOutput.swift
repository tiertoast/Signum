import Foundation
#if os(macOS)
import Darwin
import COutputPermissions
#endif

/// Publishes complete bytes once. Staging is private and on the destination volume.
/// `validate` runs on bytes read back from staging, before the final name exists.
/// This is atomic visibility, not a promise of survival across power loss.
public enum SignumFileOutput {
    public static func writeNew(_ data: Data, to url: URL,
                                validate: (Data) throws -> Void = { _ in }) throws {
        #if os(macOS)
        try writeNew(data, to: url, io: OutputIO(), validate: validate)
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }

    #if os(macOS)
    // Per-operation dependencies allow real short writes and syscall failures in
    // offline tests; there is no process-wide mutable fault-injection switch.
    struct OutputIO {
        var openParent: (String) -> Int32 = { Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC) }
        var identifyParent: (Int32, UnsafeMutablePointer<stat>) -> Int32 = { fstat($0, $1) }
        var afterPublish: () -> Void = {}
        var write: (Int32, UnsafeRawPointer, Int) -> Int = { Darwin.write($0, $1, $2) }
        var sync: (Int32) -> Int32 = { Darwin.fsync($0) }
        var close: (Int32) -> Int32 = { Darwin.close($0) }
        var harden: (Int32, mode_t) -> Int32 = { sg_output_make_private($0, $1) }
        var applyACL: (Int32, acl_t) -> Int32 = { sg_output_apply_acl($0, $1) }
        var publish: (Int32, String, Int32, String) -> Int32 = { renameatx_np($0, $1, $2, $3, UInt32(RENAME_EXCL)) }
        var staged: () throws -> Void = {}
        var beforePublish: () throws -> Void = {}
    }

    private static let prefix = ".signum-staging-"
    private static let payload = "output"

    public static func writeNew(_ data: Data, to url: URL, expectedDirectory: OutputDirectoryIdentity,
                                validate: (Data) throws -> Void = { _ in }) throws {
        try writeNew(data, to: url, expectedDirectory: expectedDirectory, io: OutputIO(), validate: validate)
    }

    static func writeNew(_ data: Data, to url: URL, expectedDirectory: OutputDirectoryIdentity? = nil, io: OutputIO,
                         validate: (Data) throws -> Void = { _ in }) throws {
        guard url.isFileURL, !data.isEmpty,
              !["", ".", "..", "/"].contains(url.lastPathComponent) else {
            throw SignumError.module("Invalid file destination or empty signed data")
        }
        // Pin the selected directory: subsequent operations never resolve its
        // ancestors again, even if someone renames/replaces that directory.
        let directory = url.deletingLastPathComponent()
        let parent = io.openParent(directory.path)
        guard parent >= 0 else { throw failure("aprire la cartella di destinazione") }
        defer { Darwin.close(parent) }
        if let expectedDirectory {
            var actual = stat()
            guard io.identifyParent(parent, &actual) == 0, actual.st_mode & S_IFMT == S_IFDIR,
                  OutputDirectoryIdentity(actual) == expectedDirectory else {
                throw SignumError.module("La directory aperta non corrisponde alla destinazione approvata.")
            }
            try expectedDirectory.requireCurrent(at: directory)
        }
        recoverAbandoned(in: parent)
        let name = prefix + UUID().uuidString
        guard mkdirat(parent, name, 0o700) == 0 else { throw failure("creare lo staging privato") }
        let stage = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard stage >= 0 else { throw failure("aprire lo staging privato") }
        defer { Darwin.close(stage) }
        guard flock(stage, LOCK_EX | LOCK_NB) == 0 else { throw failure("bloccare lo staging") }
        var stageIdentity = stat()
        guard fstat(stage, &stageIdentity) == 0 else { throw failure("identificare lo staging") }
        defer { removeDirectoryIfSame(parent: parent, name: name, identity: stageIdentity) }

        guard io.harden(stage, 0o700) == 0, sg_output_is_private(stage, 0o700) == 0 else {
            throw failure("proteggere le autorizzazioni dello staging")
        }
        guard let finalACL = sg_output_inherited_acl(parent, stage) else {
            throw failure("determinare le autorizzazioni finali")
        }
        defer { acl_free(UnsafeMutableRawPointer(finalACL)) }
        let fd = openat(stage, payload, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw failure("creare il file temporaneo") }
        var open = true
        defer { if open { Darwin.close(fd) } }
        var identity = stat()
        guard fstat(fd, &identity) == 0 else { throw failure("identificare il file temporaneo") }
        // Remove only our inode, never a replacement/symlink supplied by another
        // process. Unknown entries are deliberately left for manual inspection.
        defer { removePayloadIfSame(stage: stage, identity: identity) }
        guard io.harden(fd, 0o600) == 0, sg_output_is_private(fd, 0o600) == 0 else {
            throw failure("proteggere le autorizzazioni del file temporaneo")
        }
        try io.staged()
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = io.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0, count <= bytes.count - offset else { throw failure("scrivere il file temporaneo") }
                offset += count
            }
        }
        guard io.sync(fd) == 0 else { throw failure("sincronizzare il file temporaneo") }
        guard lseek(fd, 0, SEEK_SET) == 0 else { throw failure("rileggere il file temporaneo") }
        var readback = Data(count: data.count)
        try readback.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure("rileggere il file temporaneo") }
                offset += count
            }
        }
        var current = stat()
        guard fstat(fd, &current) == 0, current.st_size == data.count, readback == data else {
            throw SignumError.module("Il file temporaneo non corrisponde ai byte attesi.")
        }
        try validate(readback)
        // Restore destination sharing only behind the still-private directory.
        // Other users cannot obtain a payload descriptor before the atomic rename.
        guard sg_output_is_private(stage, 0o700) == 0,
              sameEntry(in: parent, name: name, identity: stageIdentity),
              io.applyACL(fd, finalACL) == 0 else { throw failure("impostare le autorizzazioni finali") }
        // A close error must prevent publication. Do not retry close: the fd may
        // already have been released by the kernel, including on error.
        open = false
        guard io.close(fd) == 0 else { throw failure("chiudere il file temporaneo") }
        try io.beforePublish()
        guard sg_output_is_private(stage, 0o700) == 0,
              sameEntry(in: parent, name: name, identity: stageIdentity),
              sameEntry(in: stage, name: payload, identity: identity) else {
            throw SignumError.module("Identità del file temporaneo modificata.")
        }
        // macOS exclusive rename is the commit point. Existing files, directories
        // and dangling symlinks are all refused atomically, without a check/use gap.
        if let expectedDirectory { try expectedDirectory.requireCurrent(at: directory) }
        guard io.publish(stage, payload, parent, url.lastPathComponent) == 0 else {
            if errno == EEXIST {
                throw SignumError.module("Il file di destinazione esiste già: scegli un altro nome.")
            }
            throw failure("pubblicare il file completo")
        }
        // After commit, never delete the published inode or report an ordinary
        // failure. A renamed/unreachable approved path is explicitly uncertain.
        io.afterPublish()
        if let expectedDirectory {
            do { try expectedDirectory.requireCurrent(at: directory) }
            catch { throw SignumError.outputUncertain("Output pubblicato nella directory approvata, ma il percorso è cambiato. Conservare l’output e non ripetere automaticamente.") }
        }
    }

    private static func failure(_ operation: String) -> SignumError {
        .module("Impossibile \(operation) (errno \(errno)).")
    }

    private static func sameEntry(in directory: Int32, name: String, identity: stat) -> Bool {
        var entry = stat()
        return fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
            entry.st_dev == identity.st_dev && entry.st_ino == identity.st_ino
    }

    private static func removePayloadIfSame(stage: Int32, identity: stat) {
        if sameEntry(in: stage, name: payload, identity: identity) { _ = unlinkat(stage, payload, 0) }
    }

    private static func removeDirectoryIfSame(parent: Int32, name: String, identity: stat) {
        if sameEntry(in: parent, name: name, identity: identity) { _ = unlinkat(parent, name, AT_REMOVEDIR) }
    }

    private static func entryNames(in fd: Int32) -> [String]? {
        let scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard scan >= 0 else { return nil }
        guard let directory = fdopendir(scan) else { Darwin.close(scan); return nil }
        defer { closedir(directory) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else { return errno == 0 ? names : nil }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.append(name) }
        }
    }

    /// Reclaim only recognizable, owner-private, unlocked staging in this folder.
    /// Locks are released by the kernel on crash. Never recurse or follow links.
    /// A destination is revisited on its next write; there is no global disk scan.
    private static func recoverAbandoned(in parent: Int32) {
        let scanFD = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard scanFD >= 0 else { return }
        guard let directory = fdopendir(scanFD) else { Darwin.close(scanFD); return }
        defer { closedir(directory) }
        while let entry = readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            guard name.hasPrefix(prefix), UUID(uuidString: String(name.dropFirst(prefix.count))) != nil else { continue }
            let stage = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard stage >= 0 else { continue }
            defer { Darwin.close(stage) }
            var identity = stat()
            guard fstat(stage, &identity) == 0, identity.st_uid == getuid(),
                  identity.st_mode & 0o777 == 0o700, sg_output_is_private(stage, 0o700) == 0,
                  flock(stage, LOCK_EX | LOCK_NB) == 0 else { continue }
            guard sg_output_cleanup_permissions(stage) == 0 else { continue }
            // A recognizable name alone is not enough to delete a directory's
            // contents. Leave unexpected layouts wholly untouched.
            guard let names = entryNames(in: stage), names.isEmpty || names == [payload] else { continue }
            var file = stat()
            if fstatat(stage, payload, &file, AT_SYMLINK_NOFOLLOW) == 0,
               file.st_mode & S_IFMT == S_IFREG, file.st_uid == getuid(),
               file.st_mode & 0o777 == 0o600, file.st_nlink == 1 {
                removePayloadIfSame(stage: stage, identity: file)
            }
            removeDirectoryIfSame(parent: parent, name: name, identity: identity)
        }
    }
    #endif
}
