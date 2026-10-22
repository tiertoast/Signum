#if os(macOS)
import Foundation
import Darwin

/// Directory identity approved with the output plan. Timestamps intentionally
/// excluded: other files may legitimately be created while the batch is pending.
public struct OutputDirectoryIdentity: Sendable, Hashable {
    let device: Int64, inode: UInt64
    init(_ value: stat) { device = Int64(value.st_dev); inode = UInt64(value.st_ino) }
    public var wire: String { "\(device):\(inode)" }
    public func requireCurrent(at directory: URL) throws {
        let current = try Self.inspect(directory)
        guard current.1 == self, current.0.path == directory.path else {
            throw SignumError.module("La cartella di destinazione è cambiata. Prepara e conferma una nuova sessione.")
        }
    }
    static func inspect(_ directory: URL) throws -> (URL, OutputDirectoryIdentity) {
        guard directory.isFileURL, directory.path.hasPrefix("/"), !directory.path.utf8.contains(0),
              directory.path.utf8.count <= 4096, let resolved = realpath(directory.path, nil) else {
            throw SignumError.module("Cartella di destinazione non disponibile. Scegli una cartella locale valida.")
        }
        defer { free(resolved) }
        let canonical = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
        let fd = Darwin.open(canonical.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw SignumError.module("Impossibile aprire la cartella di destinazione. Scegli un'altra cartella.") }
        defer { Darwin.close(fd) }
        var pinned = stat(), named = stat()
        guard fstat(fd, &pinned) == 0, lstat(canonical.path, &named) == 0,
              named.st_mode & S_IFMT == S_IFDIR, OutputDirectoryIdentity(pinned) == OutputDirectoryIdentity(named) else {
            throw SignumError.module("La cartella di destinazione è cambiata durante la preparazione.")
        }
        // Read-only authorization check, including the OS ACL decision. Never
        // create a test/staging file while planning the user's approval.
        guard faccessat(fd, ".", W_OK | X_OK, 0) == 0 else {
            throw SignumError.module("La cartella di destinazione non è scrivibile. Scegli un'altra cartella prima di confermare.")
        }
        return (canonical, OutputDirectoryIdentity(pinned))
    }
}

public enum BatchOutputDestination: Sendable, Equatable {
    case originalFolders
    case commonDirectory(URL)

    public func directory(for snapshot: DocumentSnapshot) -> URL {
        switch self {
        case .originalFolders: return snapshot.originalURL.deletingLastPathComponent()
        case .commonDirectory(let directory): return directory
        }
    }
    /// Nominal path only. Collision checks happen off-main before confirmation.
    public func proposedURL(for snapshot: DocumentSnapshot, format: SigningFormat? = nil) -> URL {
        directory(for: snapshot).appendingPathComponent(Self.filename(for: snapshot, number: 1, format: format))
    }
    static func filename(for snapshot: DocumentSnapshot, number: Int, format: SigningFormat? = nil) -> String {
        let original = snapshot.originalURL
        let suffix = number == 1 ? "" : " (\(number))"
        let kind=format ?? snapshot.format
        if kind.isAdvancedCAdES {
            let operation=kind == .cadesDetached ? "-detached" : kind == .cadesCoSign ? "-cofirmato" : "-controfirmato"
            return original.lastPathComponent+operation+suffix+"."+kind.outputExtension
        }
        if (format ?? snapshot.format).isASiC {
            return original.deletingPathExtension().lastPathComponent + "-firmato" + suffix + "." + (format ?? snapshot.format).rawValue
        }
        if (format ?? snapshot.format) == .pades {
            return original.deletingPathExtension().lastPathComponent + "-firmato" + suffix + ".pdf"
        }
        if (format ?? snapshot.format) == .xades {
            return original.deletingPathExtension().lastPathComponent + "-firmato" + suffix + ".xml"
        }
        if number == 1 { return original.lastPathComponent + ".p7m" }
        let ext = original.pathExtension.isEmpty ? "" : "." + original.pathExtension
        return original.deletingPathExtension().lastPathComponent + suffix + ext + ".p7m"
    }
    struct Planned: Sendable { let url: URL; let directoryIdentity: OutputDirectoryIdentity }
    private struct Reservation: Hashable { let directory: OutputDirectoryIdentity; let name: String }
    func plan(_ snapshots: [DocumentSnapshot], formats: [UUID:SigningFormat] = [:]) throws -> [Planned] {
        var directories: [String: (URL, OutputDirectoryIdentity)] = [:]
        var reserved = Set<Reservation>(), result: [Planned] = []
        for snapshot in snapshots {
            let input = directory(for: snapshot)
            let directory: (URL, OutputDirectoryIdentity)
            if let cached = directories[input.path] { directory = cached }
            else { directory = try OutputDirectoryIdentity.inspect(input); directories[input.path] = directory }
            var number = 1
            while true {
                let name = Self.filename(for: snapshot, number: number, format: formats[snapshot.identity.id])
                let destination = directory.0.appendingPathComponent(name)
                let key = Reservation(directory: directory.1, name: name.precomposedStringWithCanonicalMapping.lowercased())
                var info = stat()
                let exists = lstat(destination.path, &info) == 0
                guard exists || errno == ENOENT else { throw SignumError.module("Destinazione non ispezionabile. Scegli un'altra cartella.") }
                if !exists && !reserved.contains(key) {
                    reserved.insert(key); result.append(.init(url: destination, directoryIdentity: directory.1)); break
                }
                number += 1
                guard number <= 10000 else { throw SignumError.module("Troppe collisioni nella destinazione.") }
            }
        }
        for directory in directories.values { try directory.1.requireCurrent(at: directory.0) }
        return result
    }
}
#endif
