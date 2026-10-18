#if os(macOS)
import Foundation
import Darwin
import COutputPermissions

public struct MiddlewareFileIdentity: Codable, Hashable, Sendable {
    public let device: Int64, inode: UInt64, size: Int64
    public let modifiedSeconds: Int64, modifiedNanoseconds: Int64
    public let changedSeconds: Int64, changedNanoseconds: Int64
    public var moduleKey: String { "\(device):\(inode)" }
    init(_ value: stat) {
        device = Int64(value.st_dev); inode = UInt64(value.st_ino); size = value.st_size
        modifiedSeconds = Int64(value.st_mtimespec.tv_sec); modifiedNanoseconds = Int64(value.st_mtimespec.tv_nsec)
        changedSeconds = Int64(value.st_ctimespec.tv_sec); changedNanoseconds = Int64(value.st_ctimespec.tv_nsec)
    }
}

/// Read-only policy, repeated in the worker before any vendor code executes.
/// Root-owned paths prevent replacement by an unprivileged account. This does
/// not establish vendor authenticity or defend against a privileged administrator.
public enum MiddlewareFileSecurity {
    public enum Failure: Error { case missing, unsafe, changed }
    public struct Inspection: Sendable {
        public let canonicalPath: String
        public let identity: MiddlewareFileIdentity
    }
    struct Node: Equatable {
        let identity: MiddlewareFileIdentity
        let owner: UInt32, mode: UInt16
        let aclSafe: Bool
        var isLink: Bool { mode & UInt16(S_IFMT) == UInt16(S_IFLNK) }
        var isDirectory: Bool { mode & UInt16(S_IFMT) == UInt16(S_IFDIR) }
        var isRegular: Bool { mode & UInt16(S_IFMT) == UInt16(S_IFREG) }
        var trusted: Bool { owner == 0 && (isLink || (mode & 0o022 == 0 && aclSafe)) }
    }
    static func node(_ path: String) throws -> Node {
        var before = stat(), after = stat()
        guard lstat(path, &before) == 0 else { throw errno == ENOENT ? Failure.missing : Failure.unsafe }
        let link = before.st_mode & S_IFMT == S_IFLNK
        let aclSafe = link || sg_discovery_acl_safe(path) == 1
        guard lstat(path, &after) == 0, MiddlewareFileIdentity(before) == MiddlewareFileIdentity(after) else { throw Failure.changed }
        return Node(identity: .init(after), owner: after.st_uid, mode: after.st_mode, aclSafe: aclSafe)
    }
    static func canonical(_ path: String) throws -> String {
        guard let pointer = realpath(path, nil) else { throw errno == ENOENT ? Failure.missing : Failure.unsafe }
        defer { free(pointer) }; return String(cString: pointer)
    }
    public static func inspect(_ path: String, automatic: Bool) throws -> Inspection {
        try inspect(path, automatic: automatic, resolve: canonical, read: node)
    }
    // Filesystem injection is internal and never enabled by production flags/env.
    static func inspect(_ path: String, automatic: Bool, resolve: (String) throws -> String,
                        read: (String) throws -> Node) throws -> Inspection {
        guard path.hasPrefix("/"), path.utf8.count <= 4096, !path.utf8.contains(0),
              !path.split(separator: "/").contains("..") else { throw Failure.unsafe }
        let canonical = try resolve(path), file = try read(canonical)
        guard file.isRegular else { throw Failure.unsafe }
        if automatic {
            var checked: [String: Node] = [:]
            func check(_ location: String, leaf: Bool) throws {
                if let prior = checked[location] {
                    guard leaf || prior.isDirectory || prior.isLink else { throw Failure.unsafe }; return
                }
                let value = try read(location)
                guard value.trusted, (leaf ? value.isRegular || value.isLink : value.isDirectory || value.isLink) else { throw Failure.unsafe }
                checked[location] = value
            }
            func chain(_ location: String, leafIsFile: Bool) throws {
                try check("/", leaf: false)
                let components = location.split(separator: "/")
                guard components.count <= 128 else { throw Failure.unsafe }
                var prefix = ""
                for (index, part) in components.enumerated() {
                    prefix += "/" + part; try check(prefix, leaf: leafIsFile && index == components.count - 1)
                }
            }
            // Inspect the path spelling, every symlink target and all of each
            // target's ancestors. A protected symlink into /Users is not trusted.
            try chain(path, leafIsFile: true)
            var prefix = ""
            for part in path.split(separator: "/") {
                prefix += "/" + part
                try chain(resolve(prefix), leafIsFile: prefix == path)
            }
            for (location, previous) in checked {
                guard try read(location) == previous else { throw Failure.changed }
            }
        }
        guard try resolve(path) == canonical, try read(canonical) == file else { throw Failure.changed }
        return Inspection(canonicalPath: canonical, identity: file.identity)
    }
}
#endif
