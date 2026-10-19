#if os(macOS)
import Foundation

/// Configuration is untrusted input. Remembering a path never authorizes its
/// execution on launch; every manual load requires the user's explicit action.
struct MiddlewarePreferences {
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    private let pathsKey = "signum.discovery.manualPaths.v1"
    private let preferredKey = "signum.discovery.preferredPath.v1"
    static func valid(_ path: String) -> Bool {
        path.hasPrefix("/") && path.utf8.count <= 4096 && !path.utf8.contains(0) &&
            !path.split(separator: "/").contains("..")
    }
    var paths: [String] {
        var seen = Set<String>()
        return Array((defaults.stringArray(forKey: pathsKey) ?? []).filter { Self.valid($0) && seen.insert($0).inserted }.prefix(8))
    }
    // Single trigger policy consumed by the window before starting discovery.
    func discoveryPaths(explicitPath: String? = nil, authorizedPaths: [String] = []) -> [String] {
        var seen = Set<String>()
        return Array(((explicitPath.map { [$0] } ?? []) + authorizedPaths)
            .filter { Self.valid($0) && seen.insert($0).inserted }.prefix(8))
    }
    var preferredPath: String? {
        guard let path = defaults.string(forKey: preferredKey), Self.valid(path) else { return nil }; return path
    }
    func remember(_ path: String) {
        guard Self.valid(path) else { return }
        defaults.set(Array(([path] + paths.filter { $0 != path }).prefix(8)), forKey: pathsKey)
    }
    func prefer(_ path: String) { if Self.valid(path) { defaults.set(path, forKey: preferredKey) } }
    func remove(_ path: String) {
        defaults.set(paths.filter { $0 != path }, forKey: pathsKey)
        if preferredPath == path { defaults.removeObject(forKey: preferredKey) }
    }
}
#endif
