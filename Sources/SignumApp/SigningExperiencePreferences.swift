#if os(macOS)
import Foundation
import SignumCore

struct SigningDestinationSelection {
    var alongsideOriginal = true
    var customDirectory: URL?
    var policy: BatchOutputDestination? {
        if alongsideOriginal { return .originalFolders }
        guard let customDirectory, customDirectory.isFileURL, MiddlewarePreferences.valid(customDirectory.path) else { return nil }
        return .commonDirectory(customDirectory)
    }
}

struct SigningExperiencePreferences {
    enum Keys {
        static let showExcluded = "signum.signing.showExcludedCertificates.v1"
        static let alongsideOriginal = "signum.signing.alongsideOriginal.v1"
        static let customDirectory = "signum.signing.customDirectoryPath.v1"
    }
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    var showExcluded: Bool {
        get { defaults.bool(forKey: Keys.showExcluded) }
        nonmutating set { defaults.set(newValue, forKey: Keys.showExcluded) }
    }
    var alongsideOriginal: Bool {
        get { defaults.object(forKey: Keys.alongsideOriginal) == nil || defaults.bool(forKey: Keys.alongsideOriginal) }
        nonmutating set { defaults.set(newValue, forKey: Keys.alongsideOriginal) }
    }
    /// A remembered location is not an access grant. The nonsandboxed app checks
    /// current OS permissions on every plan; no permanent bookmark is created.
    var customDirectory: URL? {
        get {
            guard let path = defaults.string(forKey: Keys.customDirectory), MiddlewarePreferences.valid(path) else { return nil }
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        nonmutating set {
            if let next = newValue, next.isFileURL, MiddlewarePreferences.valid(next.path) {
                defaults.set(next.path, forKey: Keys.customDirectory)
            } else { defaults.removeObject(forKey: Keys.customDirectory) }
        }
    }
}
#endif
