#if os(macOS)
import Foundation

struct SigningExperiencePreferences {
    enum Keys {
        static let showExcluded = "signum.signing.showExcludedCertificates.v1"
    }
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    var showExcluded: Bool {
        get { defaults.bool(forKey: Keys.showExcluded) }
        nonmutating set { defaults.set(newValue, forKey: Keys.showExcluded) }
    }
}
#endif
