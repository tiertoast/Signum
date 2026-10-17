#if os(macOS)
import Foundation

enum AppVersion {
    static var label: String { label(info: Bundle.main.infoDictionary) }

    static func label(info: [String: Any]?) -> String {
        guard let version = info?["CFBundleShortVersionString"] as? String,
              !version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return "Build di sviluppo" }
        guard let build = info?["CFBundleVersion"] as? String, !build.isEmpty else { return version }
        return "\(version) · build \(build)"
    }
}
#endif
