#if os(macOS)
import Foundation

/// Short paths for ordinary consent, with enough parent context to distinguish
/// namesakes. Full paths and hashes remain in the technical disclosure.
enum BatchDisplay {
    static func sourceLabel(_ source: URL, among sources: [URL]) -> String {
        let namesakes = sources.filter { $0.lastPathComponent.compare(source.lastPathComponent, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame }
        let components = source.deletingLastPathComponent().pathComponents.filter { $0 != "/" }
        if namesakes.count < 2 { return components.last ?? "/" }
        for depth in 1...max(1, components.count) {
            let suffix = Array(components.suffix(depth))
            let matches = namesakes.filter {
                Array($0.deletingLastPathComponent().pathComponents.filter { $0 != "/" }.suffix(depth)) == suffix
            }
            if matches.count == 1 { return suffix.joined(separator: " / ") }
        }
        return source.deletingLastPathComponent().path
    }
    static func destinationLabel(_ destination: URL) -> String {
        destinationLabel(destination, among: [])
    }
    static func destinationLabel(_ destination: URL, among destinations: [URL]) -> String {
        "\(sourceLabel(destination, among: destinations)) / \(destination.lastPathComponent)"
    }
}
#endif
