#if os(macOS)
import AppKit

/// Project links for "Informazioni su Signum" and the Aiuto menu.
/// Licences open the copies bundled in the app, so they work offline.
enum SignumAboutLinks {
    static let repository = URL(string: "https://github.com/tiertoast/Signum")!
    static let issues = URL(string: "https://github.com/tiertoast/Signum/issues")!
    static let releases = URL(string: "https://github.com/tiertoast/Signum/releases")!

    static func bundled(_ name: String, in bundle: Bundle = .main) -> URL? {
        guard let url = bundle.resourceURL?.appendingPathComponent(name),
              FileManager.default.fileExists(atPath: url.path) else { return nil }
        return url
    }
    static var license: URL? { bundled("Signum-LICENSE.txt") }
    static var thirdPartyNotices: URL? { bundled("Notices") }
    static var thirdPartySources: URL? { bundled("ThirdPartySources") }

    /// Credits for the standard About panel: links only, no tracking parameters.
    static func credits() -> NSAttributedString {
        let body = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        let centered = NSMutableParagraphStyle(); centered.alignment = .center
        let text = NSMutableAttributedString()
        func line(_ string: String, link: URL? = nil) {
            var attributes: [NSAttributedString.Key: Any] = [.font: body, .paragraphStyle: centered,
                                                             .foregroundColor: NSColor.labelColor]
            if let link { attributes[.link] = link }
            text.append(NSAttributedString(string: string, attributes: attributes))
        }
        line("Firma digitale locale per macOS.\nSoftware libero con licenza Apache 2.0.\n\n")
        line("Progetto su GitHub", link: repository); line("  ·  ")
        line("Segnala un problema", link: issues); line("  ·  ")
        line("Note di rilascio", link: releases)
        line("\n\nLicenze di terze parti: menu Aiuto.")
        return text
    }
}
#endif
