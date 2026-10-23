#if os(macOS)
import SwiftUI
import SignumCore

extension Notification.Name { static let signumShowSettings = Notification.Name("Signum.ShowSettings") }

/// Visual vocabulary for Signum 0.7. System colors and materials remain in
/// charge of content and legibility; Burgundy is reserved for tint and actions.
enum SignumAppearance {
    // Foreground variant only: preserve contrast on native dark control surfaces.
    static let burgundyForeground = Color(red: 220.0 / 255.0, green: 161.0 / 255.0, blue: 173.0 / 255.0)
    static let burgundy = Color(red: 100.0 / 255.0, green: 49.0 / 255.0, blue: 62.0 / 255.0)
}

enum SignumSection: String, Hashable, CaseIterable {
    case sign, verify, devices, settings

    var title: String {
        switch self {
        case .sign: return "Firma"
        case .verify: return "Verifica"
        case .devices: return "Dispositivi"
        case .settings: return "Impostazioni"
        }
    }

    var symbol: String {
        switch self {
        case .sign: return "signature"
        case .verify: return "checkmark.shield"
        case .devices: return "externaldrive"
        case .settings: return "gearshape"
        }
    }
}

/// Settings stay attached to the document window and its operation locks.
/// Returning never rebuilds the signing workspace or replaces its selection.
struct SignumNavigation {
    var section: SignumSection
    private(set) var settingsOrigin: SignumSection = .sign
    init(section: SignumSection = .sign) { self.section = section }
    mutating func select(_ next: SignumSection) {
        if next == .settings { openSettings(blocked: false) }
        else { section = next }
    }
    mutating func openSettings(blocked: Bool) {
        guard !blocked else { return }
        if section != .settings { settingsOrigin = section }
        section = .settings
    }
    mutating func back() {
        guard section == .settings else { return }
        section = settingsOrigin
    }
}

/// Short summaries deliberately omit diagnostic paths, fingerprints and PKCS#11
/// details, which remain available through the existing disclosure controls.
struct SignumSummaryRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value)
                .fontWeight(.medium)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
                .help(value)
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }
}

struct SignumEmptyDocumentsView: View {
    let choose: () -> Void

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.badge.plus")
                .font(.system(size: 36, weight: .light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("I tuoi documenti, pronti per la firma")
                .font(.headline)
            Text("Trascina qui uno o più documenti oppure selezionali dal Mac.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Aggiungi documenti…", action: choose)
                .buttonStyle(.borderedProminent)
                .tint(SignumAppearance.burgundy)
                .controlSize(.large)
        }
        .padding(28)
        .frame(maxWidth: .infinity, minHeight: 230)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(Color.secondary.opacity(0.3), style: StrokeStyle(lineWidth: 1, dash: [6, 5]))
        )
        .accessibilityElement(children: .contain)
    }
}
// NavigationSplitView owns the system sidebar material and toolbar integration.
// Extend adjacent content only on the SDK-provided implementation; never emulate glass.
struct SignumChromeExtension: ViewModifier {
    let enabled: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if #available(macOS 26, *) { content.backgroundExtensionEffect(isEnabled: enabled) }
        else { content }
    }
}

struct SignumContextHelp: View {
    let title: String
    let text: String
    @State private var showing = false
    var body: some View {
        Button { showing.toggle() } label: { Label(title, systemImage: "info.circle") }
            .buttonStyle(.borderless)
            .popover(isPresented: $showing) {
                Text(text).textSelection(.enabled).padding(20).frame(width: 340, alignment: .leading)
            }
    }
}

extension SignumFormat {
    var displayTitle: String {
        switch self {
        case .cades: return "CAdES — Firma P7M"
        case .pades: return "PAdES — Firma PDF"
        case .xades: return "XAdES — Firma XML"
        case .cadesDetached: return "Firma separata — P7S"
        case .cadesCoSign: return "Aggiungi una firma — P7M"
        case .cadesCounterSign: return "Controfirma"
        case .asics: return "Contenitore firmato — 1 file (ASiC-S)"
        case .asice: return "Contenitore firmato — più file (ASiC-E)"
        }
    }
}
enum SigningIncomingFormat {
    static func resolve(override: SignumFormat?, selected: SigningFormat?, fallback: SignumFormat) -> SignumFormat {
        override ?? selected.flatMap { SignumFormat(rawValue: $0.rawValue) } ?? fallback
    }
}

enum SigningConsentDeclaration {
    static func text(documentCount: Int) -> String {
        documentCount > 1
            ? "Dichiaro di aver preso visione dei documenti, di sottoscriverne il contenuto e di essere consapevole della validità ai sensi della legge delle firme apposte."
            : "Dichiaro di aver preso visione del documento, di sottoscriverne il contenuto e di essere consapevole della validità ai sensi della legge della firma apposta."
    }
}

extension SignumFormat {
    var shortDescription: String {
        switch self {
        case .cades: return "Crea un file .p7m contenente il documento e la firma digitale."
        case .pades: return "Appone la firma digitale direttamente al PDF."
        case .xades: return "Inserisce la firma digitale nel documento XML."
        case .cadesDetached: return "Crea una firma .p7s separata; conserva anche il documento originale."
        case .cadesCoSign: return "Aggiunge una firma al contenuto di un file P7M già firmato."
        case .cadesCounterSign: return "Firma una delle firme già presenti nel file P7M."
        case .asics: return "Riunisce un documento e la sua firma in un contenitore."
        case .asice: return "Riunisce più documenti e la loro firma in un contenitore."
        }
    }
}
struct SignumFlexibleControl: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if #available(macOS 26, *) { content.buttonSizing(.flexible) }
        else { content }
    }
}
#endif
