#if os(macOS)
import SwiftUI

/// Visual vocabulary for Signum 0.7. System colors and materials remain in
/// charge of content and legibility; Burgundy is reserved for tint and actions.
enum SignumAppearance {
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
#endif
