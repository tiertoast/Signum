#if os(macOS)
import SwiftUI

/// Independent button action so removal never doubles as row selection.
struct SessionRemovalButton: View {
    let name: String
    let disabled: Bool
    let action: () -> Void
    @State private var hovered = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        Button {
            withAnimation(reduceMotion ? nil : .default, action)
        } label: {
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(hovered ? .primary : .secondary)
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .onHover { hovered = $0 }
        .help("Rimuovi dalla sessione")
        .accessibilityLabel("Rimuovi dalla sessione: " + name)
        .disabled(disabled)
    }
}
#endif
