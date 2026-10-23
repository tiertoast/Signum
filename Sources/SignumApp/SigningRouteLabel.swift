#if os(macOS)
import SignumCore

/// Presentation only: labels never participate in certificate/route selection.
enum SigningRouteLabel {
    static func device(token: SignumToken) -> String {
        let metadata = [token.model, token.label, token.reader].joined(separator: " ").lowercased()
        let compact = metadata.filter { $0.isLetter || $0.isNumber }
        if compact.contains("digitaldna") { return "DigitalDNA" }
        if metadata.contains("cns") { return "Smart card CNS" }
        if metadata.contains("smart card") || metadata.contains("smartcard") { return "Smart card" }
        if metadata.contains("usb") { return "Token USB" }
        // Don't claim a hardware form factor from a certificate or middleware name.
        let model = token.model.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.isEmpty ? "Dispositivo PKCS#11" : model
    }
    static func title(_ route: DeviceCertificateRoute) -> String {
        "\(route.title) — \(device(token: route.token))"
    }
    static func tooltip(_ route: DeviceCertificateRoute) -> String {
        "\(title(route))\n\(route.deviceDescription)\n\(route.providerName) · slot \(route.token.slot)"
    }
}
#endif
