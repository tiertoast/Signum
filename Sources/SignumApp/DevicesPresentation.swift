#if os(macOS)
import Foundation
import Security
import CryptoKit
import SignumCore

/// Presentation correlation only. A group never proves shared physical hardware
/// and never deduplicates or chooses security routes in DeviceSelection.
struct DevicePresentation: Identifiable {
    struct Access: Identifiable {
        let id: String
        let provider: DiscoveredMiddleware
        let observed: DiscoveredToken
        let routes: [DeviceCertificateRoute]
    }
    var accesses: [Access]
    var id: String { accesses.map(\.id).sorted().joined(separator: "|") }
    var routes: [DeviceCertificateRoute] {
        var seen = Set<String>()
        return accesses.flatMap(\.routes).filter { seen.insert($0.id).inserted }
    }
    var certificateGroups: [[DeviceCertificateRoute]] {
        Dictionary(grouping: routes, by: \.certificateFingerprint).values.sorted {
            let a = $0[0], b = $1[0]
            if a.assessment.permitsSigning != b.assessment.permitsSigning { return a.assessment.permitsSigning }
            return a.certificateFingerprint < b.certificateFingerprint
        }
    }
    var name: String { accesses.first.map { SigningRouteLabel.device(token: $0.observed.token) } ?? "Dispositivo PKCS#11" }
    var symbol: String { name.contains("card") || name.contains("CNS") ? "creditcard" : name.contains("USB") || name == "DigitalDNA" ? "externaldrive" : "externaldrive.badge.questionmark" }
    var readable: Bool { accesses.allSatisfy { $0.observed.certificateState == .readable && $0.provider.inspection != nil } }
    var countLabel: String { readable ? "\(certificateGroups.count) certificati individuati" : "Numero di certificati non determinabile" }
    var availability: String {
        readable ? "Disponibile · lettura pubblica completata" : "Rilevato · disponibilità dei certificati non determinata"
    }
    static func collect(_ selection: DeviceSelection) -> [Self] {
        let routes = selection.certificates.flatMap(\.routes)
        var accesses: [Access] = [], seen = Set<String>()
        for provider in selection.providers {
            for observed in provider.tokens {
                let token = observed.token
                let path = provider.inspection?.canonicalPath ?? provider.candidatePath
                let identity = provider.inspection?.identity
                let components = [path, identity?.moduleKey ?? "unverified", identity.map { String($0.size) } ?? "",
                    identity.map { "\($0.modifiedSeconds):\($0.modifiedNanoseconds):\($0.changedSeconds):\($0.changedNanoseconds)" } ?? "",
                    String(token.slot), token.label, token.serial, token.manufacturer, token.model, token.reader]
                let id = SHA256.hash(data: Data(components.map { "\($0.utf8.count):\($0)" }.joined().utf8)).map { String(format: "%02x", $0) }.joined()
                guard seen.insert(id).inserted else { continue }
                let matching = routes.filter { $0.providerPath == path && $0.moduleIdentity == identity && $0.token.slot == token.slot && $0.token.serial == token.serial && $0.token.model == token.model && $0.token.manufacturer == token.manufacturer && $0.token.reader == token.reader }
                accesses.append(.init(id: id, provider: provider, observed: observed, routes: matching))
            }
        }
        var result: [Self] = []
        for access in accesses {
            // Require shared DER AND nonempty, matching public token attributes.
            // This is only a useful visual correlation, not hardware identity.
            if let index = result.firstIndex(where: { group in group.accesses.contains { other in
                let a = access.observed.token, b = other.observed.token
                return !a.serial.isEmpty && a.serial == b.serial && a.model == b.model && a.manufacturer == b.manufacturer &&
                    !Set(access.routes.map(\.certificateFingerprint)).intersection(other.routes.map(\.certificateFingerprint)).isEmpty
            } }) { result[index].accesses.append(access) }
            else { result.append(.init(accesses: [access])) }
        }
        return result
    }
    static func certificateState(_ route: DeviceCertificateRoute, at date: Date = Date()) -> String {
        if let expiry = route.assessment.notAfter, expiry <= date { return "Scaduto" }
        return route.assessment.status.description
    }
    static func purpose(_ route: DeviceCertificateRoute) -> String {
        if route.assessment.contentCommitment || route.assessment.documentSigning { return "Firma digitale" }
        if route.assessment.clientAuthentication { return "Autenticazione" }
        return "Altra funzione / non determinata"
    }
    /// Security.framework is used for informational extension text only.
    static func extensionDetails(_ der: Data) -> String {
        guard der.count <= 65536, let cert = SecCertificateCreateWithData(nil, der as CFData),
              let values = SecCertificateCopyValues(cert, [kSecOIDKeyUsage, kSecOIDExtendedKeyUsage, kSecOIDCertificatePolicies] as CFArray, nil) as? [String: Any] else { return "Estensioni non disponibili." }
        func describe(_ value: Any, depth: Int = 0) -> String {
            guard depth < 8 else { return "…" }
            if let array = value as? [Any] { return array.prefix(128).map { describe($0, depth: depth + 1) }.joined(separator: "\n") }
            if let item = value as? [String: Any] {
                let label = item[kSecPropertyKeyLabel as String] as? String ?? ""
                let body = item[kSecPropertyKeyValue as String].map { describe($0, depth: depth + 1) } ?? ""
                return label.isEmpty ? body : label + ": " + body
            }
            return String(describing: value)
        }
        return [(kSecOIDKeyUsage as String, "Key Usage · 2.5.29.15"),
                (kSecOIDExtendedKeyUsage as String, "Extended Key Usage · 2.5.29.37"),
                (kSecOIDCertificatePolicies as String, "Certificate Policies · 2.5.29.32")].map { key, title in
            title + "\n" + (values[key].map { describe($0) } ?? "Estensione assente o non disponibile")
        }.joined(separator: "\n\n")
    }
}
#endif
