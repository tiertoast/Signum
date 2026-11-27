#if os(macOS)
import Foundation
import CryptoKit

/// Update policy: GitHub Releases is only the transport. An update is installed
/// automatically only when its manifest carries an Ed25519 signature made with
/// a key listed here; everything else is offered as a link to the release page.
enum SignumUpdatePolicy {
    static let bundleIdentifier = "io.github.tiertoast.Signum"
    static let releasesAPI = URL(string: "https://api.github.com/repos/tiertoast/Signum/releases?per_page=20")!
    static let manifestAsset = "SignumUpdate.json"
    static let signatureAsset = "SignumUpdate.json.sig"
    /// Base64 raw Ed25519 public keys. Empty until the release signing key exists:
    /// updates are then announced but never installed automatically.
    static let trustedPublicKeys: [String] = []
    /// HTTPS hosts the update client may contact, including GitHub's asset redirects.
    static let allowedHosts: Set<String> = ["api.github.com", "github.com", "objects.githubusercontent.com",
                                            "release-assets.githubusercontent.com"]
    static func allows(_ url: URL?) -> Bool {
        guard let url, url.scheme == "https", let host = url.host?.lowercased(), url.user == nil else { return false }
        return allowedHosts.contains(host)
    }
    static let manifestLimit = 64 * 1024
    static let releaseListLimit = 4 * 1024 * 1024
    static let dmgLimit = 512 * 1024 * 1024
}

enum SignumUpdateError: Error, Equatable, LocalizedError {
    case disallowedURL, httpStatus(Int), tooLarge, invalidResponse
    case payloadMismatch, invalidSignature, unsupportedManifest
    case stagingFailed(String), stagedAppMismatch(String)

    var errorDescription: String? {
        switch self {
        case .disallowedURL: return "Indirizzo di aggiornamento non consentito."
        case .httpStatus(let code): return "GitHub ha risposto con il codice \(code)."
        case .tooLarge: return "Il file scaricato supera la dimensione prevista."
        case .invalidResponse: return "Risposta di GitHub non valida."
        case .payloadMismatch: return "Il file scaricato non corrisponde all’impronta firmata."
        case .invalidSignature: return "La firma dell’aggiornamento non è valida."
        case .unsupportedManifest: return "Descrizione dell’aggiornamento non supportata."
        case .stagingFailed(let detail): return "Preparazione dell’aggiornamento non riuscita: \(detail)"
        case .stagedAppMismatch(let detail): return "L’app scaricata non corrisponde all’aggiornamento: \(detail)"
        }
    }
}

struct SignumUpdateManifest: Codable, Equatable {
    static let currentSchema = "signum-update-v1"
    struct Payload: Codable, Equatable { var name: String; var bytes: Int; var sha256: String }
    var schema: String
    var bundleIdentifier: String
    var version: String
    var build: Int
    var tag: String
    var minimumSystemVersion: String
    var dmg: Payload

    /// Verifies the exact published bytes against any trusted key, then decodes them.
    static func verified(_ data: Data, signature: Data, publicKeys: [String]) throws -> SignumUpdateManifest {
        guard let text = String(data: signature, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let raw = Data(base64Encoded: text), raw.count == 64 else { throw SignumUpdateError.invalidSignature }
        let trusted = publicKeys.contains { key in
            guard let keyData = Data(base64Encoded: key),
                  let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else { return false }
            return publicKey.isValidSignature(raw, for: data)
        }
        guard trusted else { throw SignumUpdateError.invalidSignature }
        guard let manifest = try? JSONDecoder().decode(SignumUpdateManifest.self, from: data),
              manifest.schema == currentSchema, manifest.build > 0, manifest.dmg.bytes > 0,
              manifest.dmg.sha256.count == 64, !manifest.dmg.name.contains("/") else {
            throw SignumUpdateError.unsupportedManifest
        }
        return manifest
    }

    func verifyPayload(_ data: Data) throws {
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard data.count == dmg.bytes, digest == dmg.sha256.lowercased() else { throw SignumUpdateError.payloadMismatch }
    }
}

struct GitHubRelease: Decodable, Equatable {
    struct Asset: Decodable, Equatable { var name: String; var size: Int; var browserDownloadUrl: URL }
    var tagName: String
    var draft: Bool
    var htmlUrl: URL
    var assets: [Asset]
    func asset(_ name: String) -> Asset? { assets.first { $0.name == name } }

    /// Build number of tags like `v0.7.0-beta.18`; nil for tags without one.
    var tagBuild: Int? {
        guard let dot = tagName.lastIndex(of: "."), let value = Int(tagName[tagName.index(after: dot)...]) else { return nil }
        return tagName.contains("-beta.") || tagName.contains("-rc.") ? value : nil
    }
    static func decodeList(_ data: Data) throws -> [GitHubRelease] {
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let list = try? decoder.decode([GitHubRelease].self, from: data) else { throw SignumUpdateError.invalidResponse }
        return list
    }
}

/// What the check found for this installation.
struct SignumUpdateOffer: Equatable {
    var build: Int
    var tag: String
    var page: URL
    /// Present only when the signed manifest verified and matches the release.
    var verified: (manifest: SignumUpdateManifest, dmg: URL)?
    var title: String { verified.map { "Signum \($0.manifest.version) — Build \(build)" } ?? "Signum Build \(build)" }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.build == rhs.build && lhs.tag == rhs.tag && lhs.page == rhs.page
            && lhs.verified?.manifest == rhs.verified?.manifest && lhs.verified?.dmg == rhs.verified?.dmg
    }
}

protocol SignumUpdateTransport: Sendable {
    func fetch(_ url: URL, limit: Int) async throws -> Data
}

struct SignumUpdateChecker {
    var transport: any SignumUpdateTransport
    var publicKeys: [String] = SignumUpdatePolicy.trustedPublicKeys
    var bundleIdentifier = SignumUpdatePolicy.bundleIdentifier
    var systemVersion = ProcessInfo.processInfo.operatingSystemVersion

    /// Newest release with a higher build. A signed, matching manifest makes it
    /// installable; a release without one (or with an invalid one) is only announced.
    func check(currentBuild: Int) async throws -> SignumUpdateOffer? {
        let releases = try GitHubRelease.decodeList(try await transport.fetch(SignumUpdatePolicy.releasesAPI,
                                                                              limit: SignumUpdatePolicy.releaseListLimit))
        var announced: SignumUpdateOffer?
        for release in releases where !release.draft {
            if let offer = await verifiedOffer(release, currentBuild: currentBuild) { return offer }
            if announced == nil, let build = release.tagBuild, build > currentBuild {
                announced = SignumUpdateOffer(build: build, tag: release.tagName, page: release.htmlUrl, verified: nil)
            }
        }
        return announced
    }

    private func verifiedOffer(_ release: GitHubRelease, currentBuild: Int) async -> SignumUpdateOffer? {
        guard !publicKeys.isEmpty,
              let manifestAsset = release.asset(SignumUpdatePolicy.manifestAsset),
              let signatureAsset = release.asset(SignumUpdatePolicy.signatureAsset),
              let manifestData = try? await transport.fetch(manifestAsset.browserDownloadUrl, limit: SignumUpdatePolicy.manifestLimit),
              let signature = try? await transport.fetch(signatureAsset.browserDownloadUrl, limit: 1024),
              let manifest = try? SignumUpdateManifest.verified(manifestData, signature: signature, publicKeys: publicKeys),
              manifest.tag == release.tagName, manifest.bundleIdentifier == bundleIdentifier,
              manifest.build > currentBuild, Self.supports(manifest.minimumSystemVersion, on: systemVersion),
              let dmg = release.asset(manifest.dmg.name), dmg.size == manifest.dmg.bytes else { return nil }
        return SignumUpdateOffer(build: manifest.build, tag: release.tagName, page: release.htmlUrl,
                                 verified: (manifest, dmg.browserDownloadUrl))
    }

    static func supports(_ minimum: String, on system: OperatingSystemVersion) -> Bool {
        let parts = minimum.split(separator: ".").map { Int($0) }
        guard !parts.isEmpty, parts.allSatisfy({ $0 != nil }) else { return false }
        let wanted = parts.compactMap { $0 } + [0, 0]
        let have = [system.majorVersion, system.minorVersion, system.patchVersion]
        for index in 0..<3 where wanted[index] != have[index] { return have[index] > wanted[index] }
        return true
    }
}
#endif
