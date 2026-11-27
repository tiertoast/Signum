#if os(macOS)
import XCTest
import CryptoKit
@testable import SignumApp

struct StubUpdateTransport: SignumUpdateTransport {
    var responses: [URL: Data]
    func fetch(_ url: URL, limit: Int) async throws -> Data {
        guard let data = responses[url] else { throw SignumUpdateError.httpStatus(404) }
        guard data.count <= limit else { throw SignumUpdateError.tooLarge }
        return data
    }
}

final class SignumUpdateTests: XCTestCase {
    let key = Curve25519.Signing.PrivateKey()
    var publicKey: String { key.publicKey.rawRepresentation.base64EncodedString() }
    let dmgBytes = Data("synthetic dmg".utf8)
    let base = URL(string: "https://github.com/tiertoast/Signum/releases/download")!

    func manifest(build: Int = 19, tag: String = "v0.7.0-beta.19", bundle: String = SignumUpdatePolicy.bundleIdentifier,
                  minimum: String = "13.0") -> SignumUpdateManifest {
        let digest = SHA256.hash(data: dmgBytes).map { String(format: "%02x", $0) }.joined()
        return SignumUpdateManifest(schema: SignumUpdateManifest.currentSchema, bundleIdentifier: bundle, version: "0.7.0",
                                    build: build, tag: tag, minimumSystemVersion: minimum,
                                    dmg: .init(name: "Signum-0.7.0-beta-arm64.dmg", bytes: dmgBytes.count, sha256: digest))
    }
    func encoded(_ manifest: SignumUpdateManifest) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return try encoder.encode(manifest)
    }
    func sign(_ data: Data, with signer: Curve25519.Signing.PrivateKey? = nil) throws -> Data {
        Data(try (signer ?? key).signature(for: data).base64EncodedString().utf8)
    }

    /// One release per entry, newest first, as the GitHub API returns them.
    func releases(_ entries: [(tag: String, manifest: Data?, signature: Data?, draft: Bool)]) -> StubUpdateTransport {
        var responses: [URL: Data] = [:]
        var list: [[String: Any]] = []
        for entry in entries {
            var assets: [[String: Any]] = []
            func asset(_ name: String, _ data: Data) {
                let url = base.appendingPathComponent(entry.tag).appendingPathComponent(name)
                responses[url] = data
                assets.append(["name": name, "size": data.count, "browser_download_url": url.absoluteString])
            }
            asset("Signum-0.7.0-beta-arm64.dmg", dmgBytes)
            if let manifest = entry.manifest { asset(SignumUpdatePolicy.manifestAsset, manifest) }
            if let signature = entry.signature { asset(SignumUpdatePolicy.signatureAsset, signature) }
            list.append(["tag_name": entry.tag, "draft": entry.draft, "prerelease": true,
                         "html_url": "https://github.com/tiertoast/Signum/releases/tag/\(entry.tag)", "assets": assets])
        }
        responses[SignumUpdatePolicy.releasesAPI] = try! JSONSerialization.data(withJSONObject: list)
        return StubUpdateTransport(responses: responses)
    }
    func checker(_ transport: StubUpdateTransport, keys: [String]? = nil) -> SignumUpdateChecker {
        SignumUpdateChecker(transport: transport, publicKeys: keys ?? [publicKey],
                            systemVersion: OperatingSystemVersion(majorVersion: 14, minorVersion: 2, patchVersion: 0))
    }

    func testSignedManifestVerifiesAndTamperingIsRejected() throws {
        let data = try encoded(manifest())
        XCTAssertEqual(try SignumUpdateManifest.verified(data, signature: try sign(data), publicKeys: [publicKey]), manifest())
        var tampered = data; tampered[tampered.count - 3] ^= 1
        XCTAssertThrowsError(try SignumUpdateManifest.verified(tampered, signature: try sign(data), publicKeys: [publicKey]))
        XCTAssertThrowsError(try SignumUpdateManifest.verified(data, signature: try sign(data, with: .init()), publicKeys: [publicKey]))
        XCTAssertThrowsError(try SignumUpdateManifest.verified(data, signature: try sign(data), publicKeys: []))
        XCTAssertThrowsError(try SignumUpdateManifest.verified(data, signature: Data("not base64".utf8), publicKeys: [publicKey]))
    }

    func testPayloadMustMatchSignedSizeAndDigest() throws {
        XCTAssertNoThrow(try manifest().verifyPayload(dmgBytes))
        XCTAssertThrowsError(try manifest().verifyPayload(Data("synthetic dmX".utf8)))
        XCTAssertThrowsError(try manifest().verifyPayload(dmgBytes + Data([0])))
    }

    func testNewestSignedReleaseIsInstallable() async throws {
        let newer = try encoded(manifest(build: 20, tag: "v0.7.0-beta.20"))
        let older = try encoded(manifest())
        let transport = releases([("v0.7.0-beta.20", newer, try sign(newer), false), ("v0.7.0-beta.19", older, try sign(older), false)])
        let offer = try await checker(transport).check(currentBuild: 18)
        XCTAssertEqual(offer?.build, 20)
        XCTAssertEqual(offer?.verified?.manifest.tag, "v0.7.0-beta.20")
        XCTAssertEqual(offer?.verified?.dmg.lastPathComponent, "Signum-0.7.0-beta-arm64.dmg")
    }

    func testCurrentBuildDraftsAndOlderReleasesAreIgnored() async throws {
        let draft = try encoded(manifest(build: 21, tag: "v0.7.0-beta.21"))
        let current = try encoded(manifest(build: 18, tag: "v0.7.0-beta.18"))
        let transport = releases([("v0.7.0-beta.21", draft, try sign(draft), true), ("v0.7.0-beta.18", current, try sign(current), false),
                                  ("v0.7.0-beta.17", nil, nil, false)])
        let offer = try await checker(transport).check(currentBuild: 18)
        XCTAssertNil(offer)
    }

    func testMismatchedManifestsAreOnlyAnnounced() async throws {
        for bad in [manifest(tag: "v0.7.0-beta.20"), manifest(bundle: "io.github.tiertoast.Signum.LocalBuild"), manifest(minimum: "15.0")] {
            let data = try encoded(bad)
            let offer = try await checker(releases([("v0.7.0-beta.19", data, try sign(data), false)])).check(currentBuild: 18)
            XCTAssertEqual(offer?.build, 19); XCTAssertNil(offer?.verified)
        }
        let data = try encoded(manifest())
        let forged = try await checker(releases([("v0.7.0-beta.19", data, try sign(data, with: .init()), false)])).check(currentBuild: 18)
        XCTAssertEqual(forged?.build, 19); XCTAssertNil(forged?.verified)
        let noKeys = try await checker(releases([("v0.7.0-beta.19", data, try sign(data), false)]), keys: []).check(currentBuild: 18)
        XCTAssertEqual(noKeys?.page.absoluteString, "https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta.19")
        XCTAssertNil(noKeys?.verified)
    }

    func testUnsignedReleasesAreAnnouncedFromTheirTag() async throws {
        let offer = try await checker(releases([("v0.7.0-beta.19", nil, nil, false), ("v0.7.0-beta", nil, nil, false)])).check(currentBuild: 18)
        XCTAssertEqual(offer?.build, 19); XCTAssertNil(offer?.verified)
        let none = try await checker(releases([("v0.7.0-beta", nil, nil, false)])).check(currentBuild: 18)
        XCTAssertNil(none)
    }

    func testOnlyHTTPSGitHubHostsAreAllowed() {
        for allowed in ["https://api.github.com/repos/tiertoast/Signum/releases", "https://github.com/tiertoast/Signum/releases/download/x/y",
                        "https://objects.githubusercontent.com/a", "https://release-assets.githubusercontent.com/b"] {
            XCTAssertTrue(SignumUpdatePolicy.allows(URL(string: allowed)), allowed)
        }
        for refused in ["http://github.com/x", "https://github.com.example.org/x", "https://example.org/x",
                        "https://user@github.com/x", "file:///tmp/x"] {
            XCTAssertFalse(SignumUpdatePolicy.allows(URL(string: refused)), refused)
        }
    }

    func testMinimumSystemComparison() {
        let system = OperatingSystemVersion(majorVersion: 13, minorVersion: 4, patchVersion: 1)
        XCTAssertTrue(SignumUpdateChecker.supports("13.0", on: system))
        XCTAssertTrue(SignumUpdateChecker.supports("13.4.1", on: system))
        XCTAssertFalse(SignumUpdateChecker.supports("13.5", on: system))
        XCTAssertFalse(SignumUpdateChecker.supports("14", on: system))
        XCTAssertFalse(SignumUpdateChecker.supports("x", on: system))
    }

    func testInstallabilityRequiresTheReleaseAppInAWritableFolder() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-update-\(UUID().uuidString)")
        let app = root.appendingPathComponent("Signum.app"); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        XCTAssertEqual(SignumUpdateInstaller.installability(of: app, bundleIdentifier: SignumUpdatePolicy.bundleIdentifier), .installable)
        XCTAssertNotEqual(SignumUpdateInstaller.installability(of: app, bundleIdentifier: "io.github.tiertoast.Signum.LocalBuild"), .installable)
        XCTAssertNotEqual(SignumUpdateInstaller.installability(of: root, bundleIdentifier: SignumUpdatePolicy.bundleIdentifier), .installable)
        let translocated = URL(fileURLWithPath: "/private/var/folders/x/AppTranslocation/ABC/d/Signum.app")
        XCTAssertNotEqual(SignumUpdateInstaller.installability(of: translocated, bundleIdentifier: SignumUpdatePolicy.bundleIdentifier), .installable)
    }

    func makeBundle(_ url: URL, build: String, version: String = "0.7.0", marker: String) throws {
        try FileManager.default.createDirectory(at: url.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let info: NSDictionary = ["CFBundleIdentifier": SignumUpdatePolicy.bundleIdentifier, "CFBundleVersion": build,
                                  "CFBundleShortVersionString": version]
        XCTAssertTrue(info.write(to: url.appendingPathComponent("Contents/Info.plist"), atomically: true))
        try Data(marker.utf8).write(to: url.appendingPathComponent("Contents/marker"))
    }

    func testStagedAppMustBeTheAnnouncedBuild() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-stage-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let staged = root.appendingPathComponent("Signum.app")
        try makeBundle(staged, build: "19", marker: "new")
        var installer = SignumUpdateInstaller(root: root); installer.verifyCodeSignature = { _ in true }
        XCTAssertNoThrow(try installer.validate(staged: staged, manifest: manifest()))
        XCTAssertThrowsError(try installer.validate(staged: staged, manifest: manifest(build: 20)))
        installer.verifyCodeSignature = { _ in false }
        XCTAssertThrowsError(try installer.validate(staged: staged, manifest: manifest()))
        let stored = try SignumUpdateInstaller(root: root).store(dmgBytes, for: manifest())
        XCTAssertEqual(try Data(contentsOf: stored), dmgBytes)
        XCTAssertThrowsError(try SignumUpdateInstaller(root: root).store(Data("other".utf8), for: manifest()))
    }

    func runSwap(staged: URL, destination: URL) throws -> Int32 {
        let finished = Process(); finished.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try finished.run(); finished.waitUntilExit()
        let swap = try SignumUpdateInstaller.launchSwap(staged: staged, destination: destination, relaunch: false,
                                                        pid: finished.processIdentifier)
        swap.waitUntilExit()
        return swap.terminationStatus
    }

    func testSwapReplacesTheBundleAfterExitAndRestoresOnFailure() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-swap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("Applications/Signum.app")
        let staged = root.appendingPathComponent("cache/Signum.app")
        try makeBundle(destination, build: "18", marker: "old")
        try makeBundle(staged, build: "19", marker: "new")
        XCTAssertEqual(try runSwap(staged: staged, destination: destination), 0)
        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("Contents/marker")), "new")
        XCTAssertFalse(FileManager.default.fileExists(atPath: staged.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path + ".signum-previous"))

        XCTAssertEqual(try runSwap(staged: root.appendingPathComponent("missing.app"), destination: destination), 3)
        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("Contents/marker")), "new")
    }

    /// Optional: stages a real release DMG (SIGNUM_TEST_UPDATE_DMG) with the real codesign check.
    func testStagingARealReleaseDMG() throws {
        guard let path = ProcessInfo.processInfo.environment["SIGNUM_TEST_UPDATE_DMG"], !path.isEmpty else { throw XCTSkip("SIGNUM_TEST_UPDATE_DMG not set") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("signum-real-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let build = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_UPDATE_BUILD"] ?? "18") ?? 18
        let real = SignumUpdateManifest(schema: SignumUpdateManifest.currentSchema, bundleIdentifier: SignumUpdatePolicy.bundleIdentifier,
                                        version: "0.7.0", build: build, tag: "v0.7.0-beta.\(build)", minimumSystemVersion: "13.0",
                                        dmg: .init(name: URL(fileURLWithPath: path).lastPathComponent, bytes: data.count, sha256: digest))
        let installer = SignumUpdateInstaller(root: root)
        let staged = try installer.stage(dmg: try installer.store(data, for: real), manifest: real)
        XCTAssertTrue(FileManager.default.fileExists(atPath: staged.appendingPathComponent("Contents/MacOS").path))
        var wrong = real; wrong.build += 1
        XCTAssertThrowsError(try installer.validate(staged: staged, manifest: wrong))
    }

    /// Optional live check (SIGNUM_TEST_UPDATE_LIVE=1): real GitHub API and an asset download through its redirect.
    func testLiveGitHubCheck() async throws {
        guard ProcessInfo.processInfo.environment["SIGNUM_TEST_UPDATE_LIVE"] == "1" else { throw XCTSkip("SIGNUM_TEST_UPDATE_LIVE not set") }
        let transport = SignumUpdateHTTPS()
        let offer = try await SignumUpdateChecker(transport: transport).check(currentBuild: 17)
        XCTAssertGreaterThanOrEqual(offer?.build ?? 0, 18)
        let releases = try GitHubRelease.decodeList(try await transport.fetch(SignumUpdatePolicy.releasesAPI, limit: SignumUpdatePolicy.releaseListLimit))
        let sums = try XCTUnwrap(releases.first { $0.tagName == "v0.7.0-beta.18" }?.asset("SHA256SUMS.txt"))
        let data = try await transport.fetch(sums.browserDownloadUrl, limit: 64 * 1024)
        XCTAssertEqual(data.count, sums.size)
        do { _ = try await transport.fetch(sums.browserDownloadUrl, limit: 10); XCTFail("limit not enforced") }
        catch { XCTAssertEqual(error as? SignumUpdateError, .tooLarge) }
    }

    func testPreferencesDefaultToCheckAndInstall() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "signum-update-tests-\(UUID().uuidString)"))
        let preferences = SignumUpdatePreferences(defaults: defaults)
        XCTAssertTrue(preferences.checkAtLaunch); XCTAssertTrue(preferences.installAutomatically)
        preferences.installAutomatically = false
        XCTAssertFalse(preferences.installAutomatically); XCTAssertTrue(preferences.checkAtLaunch)
    }
}
#endif
