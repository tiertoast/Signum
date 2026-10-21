#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

final class BatchAuthenticationPreferenceTests: XCTestCase {
    func testPreferenceIsPersistentAndContainsNoCredential() throws {
        let name = "Signum.synthetic.auth." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let preferences = SigningExperiencePreferences(defaults: defaults)
        XCTAssertEqual(preferences.authenticationMode, .automatic)
        preferences.authenticationMode = .perSignature
        XCTAssertEqual(SigningExperiencePreferences(defaults: defaults).authenticationMode, .perSignature)
        XCTAssertEqual(defaults.persistentDomain(forName: name)?.count, 1)
        XCTAssertEqual(defaults.string(forKey: SigningExperiencePreferences.Keys.batchAuthentication), "perSignature")
        defaults.set("unknown-value", forKey: SigningExperiencePreferences.Keys.batchAuthentication)
        XCTAssertEqual(preferences.authenticationMode, .perSignature)
    }
    func testSigningTimeDefaultsOnAndPersistsBothChoices() throws {
        let name = "Signum.synthetic.time." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let preferences = SigningExperiencePreferences(defaults: defaults)
        XCTAssertTrue(preferences.includeSigningTime)
        preferences.includeSigningTime = false
        XCTAssertFalse(SigningExperiencePreferences(defaults: defaults).includeSigningTime)
        XCTAssertEqual(defaults.persistentDomain(forName: name)?.count, 1)
        preferences.includeSigningTime = true
        XCTAssertTrue(SigningExperiencePreferences(defaults: defaults).includeSigningTime)
    }
    func testPolicyDoesNotPromiseReuseForPAdESMixedOrUnknownIdentity() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let jobs = try [SigningFormat.cades, .cades, .pades].enumerated().map { index, format -> SigningJob in
            let source = root.appendingPathComponent("synthetic-\(index).txt"); try Data("Policy fixture \(index)".utf8).write(to: source)
            let snapshot = try DocumentSnapshot.capture(source: source, format: format)
            return try SigningJob(snapshot: snapshot, providerPath: "/synthetic/provider", slot: 7,
                certificate: .init(label: "DS3 label does not imply capability", identifier: Data([1])), certificateDER: der,
                destination: root.appendingPathComponent("out-\(index)." + (format == .cades ? "p7m" : "pdf")))
        }
        defer { jobs.forEach { $0.snapshot.close() } }
        XCTAssertTrue(BatchAuthenticationPolicy.canAttempt(jobs: Array(jobs.prefix(2)), serial: "synthetic", mode: .automatic))
        XCTAssertTrue(BatchAuthenticationPolicy.canAttempt(jobs: Array(jobs.prefix(2)), serial: "synthetic", mode: .temporaryPIN))
        XCTAssertFalse(BatchAuthenticationPolicy.canAttempt(jobs: jobs, serial: "synthetic", mode: .temporaryPIN))
        XCTAssertFalse(BatchAuthenticationPolicy.canAttempt(jobs: jobs, serial: "synthetic", mode: .automatic))
        XCTAssertFalse(BatchAuthenticationPolicy.canAttempt(jobs: Array(jobs.prefix(2)), serial: "", mode: .automatic))
        XCTAssertFalse(BatchAuthenticationPolicy.canAttempt(jobs: Array(jobs.prefix(2)), serial: "synthetic", mode: .perSignature))
        XCTAssertTrue(BatchAuthenticationPolicy.explanation(formats: [.cades, .pades], serial: "x", mode: .automatic).contains("PIN per ogni firma"))
        XCTAssertTrue(BatchAuthenticationPolicy.explanation(formats: [.cades, .cades], serial: "x", mode: .automatic).contains("potrebbe"))
    }
    func testTemporaryModeIsExplicitOptInWithHonestDescriptionAndNoStoredCredential() throws {
        let name = "Signum.synthetic.temp-auth." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let preferences = SigningExperiencePreferences(defaults: defaults)
        XCTAssertEqual(preferences.authenticationMode, .automatic)
        preferences.authenticationMode = .temporaryPIN
        let frozenMode = preferences.authenticationMode // Approval takes a value, not a live preference reference.
        preferences.authenticationMode = .perSignature
        XCTAssertEqual(frozenMode, .temporaryPIN)
        XCTAssertEqual(preferences.authenticationMode, .perSignature)
        XCTAssertEqual(defaults.persistentDomain(forName: name)?.count, 1)
        XCTAssertEqual(Set(BatchAuthenticationMode.allCases).count, 3)
        XCTAssertTrue(BatchAuthenticationMode.temporaryPIN.explanation.contains("temporaneamente in memoria"))
        XCTAssertTrue(BatchAuthenticationMode.temporaryPIN.explanation.contains("aumenta"))
        XCTAssertTrue(BatchAuthenticationPolicy.explanation(formats: [.cades, .cades], serial: "x", mode: .temporaryPIN).contains("autenticazioni distinte"))
        XCTAssertTrue(BatchAuthenticationPolicy.explanation(formats: [.cades, .pades], serial: "x", mode: .temporaryPIN).contains("PIN per ogni firma"))
    }

}
#endif
