#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class PINChangeQualificationTests: XCTestCase {
    private func fixture(_ body: ([String: URL], URL) throws -> Void) throws {
        let root = try FixtureFiles.directory("pin-change-evidence")
        defer { try? FileManager.default.removeItem(at: root) }
        var files: [String: URL] = [:]
        for name in ["module", "configuration", "dependency:libopensc"] {
            let file = root.appendingPathComponent(name.replacingOccurrences(of: ":", with: "-"))
            XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data("synthetic-public-\(name)".utf8), attributes: [.posixPermissions: 0o600]))
            files[name] = file
        }
        try body(files, root)
    }
    private func binding(_ files: [String: URL], generation: UUID = UUID(), profile: String = "synthetic-rev-1", domain: String = "synthetic-user", applications: [String] = ["A00001"], serial: String = "SYNTHETIC") throws -> PINChangeBinding {
        try .init(profileRevision: profile, driverID: "synthetic", applicationIDs: applications, authenticationID: "01", pinDomain: domain,
                  token: .init(slot: 7, label: "Synthetic", manufacturer: "Offline", model: "Fixture", reader: "Synthetic reader", serial: serial),
                  discoveryID: generation, evidenceFiles: files)
    }
    func testPersistentLocationIsStableAcrossSessionsAndRecoveryNeverExecutes() throws {
        try fixture { _, root in
            let first = try PINChangeJournalLocation.prepare(in: root)
            let second = try PINChangeJournalLocation.prepare(in: root)
            XCTAssertEqual(first.root, second.root)
            XCTAssertEqual(first.root.lastPathComponent, "Signum-DeviceAdministration-v1")
            XCTAssertEqual(first.recover(UUID()), 0)
            let attributes = try FileManager.default.attributesOfItem(atPath: first.root.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        }
    }
    func testPersistentLocationRejectsExistingUnsafeDirectoryWithoutRepair() throws {
        try fixture { _, root in
            let location = try PINChangeJournalLocation.prepare(in: root)
            XCTAssertEqual(chmod(location.root.path, 0o755), 0)
            XCTAssertThrowsError(try PINChangeJournalLocation.prepare(in: root))
            let attributes = try FileManager.default.attributesOfItem(atPath: location.root.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o755)
        }
    }
    func testNoEvidenceEnablesTheRealBackend() throws {
        XCTAssertFalse(PINChangeQualification.realBackendEnabled)
        XCTAssertFalse(PINManagementProfile.unqualified.permitsRealMutation)
        XCTAssertEqual(PINChangeQualification.blockers.count, 4)
    }
    func testBindingRoundTripContainsOnlyPublicEvidence() throws {
        try fixture { files, _ in
            let b = try binding(files); let bytes = try JSONEncoder().encode(b)
            XCTAssertEqual(try JSONDecoder().decode(PINChangeBinding.self, from: bytes), b)
            let keys = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            XCTAssertFalse(keys.keys.contains("pin")); XCTAssertFalse(keys.keys.contains("certificate")); XCTAssertFalse(keys.keys.contains("routeID"))
            XCTAssertEqual(b.fingerprint.count, 64); try b.requireCurrentEvidence()
        }
    }
    func testNewGenerationInvalidatesConsentBindingButNotUncertainJournalScope() throws {
        try fixture { files, _ in
            let first = try binding(files), second = try binding(files)
            XCTAssertNotEqual(first.fingerprint, second.fingerprint)
            XCTAssertEqual(first.journalDomain, second.journalDomain)
        }
    }
    func testProfileDomainAndApplicationChangeCannotBypassAnUncertainDevice() throws {
        try fixture { files, _ in
            let first = try binding(files)
            for second in [try binding(files, profile: "synthetic-rev-2"), try binding(files, domain: "other-domain"), try binding(files, applications: ["A00002"])] {
                XCTAssertNotEqual(first.fingerprint, second.fingerprint); XCTAssertEqual(first.journalDomain, second.journalDomain)
            }
            XCTAssertNotEqual(first.journalDomain, try binding(files, serial: "REPLACED").journalDomain)
        }
    }
    func testConfigurationAndDependencyContentAreBound() throws {
        try fixture { files, _ in
            let generation = UUID(); let first = try binding(files, generation: generation)
            for key in ["configuration", "dependency:libopensc", "module"] {
                try Data("changed-public-evidence".utf8).write(to: XCTUnwrap(files[key]))
                XCTAssertThrowsError(try first.requireCurrentEvidence())
                let second = try binding(files, generation: generation)
                XCTAssertNotEqual(first.fingerprint, second.fingerprint)
                XCTAssertEqual(first.journalDomain, second.journalDomain)
            }
        }
    }
    func testReplacingInodeWithSameBytesInvalidatesBinding() throws {
        try fixture { files, root in
            let first = try binding(files); let file = try XCTUnwrap(files["module"])
            try FileManager.default.moveItem(at: file, to: root.appendingPathComponent("old-module"))
            XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data("synthetic-public-module".utf8), attributes: [.posixPermissions: 0o600]))
            XCTAssertThrowsError(try first.requireCurrentEvidence())
        }
    }
    func testMissingEvidenceAmbiguousIdentifiersAndAbsentSerialAreRejected() throws {
        try fixture { files, _ in
            var missing = files; missing.removeValue(forKey: "configuration"); XCTAssertThrowsError(try binding(missing))
            XCTAssertThrowsError(try binding(files, applications: ["a00001"]))
            XCTAssertThrowsError(try binding(files, applications: ["A00001", "A00001"]))
            XCTAssertThrowsError(try binding(files, serial: ""))
        }
    }
    func testDecodedIncompleteEvidenceCannotProduceAnAuthorizationBinding() throws {
        try fixture { files, _ in
            let first = try binding(files)
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(first)) as? [String: Any])
            object["files"] = [String: String]()
            let forged = try JSONDecoder().decode(PINChangeBinding.self, from: JSONSerialization.data(withJSONObject: object))
            XCTAssertEqual(forged.fingerprint, ""); XCTAssertEqual(forged.journalDomain, "")
            XCTAssertThrowsError(try forged.requireCurrentEvidence())
            XCTAssertThrowsError(try binding(files, serial: "  "))
        }
    }
    func testSymlinkHardlinkAndWritableEvidenceAreRejected() throws {
        try fixture { files, root in
            let file = try XCTUnwrap(files["module"]), alias = root.appendingPathComponent("alias")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: file)
            XCTAssertThrowsError(try PINChangeFileEvidence.capture(alias))
            try FileManager.default.removeItem(at: alias)
            try FileManager.default.linkItem(at: file, to: alias)
            XCTAssertThrowsError(try PINChangeFileEvidence.capture(file))
            try FileManager.default.removeItem(at: alias)
            XCTAssertEqual(chmod(file.path, 0o666), 0)
            XCTAssertThrowsError(try PINChangeFileEvidence.capture(file))
        }
    }
}
#endif
