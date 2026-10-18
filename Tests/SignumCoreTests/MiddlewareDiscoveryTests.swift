#if os(macOS)
import XCTest
import Darwin
import COutputPermissions
@testable import SignumCore

final class MiddlewareDiscoveryTests: XCTestCase {
    var worker: IsolatedPKCS11Client { .init(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")) }
    func identity(_ inode: UInt64 = 1) -> MiddlewareFileIdentity {
        var value = stat(); value.st_ino = ino_t(inode); value.st_dev = 1; value.st_size = 100
        return .init(value)
    }
    func inspection(_ path: String, inode: UInt64 = 1) -> MiddlewareFileSecurity.Inspection { .init(canonicalPath: path, identity: identity(inode)) }
    func testInstalledAndMissingRegistryCombinations() {
        for installed in [Set<String>(), ["bit4id"], ["opensc"], ["bit4id", "opensc"]] {
            var loads = 0
            let rows = MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known,
                inspect: { path, automatic in
                    XCTAssertTrue(automatic)
                    let index = MiddlewareRegistry.known.firstIndex { $0.candidatePaths.contains(path) }!
                    guard installed.contains(MiddlewareRegistry.known[index].id) else { throw MiddlewareFileSecurity.Failure.missing }
                    return self.inspection(path, inode: UInt64(index + 1))
                }, scan: { path, _, _, _ in loads += 1; return .init(provider: path, tokens: [], unavailableSlots: 0) },
                certificates: { _, _, _, _, _ in XCTFail("No token"); return [] })
            XCTAssertEqual(loads, installed.count)
            XCTAssertEqual(rows.filter { $0.status == .noToken }.count, installed.count)
            XCTAssertEqual(rows.filter { $0.status == .missing }.count, 2 - installed.count)
        }
    }
    func testUntrustedFileAndAncestorNeverReachWorker() {
        for failure in [MiddlewareFileSecurity.Failure.unsafe, .changed] {
            let rows = MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known,
                inspect: { _, _ in throw failure }, scan: { _, _, _, _ in XCTFail("Unsafe load"); throw failure },
                certificates: { _, _, _, _, _ in XCTFail("Unsafe load"); return [] })
            XCTAssertEqual(rows.map(\.status), [.unsafe, .unsafe])
        }
    }
    func testAliasesDeduplicatedByInodeAndNotByName() {
        var loads = 0
        let rows = MiddlewareDiscovery().discover(registry: MiddlewareRegistry.known,
            inspect: { path, _ in self.inspection(path) }, scan: { path, _, _, _ in loads += 1; return .init(provider: path, tokens: [], unavailableSlots: 0) },
            certificates: { _, _, _, _, _ in [] })
        XCTAssertEqual(loads, 1); XCTAssertEqual(rows.map(\.status), [.noToken, .duplicate])
    }
    func testChangedPathAfterScanDiscardsAllTokenResults() {
        var reads = 0
        let rows = MiddlewareDiscovery().discover(registry: [MiddlewareRegistry.known[0]],
            inspect: { path, _ in reads += 1; return self.inspection(path, inode: UInt64(reads)) },
            scan: { path, _, _, _ in .init(provider: path, tokens: [self.token], unavailableSlots: 0) },
            certificates: { _, _, _, _, _ in [] })
        XCTAssertEqual(rows.first?.status, .unsafe); XCTAssertTrue(rows[0].tokens.isEmpty)
    }
    var token: SignumToken { .init(slot: 7, label: "Same label", manufacturer: "Synthetic", model: "Mock") }
    func testEmptyIsNotProofOfAbsentCertificateOrDevice() {
        let rows = MiddlewareDiscovery().discover(registry: [MiddlewareRegistry.known[0]],
            inspect: { path, _ in self.inspection(path) }, scan: { path, _, _, _ in .init(provider: path, tokens: [self.token], unavailableSlots: 0) },
            certificates: { _, _, _, _, _ in [] })
        XCTAssertEqual(rows[0].status, .ready); XCTAssertEqual(rows[0].tokens[0].certificateState, .empty)
        XCTAssertTrue(rows[0].tokens[0].message.contains("autenticazione"))
    }
    func testUnavailableSlotsAndPublicAuthenticationRequiredStayDistinct() {
        let rows = MiddlewareDiscovery().discover(registry: [MiddlewareRegistry.known[0]],
            inspect: { path, _ in self.inspection(path) }, scan: { path, _, _, _ in .init(provider: path, tokens: [self.token], unavailableSlots: 1) },
            certificates: { _, _, _, _, _ in throw IsolatedPKCS11Client.Failure.authenticationRequired })
        XCTAssertEqual(rows[0].status, .partial); XCTAssertEqual(rows[0].unavailableSlots, 1)
        XCTAssertEqual(rows[0].tokens[0].certificateState, .authenticationRequired)
    }
    func testCancellationAndDeadlineDoNotLoadProvider() {
        for cancel in [true, false] {
            let rows = MiddlewareDiscovery().discover(registry: [MiddlewareRegistry.known[0]], timeout: cancel ? 30 : 0, isCancelled: { cancel },
                inspect: { _, _ in XCTFail("No inspection"); throw MiddlewareFileSecurity.Failure.unsafe },
                scan: { _, _, _, _ in XCTFail("No load"); throw SupervisedProcess.Failure.timeout }, certificates: { _, _, _, _, _ in [] })
            XCTAssertEqual(rows[0].status, cancel ? .cancelled : .communicationError)
        }
    }
    func testForeignProviderIdentityRejected() {
        let rows = MiddlewareDiscovery().discover(registry: [MiddlewareRegistry.known[0]],
            inspect: { path, _ in self.inspection(path) }, scan: { _, _, _, _ in .init(provider: "/foreign/module", tokens: [self.token], unavailableSlots: 0) },
            certificates: { _, _, _, _, _ in XCTFail("Foreign provider"); return [] })
        XCTAssertEqual(rows[0].status, .communicationError); XCTAssertTrue(rows[0].tokens.isEmpty)
    }
    func testSyntheticWorkerSuccessFailureHangCrashAndAuthWithoutLogin() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        for (phase, effect, expected) in [(0, 0, MiddlewareDetectionStatus.ready), (0, 4, .communicationError), (0, 2, .communicationError), (0, 3, .communicationError), (11, 6, .partial)] {
            let mock = try MockModule(certificate: der, workerPhase: phase, workerEffect: effect, audit: true)
            let rows = MiddlewareDiscovery(client: worker).discover(registry: [], manualPaths: [mock.path.path], timeout: effect == 2 ? 0.25 : 5)
            XCTAssertEqual(rows.first?.status, expected, "\(phase)/\(effect)")
            if effect == 0 { XCTAssertEqual(rows[0].tokens.first?.certificates.first?.der, der) }
            if effect == 6 { XCTAssertEqual(rows[0].tokens.first?.certificateState, .authenticationRequired) }
            let audit = (try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? ""
            XCTAssertFalse(audit.split(separator: "\n").contains("8")); XCTAssertFalse(audit.split(separator: "\n").contains("9"))
            XCTAssertFalse(audit.split(separator: "\n").contains("16"))
        }
    }
    func testWorkerRejectsChangedIdentityBeforeInitializationAndAutoUserOwnedCode() throws {
        let mock = try MockModule(audit: true), worker = worker
        let current = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        XCTAssertThrowsError(try worker.scan(provider: current.canonicalPath, expectedModule: identity(999)))
        XCTAssertThrowsError(try worker.scan(provider: current.canonicalPath, expectedModule: current.identity, automatic: true))
        XCTAssertFalse(FileManager.default.fileExists(atPath: mock.folder.appendingPathComponent("operations").path))
    }
    func testActualManualSymlinkCanonicalizedAndAutomaticUserFileRefused() throws {
        let mock = try MockModule()
        let alias = mock.folder.appendingPathComponent("alias.dylib")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: mock.path)
        let original = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let resolved = try MiddlewareFileSecurity.inspect(alias.path, automatic: false)
        XCTAssertEqual(original.identity, resolved.identity); XCTAssertEqual(original.canonicalPath, resolved.canonicalPath)
        XCTAssertThrowsError(try MiddlewareFileSecurity.inspect(alias.path, automatic: true))
        XCTAssertThrowsError(try MiddlewareFileSecurity.inspect(mock.folder.path, automatic: false))
    }
    func testActualExtendedWriteACLIsUnsafeWithoutChangingPOSIXMode() throws {
        let mock = try MockModule()
        XCTAssertEqual(sg_discovery_acl_safe(mock.path.path), 1)
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "user:\(NSUserName()) allow write", mock.path.path]
        try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertEqual(sg_discovery_acl_safe(mock.path.path), 0)
        XCTAssertFalse(try MiddlewareFileSecurity.node(mock.path.path).aclSafe)
    }
    func testProtectedSymlinksAndAncestorRulesOnSyntheticFilesystem() throws {
        typealias Node = MiddlewareFileSecurity.Node
        func node(_ kind: UInt16, owner: UInt32 = 0, permissions: UInt16 = 0o755, acl: Bool = true, inode: UInt64 = 1) -> Node {
            .init(identity: identity(inode), owner: owner, mode: kind | permissions, aclSafe: acl)
        }
        let directory = node(UInt16(S_IFDIR)), file = node(UInt16(S_IFREG)), link = node(UInt16(S_IFLNK), permissions: 0o777)
        var fs = ["/": directory, "/Library": directory, "/Library/Vendor": directory,
                  "/Library/Vendor/module": link, "/Library/Vendor/real": file]
        let resolve: (String) -> String = { $0 == "/Library/Vendor/module" ? "/Library/Vendor/real" : $0 }
        let read: (String) throws -> Node = { guard let node = fs[$0] else { throw MiddlewareFileSecurity.Failure.missing }; return node }
        XCTAssertEqual(try MiddlewareFileSecurity.inspect("/Library/Vendor/module", automatic: true, resolve: resolve, read: read).canonicalPath, "/Library/Vendor/real")
        for unsafe in [node(UInt16(S_IFDIR), owner: 501), node(UInt16(S_IFDIR), permissions: 0o775), node(UInt16(S_IFDIR), acl: false)] {
            fs["/Library/Vendor"] = unsafe
            XCTAssertThrowsError(try MiddlewareFileSecurity.inspect("/Library/Vendor/module", automatic: true, resolve: resolve, read: read))
        }
        fs["/Library/Vendor"] = directory
        fs["/Library/Vendor/real"] = node(UInt16(S_IFREG), owner: 501)
        XCTAssertThrowsError(try MiddlewareFileSecurity.inspect("/Library/Vendor/module", automatic: true, resolve: resolve, read: read))
        fs["/Library/Vendor/real"] = file; fs["/Library/Vendor/module"] = node(UInt16(S_IFLNK), owner: 501)
        XCTAssertThrowsError(try MiddlewareFileSecurity.inspect("/Library/Vendor/module", automatic: true, resolve: resolve, read: read))
    }
}
#endif
