#if os(macOS)
import XCTest
import Darwin
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

@MainActor final class BatchDestinationTests: XCTestCase {
    private func fixture(_ body: (URL, [URL], BatchSigningCoordinator, Data) async throws -> Void) async throws {
        let requested = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: requested, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let resolved = try XCTUnwrap(realpath(requested.path, nil)); defer { free(resolved) }
        let root = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let files = try ["one", "two", "three"].map { name -> URL in
            let folder = root.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let file = folder.appendingPathComponent("Relazione.pdf")
            try Data("Synthetic approved \(name)".utf8).write(to: file); return file
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        try await body(root, files, batch, CertificateEligibilityTests.fixtures.get().der("valid"))
    }
    private func plan(_ batch: BatchSigningCoordinator, der: Data, destination: BatchOutputDestination = .originalFolders) async throws -> BatchApproval {
        try await batch.prepareApproval(provider: "/synthetic/provider", slot: 7, certificate: .init(label: "Synthetic", identifier: Data([1])), der: der, destination: destination)
    }
    func testSingleDefaultsToOriginalFolderWithoutCreatingOutputBeforeConsent() async throws {
        try await fixture { _, paths, batch, der in
            await batch.addDocuments([paths[0]], format: .cades)
            let before = try FileManager.default.contentsOfDirectory(atPath: paths[0].deletingLastPathComponent().path)
            let approval = try await plan(batch, der: der)
            XCTAssertEqual(approval.jobs[0].destination, paths[0].appendingPathExtension("p7m"))
            XCTAssertFalse(batch.isApproved)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: paths[0].deletingLastPathComponent().path), before)
            do { try await batch.authorizeNext(pin: "synthetic") { _, _, _ in XCTFail("Private request before approval") }; XCTFail("Approval required") } catch {}
            batch.declineApproval(); XCTAssertFalse(batch.isFrozen); XCTAssertNil(batch.approval)
            XCTAssertTrue(batch.documents.allSatisfy { $0.destination == nil })
        }
    }
    func testDifferentOriginalFoldersKeepEqualNamesSeparate() async throws {
        try await fixture { _, paths, batch, der in
            await batch.addDocuments(paths, format: .cades)
            let approval = try await plan(batch, der: der)
            XCTAssertEqual(approval.jobs.map(\.destination), paths.map { $0.appendingPathExtension("p7m") })
            XCTAssertEqual(Set(approval.jobs.map { $0.destination.lastPathComponent }), ["Relazione.pdf.p7m"])
            for (index, file) in paths.enumerated() { XCTAssertEqual(try Data(contentsOf: file), Data("Synthetic approved \(["one", "two", "three"][index])".utf8)) }
        }
    }
    func testCommonFolderReservesCollisionFreeNamesBeforeConsentIncludingSymlinks() async throws {
        try await fixture { root, paths, batch, der in
            let output = root.appendingPathComponent("output")
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
            let preserved = output.appendingPathComponent("Relazione.pdf.p7m")
            try Data("PRESERVE".utf8).write(to: preserved)
            let alias = output.appendingPathComponent("Relazione (2).pdf.p7m")
            try FileManager.default.createSymbolicLink(atPath: alias.path, withDestinationPath: output.appendingPathComponent("missing").path)
            await batch.addDocuments(paths, format: .cades)
            let approval = try await plan(batch, der: der, destination: .commonDirectory(output))
            XCTAssertEqual(approval.jobs.map { $0.destination.lastPathComponent }, ["Relazione (3).pdf.p7m", "Relazione (4).pdf.p7m", "Relazione (5).pdf.p7m"])
            XCTAssertTrue(approval.jobs.allSatisfy { $0.destination.deletingLastPathComponent().path == output.path })
            XCTAssertEqual(try String(contentsOf: preserved), "PRESERVE")
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: alias.path), output.appendingPathComponent("missing").path)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: output.path).count, 2)
        }
    }
    func testPAdESPreservesExistingHyphenatedNameInOriginalFolder() async throws {
        try await fixture { _, paths, batch, der in
            let bytes = NSMutableData(); let sink = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
            var box = CGRect(x: 0, y: 0, width: 300, height: 400)
            let context = try XCTUnwrap(CGContext(consumer: sink, mediaBox: &box, nil))
            context.beginPDFPage(nil); context.endPDFPage(); context.closePDF()
            try (bytes as Data).write(to: paths[0])
            await batch.addDocuments([paths[0]], format: .pades)
            let approval = try await plan(batch, der: der)
            XCTAssertEqual(approval.jobs[0].destination.lastPathComponent, "Relazione-firmato.pdf")
            XCTAssertEqual(approval.jobs[0].destination.deletingLastPathComponent(), paths[0].deletingLastPathComponent())
            XCTAssertEqual(try Data(contentsOf: paths[0]), bytes as Data)
        }
    }
    func testMissingInvalidAndReadOnlyDirectoriesFailBeforeApproval() async throws {
        try await fixture { root, paths, batch, der in
            await batch.addDocuments([paths[0]], format: .cades)
            let readOnly = root.appendingPathComponent("read-only")
            try FileManager.default.createDirectory(at: readOnly, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(readOnly.path, 0o500), 0); defer { chmod(readOnly.path, 0o700) }
            for destination in [root.appendingPathComponent("missing"), paths[1], readOnly] {
                do { _ = try await plan(batch, der: der, destination: .commonDirectory(destination)); XCTFail("Invalid directory accepted") } catch {}
                XCTAssertFalse(batch.isFrozen); XCTAssertFalse(batch.isApproved); XCTAssertNil(batch.approval)
            }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: readOnly.path).isEmpty)
        }
    }
    func testDirectoryACLWriteDenialFailsWithoutProbeFiles() async throws {
        try await fixture { root, paths, batch, der in
            let output = root.appendingPathComponent("acl-output")
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
            let chmod = Process(); chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+a", "user:\(NSUserName()) deny add_file,add_subdirectory", output.path]
            try chmod.run(); chmod.waitUntilExit(); XCTAssertEqual(chmod.terminationStatus, 0)
            defer {
                let cleanup = Process(); cleanup.executableURL = URL(fileURLWithPath: "/bin/chmod"); cleanup.arguments = ["-N", output.path]
                try? cleanup.run(); cleanup.waitUntilExit()
            }
            await batch.addDocuments([paths[0]], format: .cades)
            do { _ = try await plan(batch, der: der, destination: .commonDirectory(output)); XCTFail("Denied ACL accepted") } catch {}
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty)
            XCTAssertFalse(batch.isApproved)
        }
    }
    func testLateCollisionDoesNotAuthenticateRenameOrOverwriteAndNeedsNewConsent() async throws {
        try await fixture { _, paths, batch, der in
            await batch.addDocuments([paths[0]], format: .cades)
            let approval = try await plan(batch, der: der); try batch.confirm(approval)
            let destination = approval.jobs[0].destination
            try Data("CONCURRENT".utf8).write(to: destination)
            try await batch.authorizeNext(pin: "synthetic") { _, _, _ in XCTFail("Collision must reject before authentication") }
            XCTAssertEqual(batch.documents[0].state, .failed)
            XCTAssertEqual(batch.approval?.jobs[0].destination, destination)
            XCTAssertEqual(try String(contentsOf: destination), "CONCURRENT")
            XCTAssertTrue(batch.documents[0].result.contains("nuova sessione"))
            batch.reset(); await batch.addDocuments([paths[0]], format: .cades)
            let second = try await plan(batch, der: der)
            XCTAssertEqual(second.jobs[0].destination.lastPathComponent, "Relazione (2).pdf.p7m")
            XCTAssertNotEqual(second.id, approval.id); XCTAssertFalse(batch.isApproved)
        }
    }
    func testDirectoryReplacementAfterConsentNeverRetargetsTheApprovedJob() async throws {
        try await fixture { root, paths, batch, der in
            let output = root.appendingPathComponent("output"), renamed = root.appendingPathComponent("renamed")
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
            await batch.addDocuments([paths[0]], format: .cades)
            let approval = try await plan(batch, der: der, destination: .commonDirectory(output)); try batch.confirm(approval)
            try FileManager.default.moveItem(at: output, to: renamed)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
            try await batch.authorizeNext(pin: "synthetic") { _, _, _ in XCTFail("Replaced directory must reject before authentication") }
            XCTAssertEqual(batch.documents[0].state, .failed)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: renamed.path).isEmpty)
        }
    }
    func testDestinationPreferenceDefaultsAndMissingSelectionAreExplicit() throws {
        let name = "Signum.synthetic.destinations." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name)); defer { defaults.removePersistentDomain(forName: name) }
        let store = SigningExperiencePreferences(defaults: defaults)
        XCTAssertTrue(store.alongsideOriginal); XCTAssertNil(store.customDirectory)
        XCTAssertEqual(SigningDestinationSelection().policy, .originalFolders)
        XCTAssertNil(SigningDestinationSelection(alongsideOriginal: false).policy)
        store.alongsideOriginal = false; store.customDirectory = URL(fileURLWithPath: "/synthetic/missing")
        let restored = SigningExperiencePreferences(defaults: defaults)
        XCTAssertFalse(restored.alongsideOriginal); XCTAssertEqual(restored.customDirectory?.path, "/synthetic/missing")
        store.customDirectory = URL(string: "https://example.invalid/output")
        XCTAssertNil(store.customDirectory)
    }
    func testPreferenceEditsAndNewDocumentsCannotMutateApprovedOutputs() async throws {
        try await fixture { root, paths, batch, der in
            await batch.addDocuments([paths[0]], format: .cades)
            let approval = try await plan(batch, der: der, destination: .commonDirectory(root)); try batch.confirm(approval)
            var settings = SigningDestinationSelection(alongsideOriginal: false, customDirectory: root)
            settings.alongsideOriginal = true; settings.customDirectory = paths[1].deletingLastPathComponent()
            await batch.addDocuments([paths[1]], format: .cades)
            XCTAssertEqual(batch.documents.count, 1)
            XCTAssertEqual(batch.approval?.jobs.map(\.id), approval.jobs.map(\.id))
            XCTAssertEqual(batch.approval?.jobs.map(\.destination), approval.jobs.map(\.destination))
        }
    }
    func testDefaultSameFolderCAdESBatchPublishesVerifiedCopiesAndPreservesSources() async throws {
        try await fixture { root, _, batch, _ in
            let signer = try SoftwareSigner(folder: root)
            let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER())
            let sources = try ["a.txt", "b.txt", "c.txt"].enumerated().map { i, name -> URL in
                let file = root.appendingPathComponent(name); try Data("Synthetic \(i)".utf8).write(to: file); return file
            }
            await batch.addDocuments(sources, format: .cades)
            let approval = try await batch.prepareApproval(provider: mock.path.path, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
            try batch.confirm(approval)
            let worker = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
            for index in 0..<3 {
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: .init(executable: worker), pin: pin, operation: operation)
                }
                XCTAssertEqual(batch.documents[index].state, .completed)
                XCTAssertEqual(approval.jobs[index].destination, sources[index].appendingPathExtension("p7m"))
                let bytes = try await Task.detached { try CAdESVerifier.verify(file: approval.jobs[index].destination).originalDocument }.value
                XCTAssertEqual(bytes, try Data(contentsOf: sources[index]))
            }
        }
    }
}
#endif
