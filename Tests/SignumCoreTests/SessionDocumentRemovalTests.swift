#if os(macOS)
import XCTest
import SwiftUI
@testable import SignumApp
@testable import SignumCore

@MainActor final class SessionDocumentRemovalTests: XCTestCase {
    private let verifier: VerificationWorkspace.Verifier = { url, _ in
        .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .unknown,
              signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: Data(url.lastPathComponent.utf8))
    }
    func testVerificationRemovalPreservesOtherReportsAndSelectsNeighbourUntilEmpty() async throws {
        let root = try FixtureFiles.directory("removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let files = try (0..<3).map { i -> URL in
            let url = root.appendingPathComponent("input-\(i).txt")
            try Data("Original \(i)".utf8).write(to: url); return url
        }
        let exported = root.appendingPathComponent("exported.txt")
        try Data("Export preserved".utf8).write(to: exported)
        let workspace = VerificationWorkspace()
        await workspace.verify(files, using: verifier)
        let rows = workspace.rows
        workspace.selectedDocument = rows[1].id
        XCTAssertTrue(workspace.remove(rows[0].id))
        XCTAssertEqual(workspace.selectedDocument, rows[1].id)
        XCTAssertEqual(workspace.rows[1].report?.id, rows[2].report?.id)
        XCTAssertEqual(workspace.rows[1].report?.originalContent, rows[2].report?.originalContent)
        XCTAssertTrue(workspace.remove(rows[1].id))
        XCTAssertEqual(workspace.selectedDocument, rows[2].id)
        XCTAssertTrue(workspace.remove(rows[2].id))
        XCTAssertTrue(workspace.rows.isEmpty); XCTAssertNil(workspace.selectedDocument)
        XCTAssertFalse(workspace.remove(rows[0].id))
        for (i, file) in files.enumerated() { XCTAssertEqual(try Data(contentsOf: file), Data("Original \(i)".utf8)) }
        XCTAssertEqual(try Data(contentsOf: exported), Data("Export preserved".utf8))
        await workspace.verify(files, using: verifier)
        XCTAssertEqual(workspace.selectedDocument, workspace.rows.first?.id)
    }
    func testRemovalBlockedDuringVerificationAndAcquisition() async throws {
        let workspace = VerificationWorkspace(), entered = expectation(description: "verifier entered")
        let release = DispatchSemaphore(value: 0)
        let task = workspace.start([URL(fileURLWithPath: "/synthetic/input")]) { url, _ in
            entered.fulfill(); _ = release.wait(timeout: .now() + 3)
            return .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .unknown, signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: nil)
        }
        await fulfillment(of: [entered], timeout: 2)
        let id = try XCTUnwrap(workspace.rows.first?.id)
        XCTAssertFalse(workspace.remove(id)); XCTAssertEqual(workspace.rows.count, 1)
        release.signal(); await task.value
        XCTAssertTrue(workspace.remove(id))
        let ready = expectation(description: "acquiring"), drop = ControlledDrop(1, ready: ready)
        let acquisition = workspace.acquire(using: { await drop.resolve() }, verifier: verifier)
        await fulfillment(of: [ready], timeout: 2)
        XCTAssertFalse(workspace.remove(UUID())); XCTAssertTrue(workspace.acquiring)
        drop.send(0, "new"); await acquisition.value
        XCTAssertEqual(workspace.rows.count, 1)
    }
    func testDetachedReportRetainsOriginalAssociationWhenAnotherRowIsRemoved() async throws {
        let workspace = VerificationWorkspace()
        let original = Data("detached verified original".utf8)
        await workspace.verify([URL(fileURLWithPath: "/synthetic/first"), URL(fileURLWithPath: "/synthetic/signature.p7s")]) { url, _ in
            .init(id: UUID(), documentName: url.lastPathComponent, sha256: "synthetic", format: .cades, signatures: [], documentState: "unsigned", issue: "", previewPDF: nil, originalContent: original)
        }
        let detached = workspace.rows[1]
        workspace.selectedDocument = detached.id
        XCTAssertTrue(workspace.remove(workspace.rows[0].id))
        XCTAssertEqual(workspace.rows[0].id, detached.id)
        XCTAssertEqual(workspace.rows[0].report?.id, detached.report?.id)
        XCTAssertEqual(workspace.rows[0].report?.originalContent, original)
    }
    func testSigningRemovalRetiresSnapshotAndRejectsStaleApprovalWithoutDeletingFiles() async throws {
        let root = try FixtureFiles.directory("signing-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        let files = try (0..<3).map { i -> URL in
            let url = root.appendingPathComponent("input-\(i).txt")
            try Data("Original \(i)".utf8).write(to: url); return url
        }
        let output = root.appendingPathComponent("existing-signed.p7m")
        try Data("Keep output".utf8).write(to: output)
        await batch.addDocuments(files, format: .cades)
        let certificate = SignumCertificate(label: "Synthetic", identifier: Data([1]))
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7, certificate: certificate, der: der, destination: .originalFolders)
        let first = batch.documents[0].snapshot
        batch.remove(first.identity.id)
        XCTAssertTrue(first.isRetired); XCTAssertNil(batch.review)
        XCTAssertThrowsError(try batch.freezeReview(plan))
        XCTAssertFalse(batch.isApproved)
        for id in batch.documents.map(\.id) { batch.remove(id) }
        XCTAssertTrue(batch.documents.isEmpty)
        for (i, file) in files.enumerated() { XCTAssertEqual(try Data(contentsOf: file), Data("Original \(i)".utf8)) }
        XCTAssertEqual(try Data(contentsOf: output), Data("Keep output".utf8))
    }
    func testFrozenApprovalBlocksRemovalUntilExplicitlyDeclined() async throws {
        let root = try FixtureFiles.directory("frozen-removal")
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("input.txt"); try Data("input".utf8).write(to: file)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments([file], format: .cades)
        let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: CertificateEligibilityTests.fixtures.get().der("valid"), destination: .originalFolders)
        try batch.freezeReview(plan)
        let id = batch.documents[0].id
        batch.remove(id); XCTAssertEqual(batch.documents.count, 1)
        batch.declineApproval(); batch.remove(id); XCTAssertTrue(batch.documents.isEmpty)
    }
}
#endif
