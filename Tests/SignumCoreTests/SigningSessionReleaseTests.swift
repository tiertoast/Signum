#if os(macOS)
import XCTest
import SwiftUI
@testable import SignumApp
@testable import SignumCore

@MainActor final class SigningSessionReleaseTests: XCTestCase {
    func fixture(_ body: (BatchSigningCoordinator, SoftwareSigner, MockModule, [URL]) async throws -> Void) async throws {
        let root = try FixtureFiles.directory("session-release")
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        let files = try (0..<3).map { i -> URL in
            let url = root.appendingPathComponent("input-\(i).txt"); try Data("File \(i)".utf8).write(to: url); return url
        }
        await batch.addDocuments(files, format: .cades)
        let plan = try await batch.prepareApproval(provider: mock.path.path, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der)
        try batch.confirm(plan)
        try await body(batch, signer, mock, files)
    }
    func testCompletedBatchReleasesOnlyAfterLastPublicationAndKeepsAllOutputs() async throws {
        try await fixture { batch, _, _, files in
            let store = SigningSessionResults()
            let jobs = try XCTUnwrap(batch.approval).jobs
            let client = IsolatedPKCS11Client(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
            for i in 0..<3 {
                try await batch.authorizeNext(pin: "synthetic") { job, pin, operation in try job.signCAdES(using: client, pin: pin, operation: operation) }
                if i < 2 { XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false)) }
            }
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: true, hasAuthenticationContext: false))
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: true))
            XCTAssertTrue(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertFalse(batch.isFrozen); XCTAssertFalse(batch.isApproved); XCTAssertNil(batch.approval)
            XCTAssertEqual(store.receipts.map(\.state), [.completed, .completed, .completed])
            for (i, job) in jobs.enumerated() {
                XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, try Data(contentsOf: files[i]))
                XCTAssertEqual(store.receipts[i].output, job.destination)
            }
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            await batch.addDocuments([files[0]], format: .cades)
            XCTAssertEqual(batch.documents.count, 1); XCTAssertEqual(store.receipts.count, 3)
        }
    }
    func testWindowAutomaticallyReleasesTerminalSessionWithoutNewSessionButton() async throws {
        try await fixture { batch, _, _, _ in
            let store = SigningSessionResults()
            let host = NSHostingView(rootView: SignumWindow(batch: batch, automaticallyDiscover: false, sessionResults: store))
            let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 1200, height: 800), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = host; window.orderFront(nil)
            defer { window.close() }
            batch.cancelPending()
            let deadline = Date().addingTimeInterval(5)
            while store.receipts.count != 3 && Date() < deadline { try await Task.sleep(nanoseconds: 10_000_000); host.layoutSubtreeIfNeeded() }
            XCTAssertEqual(store.receipts.count, 3)
            XCTAssertFalse(batch.isFrozen); XCTAssertNil(batch.approval)
            XCTAssertTrue(batch.documents.isEmpty)
            var selection = DeviceSelection(), refresh = DeviceRefreshLifecycle()
            XCTAssertNotNil(refresh.begin(selection: &selection, blocked: batch.isFrozen || batch.isRunning))
        }
    }

    func testLiveOperationCannotReleaseEvenIfQueuedDocumentsAreCancelled() async throws {
        try await fixture { batch, _, _, _ in
            let store = SigningSessionResults(), entered = FixtureLocked(false)
            let gate = DispatchSemaphore(value: 0)
            defer { gate.signal() }
            let task = Task { @MainActor in
                try await batch.authorizeNext(pin: "synthetic") { _, _, _ in
                    entered.withValue { $0 = true }
                    _ = gate.wait(timeout: .now() + 5)
                    throw SignumError.module("Synthetic stopped operation")
                }
            }
            let deadline = Date().addingTimeInterval(3)
            while !entered.withValue({ $0 }) && Date() < deadline { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertTrue(entered.withValue { $0 }); XCTAssertTrue(batch.isRunning)
            batch.cancelPending()
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertNotNil(batch.approval); XCTAssertTrue(store.receipts.isEmpty)
            gate.signal(); try await task.value
            XCTAssertTrue(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertEqual(store.receipts.count, 3)
        }
    }

    func testCancelledApprovedBatchUnlocksWithoutLosingCancellation() async throws {
        try await fixture { batch, _, _, _ in
            let store = SigningSessionResults(); batch.cancelPending()
            XCTAssertTrue(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertEqual(store.receipts.map(\.state), [.cancelled, .cancelled, .cancelled])
            XCTAssertFalse(batch.isFrozen)
            XCTAssertTrue(store.receipts.allSatisfy { $0.output.map { !FileManager.default.fileExists(atPath: $0.path) } ?? true })
        }
    }
    func testUncertainResultMustBeAcknowledgedAndPendingDocumentsMustFinish() async throws {
        try await fixture { batch, _, _, _ in
            let store = SigningSessionResults()
            try await batch.authorizeNext(pin: "synthetic") { _, _, _ in }
            XCTAssertTrue(batch.needsOutcomeReview)
            batch.cancelPending()
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertTrue(batch.isApproved)
            batch.acknowledgeUncertainOutcome()
            XCTAssertTrue(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertEqual(store.receipts.first?.state, .uncertain)
            XCTAssertEqual(store.receipts.count, 3)
        }
    }
    func testErrorIsPreservedAndPendingJobsAreNeverReset() async throws {
        try await fixture { batch, _, _, _ in
            let store = SigningSessionResults()
            try await batch.authorizeNext(pin: "synthetic") { _, _, _ in throw SignumError.module("Synthetic retained error") }
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            batch.cancelPending()
            XCTAssertFalse(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false, otherWork: true))
            XCTAssertTrue(store.releaseIfFinished(batch, interactionBusy: false, hasAuthenticationContext: false))
            XCTAssertEqual(store.receipts.first?.state, .failed)
            XCTAssertTrue(store.receipts.first?.detail.contains("Synthetic retained error") == true)
        }
    }
}
#endif
