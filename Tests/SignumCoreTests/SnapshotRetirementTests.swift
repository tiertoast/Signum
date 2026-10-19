#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

@MainActor final class SnapshotRetirementTests: XCTestCase {
    private func fixture() throws -> (URL, DocumentSnapshot) {
        let root = try FixtureFiles.directory("retirement")
        let source = root.appendingPathComponent("document.bin")
        try Data(repeating: 65, count: 1_000_000).write(to: source)
        return (root, try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: root))
    }
    func testCloseInvalidatesWhileReadLeaseKeepsFilesAlive() async throws {
        let (root, snapshot) = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let entered = expectation(description: "reader holds descriptor"), release = DispatchSemaphore(value: 0)
        let reader = Task.detached { Result { try snapshot.verifiedBytes(reading: {
            entered.fulfill(); XCTAssertEqual(release.wait(timeout: .now()+5), .success)
        }) } }
        await fulfillment(of: [entered], timeout: 5)
        let start = ProcessInfo.processInfo.systemUptime
        snapshot.close(); snapshot.close()
        let elapsed = ProcessInfo.processInfo.systemUptime-start
        XCTAssertTrue(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
        XCTAssertThrowsError(try snapshot.verifiedBytes())
        release.signal()
        let result = await reader.value
        XCTAssertThrowsError(try result.get())
        XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
        print("CQ08 logical-close seconds=\(elapsed) blocked-reader=true")
    }
    func testRemoveAndResetInvalidateImmediatelyDuringRead() async throws {
        for reset in [false, true] {
            let (root, snapshot) = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
            let batch = BatchSigningCoordinator(capture: { _, _, _ in snapshot })
            await batch.addDocuments([snapshot.originalURL], format: .cades)
            let entered = expectation(description: "read"), release = DispatchSemaphore(value: 0)
            let reader = Task.detached { Result { try snapshot.verifiedBytes(reading: {
                entered.fulfill(); XCTAssertEqual(release.wait(timeout: .now()+5), .success)
            }) } }
            await fulfillment(of: [entered], timeout: 5)
            let old = batch.revision
            if reset { batch.reset() } else { batch.remove(snapshot.identity.id) }
            XCTAssertTrue(batch.documents.isEmpty); XCTAssertNotEqual(batch.revision, old)
            XCTAssertTrue(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
            XCTAssertThrowsError(try snapshot.verifiedBytes())
            release.signal(); _ = await reader.value
            XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
        }
    }
    func testQueuedReadersCannotReopenAfterRetirement() async throws {
        let (root, snapshot) = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let entered = expectation(description: "read"), release = DispatchSemaphore(value: 0)
        let first = Task.detached { Result { try snapshot.verifiedBytes(reading: {
            entered.fulfill(); XCTAssertEqual(release.wait(timeout: .now()+5), .success)
        }) } }
        await fulfillment(of: [entered], timeout: 5)
        let next = Task.detached { Result { try snapshot.verifiedBytes() } }
        snapshot.retire(); release.signal()
        let a = await first.value, b = await next.value
        XCTAssertThrowsError(try a.get()); XCTAssertThrowsError(try b.get())
        snapshot.close()
    }
    func testCancellationDuringReadAndIntegrityStillChecked() throws {
        let (root, snapshot) = try fixture(); defer { snapshot.close(); try? FileManager.default.removeItem(at: root) }
        var cancelled = false
        XCTAssertThrowsError(try snapshot.verifiedBytes(isCancelled: { cancelled }, reading: { cancelled = true }))
        XCTAssertEqual(try snapshot.verifiedBytes(), snapshot.approvedBytes)
        XCTAssertEqual(chmod(snapshot.fileURL.path, 0o600), 0)
        try Data(repeating: 66, count: snapshot.identity.byteCount).write(to: snapshot.fileURL)
        XCTAssertThrowsError(try snapshot.verifiedBytes())
    }
    func testFailedUnlinkIsRecoverableAndNeverRemovesOriginal() throws {
        let (root, snapshot) = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertEqual(chflags(snapshot.fileURL.path, UInt32(UF_IMMUTABLE)), 0)
        snapshot.close()
        XCTAssertTrue(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
        XCTAssertThrowsError(try snapshot.verifiedBytes())
        XCTAssertEqual(chflags(snapshot.fileURL.path, 0), 0)
        let next = try DocumentSnapshot.capture(source: snapshot.originalURL, format: .cades, privateRoot: root)
        next.close()
        XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
        XCTAssertEqual(try Data(contentsOf: snapshot.originalURL), snapshot.approvedBytes)
    }
}
#endif
