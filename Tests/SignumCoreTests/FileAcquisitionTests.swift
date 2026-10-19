#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class FileAcquisitionTests: XCTestCase {
    func fixture(_ body: (URL, URL, Data) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("synthetic.pdf")
        let bytes = Data("%PDF-1.4\nSynthetic acquisition fixture\n".utf8) + Data(repeating: 0x53, count: 160_000)
        try bytes.write(to: source)
        try body(root, source, bytes)
    }

    func testMetadataOnlyChangeDoesNotRejectCoherentPDF() throws {
        try fixture { root, source, bytes in
            var io = DocumentSnapshot.CaptureIO(), changed = false
            var sourceFD: Int32 = -1
            io.sourceOpened = { sourceFD = $0 }
            io.read = { fd, pointer, count in
                if !changed {
                    changed = true
                    var before = stat(), after = stat()
                    XCTAssertEqual(fstat(sourceFD, &before), 0)
                    let value: UInt8 = 1
                    XCTAssertEqual(withUnsafePointer(to: value) { fsetxattr(sourceFD, "org.signum.synthetic-test", $0, 1, 0, 0) }, 0)
                    XCTAssertEqual(fstat(sourceFD, &after), 0)
                    XCTAssertEqual(before.st_size, after.st_size)
                    XCTAssertEqual(before.st_mtimespec.tv_sec, after.st_mtimespec.tv_sec)
                    XCTAssertEqual(before.st_mtimespec.tv_nsec, after.st_mtimespec.tv_nsec)
                    XCTAssertTrue(before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec)
                }
                return Darwin.read(fd, pointer, count)
            }
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)
            defer { snapshot.close() }
            XCTAssertTrue(changed)
            XCTAssertEqual(snapshot.approvedBytes, bytes)
            XCTAssertEqual(try snapshot.verifiedBytes(), bytes)
            XCTAssertEqual(try Data(contentsOf: source), bytes)
        }
    }

    func testTransientWriteWithRestoredBytesAndMtimeIsStillRejected() throws {
        try fixture { root, source, bytes in
            var io = DocumentSnapshot.CaptureIO(), changed = false
            io.read = { fd, pointer, count in
                if !changed {
                    changed = true
                    let writer = Darwin.open(source.path, O_RDWR); defer { Darwin.close(writer) }
                    var info = stat(); XCTAssertEqual(fstat(writer, &info), 0)
                    var value: UInt8 = 0x58
                    XCTAssertEqual(pwrite(writer, &value, 1, 0), 1)
                    value = bytes[0]; XCTAssertEqual(pwrite(writer, &value, 1, 0), 1)
                    var times = [info.st_atimespec, info.st_mtimespec]
                    XCTAssertEqual(futimens(writer, &times), 0)
                }
                return Darwin.read(fd, pointer, count)
            }
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .changed)
            }
            XCTAssertEqual(try Data(contentsOf: source), bytes)
        }
    }

    func testTruncateRenameAndReplacementFailWithoutLeavingSnapshot() throws {
        for action in 0..<3 {
            try fixture { root, source, _ in
                var io = DocumentSnapshot.CaptureIO()
                io.sourceOpened = { _ in
                    if action == 0 {
                        let writer = Darwin.open(source.path, O_WRONLY); defer { Darwin.close(writer) }
                        XCTAssertEqual(ftruncate(writer, 10), 0)
                    } else {
                        try FileManager.default.moveItem(at: source, to: root.appendingPathComponent("moved.pdf"))
                        if action == 2 { try Data("replacement".utf8).write(to: source) }
                    }
                }
                XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)) {
                    XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .changed)
                }
                XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.hasPrefix(".signum-snapshot-") })
            }
        }
    }

    func testInterruptedReadRetriesOnlyEINTRButIOAndSpaceErrorsAreDistinct() throws {
        for action in 0..<4 {
            try fixture { root, source, bytes in
                var io = DocumentSnapshot.CaptureIO(), first = true
                if action == 1 { io.clone = { _, _, _ in errno = ENOSPC; return -1 } }
                if action != 1 {
                    io.read = { fd, pointer, count in
                        if first { first = false; errno = action == 0 ? EINTR : (action == 2 ? EIO : EACCES); return -1 }
                        return Darwin.read(fd, pointer, count)
                    }
                }
                if action == 0 {
                    let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)
                    XCTAssertEqual(try snapshot.verifiedBytes(), bytes); snapshot.close()
                } else {
                    XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)) {
                        let failure = $0 as? DocumentAcquisitionFailure
                        XCTAssertEqual(failure?.kind, action == 1 ? .space : .read)
                        XCTAssertFalse($0.localizedDescription.contains("modificato"))
                    }
                }
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["synthetic.pdf"])
            }
        }
    }

    func testUnavailablePermissionOversizeAndDeadlineAreDistinct() throws {
        try fixture { root, source, _ in
            XCTAssertEqual(chmod(source.path, 0), 0)
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root)) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .read)
            }
            XCTAssertEqual(chmod(source.path, 0o600), 0)
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, timeout: 0)) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .timeout)
            }
            var io = DocumentSnapshot.CaptureIO(), now: TimeInterval = 1
            io.clock = { now }; io.read = { fd, p, n in now = 40; return Darwin.read(fd, p, n) }
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .timeout)
            }
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, isCancelled: { true })) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .cancelled)
            }
            try FileManager.default.removeItem(at: source)
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root)) {
                XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .unavailable)
            }
        }
    }

    @MainActor func testLateAcquisitionCannotRepopulateCancelledSession() async throws {
        let entered = expectation(description: "capture entered"), release = DispatchSemaphore(value: 0)
        let batch = BatchSigningCoordinator(capture: { url, format, _ in
            let snapshot = try DocumentSnapshot.capture(source: url, format: format)
            entered.fulfill(); _ = release.wait(timeout:.now()+5); return snapshot
        })
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("late.txt"); try Data("synthetic late callback".utf8).write(to: source)
        let task = Task { await batch.addDocuments([source], format: .cades) }
        await fulfillment(of: [entered], timeout: 5)
        XCTAssertTrue(batch.isPreparing)
        await batch.addDocuments([source], format: .pades) // Concurrent selection cannot alter this acquisition.
        batch.cancelAll(); release.signal(); await task.value
        XCTAssertTrue(batch.documents.isEmpty); XCTAssertFalse(batch.isPreparing)
        batch.reset(); XCTAssertFalse(batch.isApproved)
    }
}
#endif
