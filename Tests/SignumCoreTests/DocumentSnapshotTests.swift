#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

final class DocumentSnapshotTests: XCTestCase {
    private let bytes = Data(repeating: 0x53, count: 160_000)
    private func inFolder(_ body: (URL, URL) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-snapshot-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("source.bin")
        try bytes.write(to: source)
        try body(folder, source)
    }
    private func capture(_ source: URL, _ root: URL, io: DocumentSnapshot.CaptureIO = .init()) throws -> DocumentSnapshot {
        try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: root, io: io)
    }
    private func entries(_ folder: URL) throws -> [String] { try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted() }
    func testExactImmutableBytesPrivatePermissionsAndOriginalUntouched() throws {
        try inFolder { folder, source in
            let original = try Data(contentsOf: source)
            let snapshot = try capture(source, folder)
            XCTAssertEqual(snapshot.approvedBytes, original)
            XCTAssertEqual(try snapshot.verifiedBytes(), original)
            XCTAssertEqual(snapshot.identity.sha256, DocumentSnapshot.digest(original))
            XCTAssertEqual(snapshot.identity.byteCount, original.count)
            let attributes = try FileManager.default.attributesOfItem(atPath: snapshot.fileURL.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o400)
            XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: snapshot.fileURL.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber)?.intValue, 0o700)
            var value = snapshot.approvedBytes; value[0] ^= 1
            XCTAssertEqual(snapshot.approvedBytes, original)
            snapshot.close(); snapshot.close()
            XCTAssertEqual(try Data(contentsOf: source), original)
            XCTAssertEqual(try entries(folder), ["source.bin"])
            XCTAssertThrowsError(try snapshot.verifiedBytes())
        }
    }
    func testSourceModifiedOrReplacedAfterPreviewDoesNotChangeApprovedBytes() throws {
        for replace in [false, true] {
            try inFolder { folder, source in
                let snapshot = try capture(source, folder); defer { snapshot.close() }
                let preview = snapshot.approvedBytes
                if replace { try FileManager.default.removeItem(at: source) }
                try Data("New synthetic document".utf8).write(to: source)
                XCTAssertEqual(try snapshot.verifiedBytes(), preview)
                XCTAssertEqual(snapshot.identity.sha256, DocumentSnapshot.digest(preview))
                XCTAssertNotEqual(try Data(contentsOf: source), preview)
            }
        }
    }
    func testSourceRemovalAfterCaptureDoesNotRequireReopeningOriginal() throws {
        try inFolder { folder, source in
            let snapshot = try capture(source, folder); defer { snapshot.close() }
            try FileManager.default.removeItem(at: source)
            XCTAssertEqual(try snapshot.verifiedBytes(), bytes)
        }
    }
    func testInPlaceWriteDuringSnapshotReadRejectsSelection() throws {
        try inFolder { folder, source in
            var io = DocumentSnapshot.CaptureIO(), modified = false
            io.read = { fd, pointer, count in
                if !modified {
                    modified = true
                    let writer = Darwin.open(source.path, O_WRONLY)
                    XCTAssertGreaterThanOrEqual(writer, 0)
                    let changed = [UInt8](repeating: 0x58, count: 160_000)
                    _ = changed.withUnsafeBytes { Darwin.write(writer, $0.baseAddress!, $0.count) }
                    Darwin.close(writer)
                }
                return Darwin.read(fd, pointer, count)
            }
            XCTAssertThrowsError(try capture(source, folder, io: io))
            XCTAssertTrue(modified)
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testReplacementDuringAcquisitionIsRejected() throws {
        try inFolder { folder, source in
            var io = DocumentSnapshot.CaptureIO()
            io.sourceOpened = { _ in
                try FileManager.default.removeItem(at: source)
                try self.bytes.write(to: source) // Equal contents/size, different inode.
            }
            XCTAssertThrowsError(try capture(source, folder, io: io))
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testSourceGrowingBeyondLimitIsRejectedBeforeAllocation() throws {
        try inFolder { folder, source in
            var io = DocumentSnapshot.CaptureIO()
            io.sourceOpened = { fd in
                let writer = Darwin.open(source.path, O_WRONLY)
                XCTAssertGreaterThanOrEqual(writer, 0)
                XCTAssertEqual(ftruncate(writer, off_t(CAdES.maximumDocumentBytes + 1)), 0)
                Darwin.close(writer)
                var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
                XCTAssertGreaterThan(info.st_size, off_t(CAdES.maximumDocumentBytes))
            }
            XCTAssertThrowsError(try capture(source, folder, io: io))
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testSymlinkLeafAncestorAndPrivateRootAreRejected() throws {
        try inFolder { folder, source in
            let link = folder.appendingPathComponent("link.bin")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)
            XCTAssertThrowsError(try capture(link, folder))
            let alias = folder.appendingPathComponent("alias")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: folder)
            XCTAssertThrowsError(try capture(alias.appendingPathComponent("source.bin"), folder))
            XCTAssertThrowsError(try capture(source, alias))
            XCTAssertEqual(try Data(contentsOf: source), bytes)
        }
    }
    func testSnapshotCorruptionWithSameLengthCannotBypassHash() throws {
        try inFolder { folder, source in
            let snapshot = try capture(source, folder)
            XCTAssertEqual(chmod(snapshot.fileURL.path, 0o600), 0)
            try Data(repeating: 0x58, count: bytes.count).write(to: snapshot.fileURL)
            XCTAssertThrowsError(try snapshot.verifiedBytes())
            XCTAssertEqual(snapshot.approvedBytes, bytes)
            snapshot.close()
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testMissingAndReplacedSnapshotNeverFallBackToSource() throws {
        for replace in [false, true] {
            try inFolder { folder, source in
                let snapshot = try capture(source, folder)
                try FileManager.default.removeItem(at: snapshot.fileURL)
                if replace { try bytes.write(to: snapshot.fileURL) }
                XCTAssertThrowsError(try snapshot.verifiedBytes())
                snapshot.close()
                if replace { XCTAssertEqual(try Data(contentsOf: snapshot.fileURL), bytes) } // Foreign inode preserved.
                XCTAssertEqual(try Data(contentsOf: source), bytes)
            }
        }
    }
    func testSymlinkReplacingSnapshotCannotRedirectCleanup() throws {
        try inFolder { folder, source in
            let snapshot = try capture(source, folder)
            try FileManager.default.removeItem(at: snapshot.fileURL)
            try FileManager.default.createSymbolicLink(at: snapshot.fileURL, withDestinationURL: source)
            XCTAssertThrowsError(try snapshot.verifiedBytes())
            snapshot.close()
            XCTAssertEqual(try Data(contentsOf: source), bytes)
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: snapshot.fileURL.path), source.path)
        }
    }
    func testUnsupportedCloneAndReadErrorsCleanPrivateCopies() throws {
        for phase in 0..<2 {
            try inFolder { folder, source in
                var io = DocumentSnapshot.CaptureIO()
                if phase == 0 { io.clone = { _, _, _ in errno = ENOTSUP; return -1 } }
                else { io.read = { _, _, _ in errno = EIO; return -1 } }
                XCTAssertThrowsError(try capture(source, folder, io: io))
                XCTAssertEqual(try entries(folder), ["source.bin"])
                XCTAssertEqual(try Data(contentsOf: source), bytes)
            }
        }
    }
    func testEmptyOversizedAndNonRegularSourcesAreRejected() throws {
        try inFolder { folder, source in
            try Data().write(to: source)
            XCTAssertThrowsError(try capture(source, folder))
            let fd = Darwin.open(source.path, O_WRONLY)
            XCTAssertEqual(ftruncate(fd, off_t(CAdES.maximumDocumentBytes + 1)), 0); Darwin.close(fd)
            XCTAssertThrowsError(try capture(source, folder))
            XCTAssertThrowsError(try capture(folder, folder))
            let fifo = folder.appendingPathComponent("fifo")
            XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
            XCTAssertThrowsError(try capture(fifo, folder)) // O_NONBLOCK: never waits for a writer.
        }
    }
    func testCancelledSelectionAndLastReferenceReleaseCleanCopies() throws {
        try inFolder { folder, source in
            var snapshot: DocumentSnapshot? = try capture(source, folder)
            let location = try XCTUnwrap(snapshot?.fileURL)
            snapshot = nil
            XCTAssertFalse(FileManager.default.fileExists(atPath: location.path))
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testCrashRecoveryReclaimsOnlyAbandonedSnapshot() throws {
        try inFolder { _, source in
            let process = Process()
            process.executableURL = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumOutputCrashProbe")
            process.arguments = ["snapshot-crash", source.path]
            let output = Pipe(), input = Pipe(); process.standardOutput = output; process.standardInput = input
            let fd = output.fileHandleForReading.fileDescriptor
            XCTAssertEqual(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK), 0)
            try process.run()
            defer { if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit() } }
            var captured = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while ProcessInfo.processInfo.systemUptime < deadline {
                let count = Darwin.read(fd, &buffer, buffer.count)
                if count > 0 { captured.append(contentsOf: buffer.prefix(count)) }
                if captured.contains(10) || !process.isRunning { break }
                Thread.sleep(forTimeInterval: 0.01)
            }
            let location = String(decoding: captured, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            XCTAssertFalse(location.isEmpty)
            XCTAssertTrue(FileManager.default.fileExists(atPath: location))
            try input.fileHandleForWriting.write(contentsOf: Data([1]))
            try input.fileHandleForWriting.close()
            let finish = ProcessInfo.processInfo.systemUptime + 3
            while process.isRunning && ProcessInfo.processInfo.systemUptime < finish { Thread.sleep(forTimeInterval: 0.01) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL); XCTFail("Crash fixture blocked") }
            process.waitUntilExit()
            XCTAssertEqual(process.terminationReason, .uncaughtSignal)
            XCTAssertEqual(process.terminationStatus, SIGKILL)
            let next = try DocumentSnapshot.capture(source: source, format: .cades)
            defer { next.close() }
            XCTAssertFalse(FileManager.default.fileExists(atPath: location))
            XCTAssertEqual(try next.verifiedBytes(), bytes)
        }
    }
    func testHardLinkCannotMakeSnapshotChmodOrRemoveOriginal() throws {
        try inFolder { folder, source in
            let before = try FileManager.default.attributesOfItem(atPath: source.path)[.posixPermissions] as? NSNumber
            var io = DocumentSnapshot.CaptureIO()
            io.clone = { _, target, name in linkat(AT_FDCWD, source.path, target, name, 0) }
            XCTAssertThrowsError(try capture(source, folder, io: io))
            XCTAssertEqual(try Data(contentsOf: source), bytes)
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: source.path)[.posixPermissions] as? NSNumber, before)
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testInterruptedAndShortSnapshotReadsAreHandled() throws {
        try inFolder { folder, source in
            var io = DocumentSnapshot.CaptureIO(), first = true
            io.read = { fd, buffer, count in
                if first { first = false; errno = EINTR; return -1 }
                return Darwin.read(fd, buffer, min(31, count))
            }
            let snapshot = try capture(source, folder, io: io); defer { snapshot.close() }
            XCTAssertEqual(snapshot.approvedBytes, bytes)
        }
    }
    func testPAdESMaximumIsEnforcedWithoutAllocatingOversizedFile() throws {
        try inFolder { folder, source in
            let fd = Darwin.open(source.path, O_WRONLY)
            XCTAssertEqual(ftruncate(fd, off_t(SigningFormat.pades.maximumDocumentBytes + 1)), 0); Darwin.close(fd)
            XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: folder))
            XCTAssertEqual(try entries(folder), ["source.bin"])
        }
    }
    func testRecoverySkipsLiveSnapshotAndUnknownLayouts() throws {
        try inFolder { folder, source in
            let first = try capture(source, folder)
            let unknown = folder.appendingPathComponent(".signum-snapshot-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: unknown, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Data([1]).write(to: unknown.appendingPathComponent("foreign"))
            let second = try capture(source, folder)
            XCTAssertEqual(try first.verifiedBytes(), bytes)
            XCTAssertTrue(FileManager.default.fileExists(atPath: unknown.appendingPathComponent("foreign").path))
            second.close(); first.close()
        }
    }
}
#endif
