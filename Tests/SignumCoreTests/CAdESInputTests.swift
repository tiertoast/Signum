#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

final class CAdESInputTests: XCTestCase {
    private func inFolder(_ body: (URL, URL) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("signum-cades-input-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        try body(folder, folder.appendingPathComponent("synthetic.p7m"))
    }
    private func resize(_ file: URL, to size: Int) throws {
        let fd = Darwin.open(file.path, O_WRONLY | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SignumError.module("Cannot open synthetic fixture") }
        defer { Darwin.close(fd) }
        XCTAssertEqual(ftruncate(fd, off_t(size)), 0)
    }

    func testSmallFileAndEINTRAndShortReadsPreserveExactBytes() throws {
        try inFolder { _, file in
            let bytes = Data(repeating: 0x53, count: 100_000); try bytes.write(to: file)
            var io = CAdESVerifier.InputIO(), calls = 0
            io.read = { fd, p, n in
                calls += 1
                if calls == 1 { errno = EINTR; return -1 }
                return Darwin.read(fd, p, min(317, n))
            }
            XCTAssertEqual(try CAdESVerifier.readInput(file: file, io: io), bytes)
            XCTAssertGreaterThan(calls, 3)
        }
    }
    func testExactlyAt64MiBLimitIsReadWithoutReadingPastOneEOFProbe() throws {
        try inFolder { _, file in
            try resize(file, to: CAdESVerifier.maximumInputBytes)
            var total = 0, maximumRequest = 0, lastRequest = 0
            var io = CAdESVerifier.InputIO()
            io.read = { fd, p, n in
                maximumRequest = max(maximumRequest, n); lastRequest = n
                let read = Darwin.read(fd, p, n); if read > 0 { total += read }; return read
            }
            let bytes = try CAdESVerifier.readInput(file: file, io: io)
            XCTAssertEqual(bytes.count, CAdESVerifier.maximumInputBytes)
            XCTAssertEqual(total, bytes.count); XCTAssertEqual(maximumRequest, 65536); XCTAssertEqual(lastRequest, 1)
            XCTAssertTrue(bytes.allSatisfy { $0 == 0 })
        }
    }
    func testOversizedAndEmptyFilesAreRejectedBeforeAnyRead() throws {
        for size in [0, CAdESVerifier.maximumInputBytes + 1] {
            try inFolder { _, file in
                try resize(file, to: size)
                var io = CAdESVerifier.InputIO(), reads = 0
                io.read = { _, _, _ in reads += 1; return 0 }
                XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
                XCTAssertEqual(reads, 0)
                XCTAssertThrowsError(try CAdESVerifier.verify(file: file))
            }
        }
    }
    func testSymlinkToOversizedFileIsRejectedBeforeReadingTarget() throws {
        try inFolder { folder, file in
            let target = folder.appendingPathComponent("large")
            try resize(target, to: CAdESVerifier.maximumInputBytes + 1)
            try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
            var io = CAdESVerifier.InputIO(), reads = 0
            io.read = { _, _, _ in reads += 1; return 0 }
            XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
            XCTAssertEqual(reads, 0)
            XCTAssertThrowsError(try CAdESVerifier.verify(file: file))
        }
    }
    func testGrowthPastLimitAfterOpenIsBoundedDuringReads() throws {
        try inFolder { _, file in
            try Data([0x53]).write(to: file)
            var io = CAdESVerifier.InputIO(), total = 0
            io.opened = { _ in try self.resize(file, to: CAdESVerifier.maximumInputBytes + 1024 * 1024) }
            io.read = { fd, p, n in
                let count = Darwin.read(fd, p, n); if count > 0 { total += count }; return count
            }
            XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io)) { error in
                XCTAssertTrue(error.localizedDescription.contains("supera il limite"))
            }
            XCTAssertEqual(total, CAdESVerifier.maximumInputBytes + 1)
        }
    }
    func testGrowthAndInPlaceChangesWithinLimitAreRejected() throws {
        for grow in [false, true] {
            try inFolder { _, file in
                try Data(repeating: 0x53, count: 100_000).write(to: file)
                var io = CAdESVerifier.InputIO(), calls = 0
                io.read = { fd, p, n in
                    calls += 1
                    if calls == 2 {
                        if grow { try! self.resize(file, to: 110_000) }
                        else {
                            let writer = Darwin.open(file.path, O_WRONLY); defer { Darwin.close(writer) }
                            var byte: UInt8 = 0x42; XCTAssertEqual(pwrite(writer, &byte, 1, 0), 1)
                        }
                    }
                    return Darwin.read(fd, p, n)
                }
                XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
            }
        }
    }
    func testFileReplacementAndSymlinkSubstitutionAreRejected() throws {
        for link in [false, true] {
            try inFolder { folder, file in
                try Data("Approved original bytes".utf8).write(to: file)
                let moved = folder.appendingPathComponent("moved")
                var io = CAdESVerifier.InputIO()
                io.opened = { _ in
                    try FileManager.default.moveItem(at: file, to: moved)
                    if link { try FileManager.default.createSymbolicLink(at: file, withDestinationURL: moved) }
                    else { try Data("Replacement".utf8).write(to: file) }
                }
                XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
                XCTAssertEqual(try Data(contentsOf: moved), Data("Approved original bytes".utf8))
            }
        }
    }
    func testPinnedParentReplacementIsRejectedWithoutReadingForeignInput() throws {
        try inFolder { folder, _ in
            let selected = folder.appendingPathComponent("selected"), moved = folder.appendingPathComponent("moved")
            try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: false)
            let file = selected.appendingPathComponent("input.p7m")
            try Data("Original".utf8).write(to: file)
            var io = CAdESVerifier.InputIO(), readBytes = Data()
            io.opened = { _ in
                try FileManager.default.moveItem(at: selected, to: moved)
                try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: false)
                try Data("Foreign".utf8).write(to: file)
            }
            io.read = { fd, p, n in
                let count = Darwin.read(fd, p, n)
                if count > 0 { readBytes.append(p.assumingMemoryBound(to: UInt8.self), count: count) }
                return count
            }
            XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
            XCTAssertEqual(readBytes, Data("Original".utf8))
        }
    }
    func testFIFOAndDirectoryAndDeviceAreRejectedWithoutContentReadOrBlocking() throws {
        try inFolder { _, file in
            XCTAssertEqual(mkfifo(file.path, 0o600), 0)
            var io = CAdESVerifier.InputIO(), reads = 0
            io.read = { _, _, _ in reads += 1; return 0 }
            for object in [file, file.deletingLastPathComponent(), URL(fileURLWithPath: "/dev/null")] {
                XCTAssertThrowsError(try CAdESVerifier.readInput(file: object, io: io))
            }
            XCTAssertEqual(reads, 0)
        }
    }
    func testIOErrorAndPrematureEOFAreRejectedAndDescriptorClosed() throws {
        for fail in [false, true] {
            try inFolder { _, file in
                try Data("Synthetic data".utf8).write(to: file)
                var io = CAdESVerifier.InputIO(), descriptor: Int32 = -1
                io.read = { fd, _, _ in descriptor = fd; errno = EIO; return fail ? -1 : 0 }
                XCTAssertThrowsError(try CAdESVerifier.readInput(file: file, io: io))
                XCTAssertEqual(fcntl(descriptor, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
                XCTAssertEqual(try CAdESVerifier.readInput(file: file), Data("Synthetic data".utf8))
            }
        }
    }
}
#endif
