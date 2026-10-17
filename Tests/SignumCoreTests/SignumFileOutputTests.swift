import XCTest
import Foundation
import Darwin
@testable import SignumCore

#if os(macOS)
final class SignumFileOutputTests: XCTestCase {
    func testCreatesNewP7MWithoutOverwriting() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("signum-output-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let output = directory.appendingPathComponent("prova.txt.p7m")
        let original = Data("First file".utf8)
        try SignumFileOutput.writeNew(original, to: output)
        XCTAssertEqual(try Data(contentsOf: output), original)
        XCTAssertThrowsError(try SignumFileOutput.writeNew(Data("Overwrite".utf8), to: output))
        XCTAssertEqual(try Data(contentsOf: output), original)
    }

    func testRejectsEmptyData() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("signum-empty-test-\(UUID().uuidString).p7m")
        XCTAssertThrowsError(try SignumFileOutput.writeNew(Data(), to: file))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
    private let bytes = Data(repeating: 0x53, count: 32768)
    private enum FixtureError: Error { case rejected }

    private func inFolder(_ body: (URL, URL) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        try body(folder, folder.appendingPathComponent("signed.p7m"))
    }

    private func assertEmpty(_ folder: URL, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [], file: file, line: line)
    }

    func testPrivateStagingAndNoFinalNameUntilValidation() throws {
        try inFolder { folder, output in
            try SignumFileOutput.writeNew(bytes, to: output) { staged in
                XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
                XCTAssertEqual(staged, self.bytes)
                let entries = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
                XCTAssertEqual(entries.count, 1)
                let stage = try XCTUnwrap(entries.first)
                XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: stage.path)[.posixPermissions] as? NSNumber)?.intValue, 0o700)
                XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: stage.appendingPathComponent("output").path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
            }
            XCTAssertEqual(try Data(contentsOf: output), bytes)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [output.lastPathComponent])
        }
    }

    func testRejectedValidationCleansStagingWithoutPublishing() throws {
        try inFolder { folder, output in
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output) { _ in throw FixtureError.rejected })
            try assertEmpty(folder)
        }
    }

    func testShortWritesAndInterruptedWriteAreRetried() throws {
        try inFolder { _, output in
            var io = SignumFileOutput.OutputIO()
            var calls = 0
            io.write = { fd, pointer, count in
                calls += 1
                XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
                if calls == 1 { errno = EINTR; return -1 }
                return Darwin.write(fd, pointer, min(31, count))
            }
            try SignumFileOutput.writeNew(bytes, to: output, io: io)
            XCTAssertGreaterThan(calls, 2)
            XCTAssertEqual(try Data(contentsOf: output), bytes)
        }
    }

    func testDiskFullAfterPartialWriteLeavesNoOutput() throws {
        try inFolder { folder, output in
            var io = SignumFileOutput.OutputIO()
            var calls = 0
            io.write = { fd, pointer, count in
                calls += 1
                if calls == 1 { return Darwin.write(fd, pointer, min(31, count)) }
                errno = ENOSPC
                return -1
            }
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
            XCTAssertEqual(calls, 2)
            try assertEmpty(folder)
        }
    }

    func testZeroWriteSyncAndCloseFailuresPreventPublication() throws {
        for phase in 0..<3 {
            try inFolder { folder, output in
                var io = SignumFileOutput.OutputIO()
                switch phase {
                case 0: io.write = { _, _, _ in 0 }
                case 1: io.sync = { _ in errno = EIO; return -1 }
                default: io.close = { fd in _ = Darwin.close(fd); errno = EIO; return -1 }
                }
                XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
                try assertEmpty(folder)
            }
        }
    }

    func testCorruptWriteIsDetectedBeforeValidatorAndPublication() throws {
        try inFolder { folder, output in
            var io = SignumFileOutput.OutputIO()
            io.write = { fd, _, count in
                let bad = [UInt8](repeating: 0xFF, count: count)
                return bad.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, count) }
            }
            var validated = false
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io) { _ in validated = true })
            XCTAssertFalse(validated)
            try assertEmpty(folder)
        }
    }

    func testDestinationAppearingAtCommitIsNeverOverwritten() throws {
        try inFolder { folder, output in
            let foreign = Data("Concurrent winner".utf8)
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output) { _ in
                try foreign.write(to: output)
            })
            XCTAssertEqual(try Data(contentsOf: output), foreign)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [output.lastPathComponent])
        }
    }

    func testDanglingDestinationSymlinkIsPreserved() throws {
        try inFolder { folder, output in
            let target = folder.appendingPathComponent("absent")
            try FileManager.default.createSymbolicLink(at: output, withDestinationURL: target)
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output))
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: output.path), target.path)
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        }
    }

    func testRecoverySkipsLiveTransaction() throws {
        try inFolder { folder, output in
            let other = folder.appendingPathComponent("other")
            try SignumFileOutput.writeNew(bytes, to: output) { _ in
                try SignumFileOutput.writeNew(Data("Other complete output".utf8), to: other)
            }
            XCTAssertEqual(try Data(contentsOf: output), bytes)
            XCTAssertEqual(try Data(contentsOf: other), Data("Other complete output".utf8))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path).count, 2)
        }
    }

    func testRecoveryIgnoresSymlinksAndUnknownStagingEntries() throws {
        try inFolder { folder, output in
            let foreign = folder.appendingPathComponent("foreign")
            try FileManager.default.createDirectory(at: foreign, withIntermediateDirectories: false)
            try Data("Foreign data".utf8).write(to: foreign.appendingPathComponent("output"))
            let link = folder.appendingPathComponent(".signum-staging-" + UUID().uuidString)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: foreign)
            let unknown = folder.appendingPathComponent(".signum-staging-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: unknown, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Data("Keep".utf8).write(to: unknown.appendingPathComponent("unrecognized"))
            let unknownOutput = unknown.appendingPathComponent("output")
            try Data("Also keep".utf8).write(to: unknownOutput)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: unknownOutput.path)
            try SignumFileOutput.writeNew(bytes, to: output)
            XCTAssertEqual(try Data(contentsOf: foreign.appendingPathComponent("output")), Data("Foreign data".utf8))
            XCTAssertEqual(try Data(contentsOf: unknown.appendingPathComponent("unrecognized")), Data("Keep".utf8))
            XCTAssertEqual(try Data(contentsOf: unknownOutput), Data("Also keep".utf8))
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), foreign.path)
        }
    }

    func testKilledWriterLeavesNoFinalAndNextWriteRecoversStaging() throws {
        try inFolder { folder, output in
            let probe = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumOutputCrashProbe")
            XCTAssertTrue(FileManager.default.isExecutableFile(atPath: probe.path))
            let process = Process()
            process.executableURL = probe
            process.arguments = [output.path]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationReason, .uncaughtSignal)
            XCTAssertEqual(process.terminationStatus, SIGKILL)
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
            let abandoned = try FileManager.default.contentsOfDirectory(atPath: folder.path)
            XCTAssertEqual(abandoned.count, 1)
            XCTAssertTrue(abandoned.first?.hasPrefix(".signum-staging-") == true)
            try SignumFileOutput.writeNew(bytes, to: output)
            XCTAssertEqual(try Data(contentsOf: output), bytes)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [output.lastPathComponent])
        }
    }

    func testStagingReplacementIsNotPublishedOrDeleted() throws {
        try inFolder { folder, output in
            var io = SignumFileOutput.OutputIO()
            var stage: URL!
            io.staged = {
                stage = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil).first)
            }
            io.beforePublish = {
                let payload = stage.appendingPathComponent("output")
                try FileManager.default.moveItem(at: payload, to: stage.appendingPathComponent("moved"))
                try Data("Foreign replacement".utf8).write(to: payload)
            }
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
            XCTAssertEqual(try Data(contentsOf: stage.appendingPathComponent("output")), Data("Foreign replacement".utf8))
        }
    }

    func testErrorCleanupUsesPinnedDirectoryAfterParentReplacement() throws {
        try inFolder { folder, _ in
            let selected = folder.appendingPathComponent("selected")
            let moved = folder.appendingPathComponent("moved")
            try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: false)
            let output = selected.appendingPathComponent("signed.p7m")
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output) { _ in
                try FileManager.default.moveItem(at: selected, to: moved)
                try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: false)
                try Data("Foreign output".utf8).write(to: output)
                throw FixtureError.rejected
            })
            XCTAssertEqual(try Data(contentsOf: output), Data("Foreign output".utf8))
            try assertEmpty(moved)
        }
    }

}
#endif
