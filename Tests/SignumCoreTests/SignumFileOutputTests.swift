import XCTest
import Foundation
import Darwin
import COutputPermissions
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

    private func setInheritedACL(_ folder: URL, write: Bool,
                                 inheritance: [acl_flag_t] = [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT],
                                 deny: Bool = false, permissions: [acl_perm_t]? = nil, append: Bool = false) throws {
        let fd = Darwin.open(folder.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { Darwin.close(fd) }
        var acl: acl_t? = append ? acl_get_fd(fd) : nil
        if acl == nil { acl = try XCTUnwrap(acl_init(1)) }
        defer { acl_free(UnsafeMutableRawPointer(acl!)) }
        var entry: acl_entry_t?
        XCTAssertEqual(acl_create_entry(&acl, &entry), 0)
        let ace = try XCTUnwrap(entry)
        XCTAssertEqual(acl_set_tag_type(ace, deny ? ACL_EXTENDED_DENY : ACL_EXTENDED_ALLOW), 0)
        var everyone = UUID(uuidString: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C")!.uuid
        XCTAssertEqual(withUnsafePointer(to: &everyone) { acl_set_qualifier(ace, $0) }, 0)
        var perms: acl_permset_t?
        XCTAssertEqual(acl_get_permset(ace, &perms), 0)
        let rights: [acl_perm_t] = permissions ?? ([ACL_READ_DATA, ACL_EXECUTE, ACL_READ_ATTRIBUTES, ACL_READ_SECURITY] +
            (write ? [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_WRITE_ATTRIBUTES] : []))
        for right in rights { XCTAssertEqual(acl_add_perm(perms!, right), 0) }
        var flags: acl_flagset_t?
        XCTAssertEqual(acl_get_flagset_np(UnsafeMutableRawPointer(ace), &flags), 0)
        for flag in inheritance { XCTAssertEqual(acl_add_flag_np(flags!, flag), 0) }
        XCTAssertEqual(acl_set_fd(fd, acl), 0)
    }

    private func clearFixtureACL(_ url: URL, directory: Bool = false) {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd >= 0 { _ = sg_output_make_private(fd, directory ? 0o700 : 0o600); Darwin.close(fd) }
    }

    private func aclDescription(_ url: URL) throws -> String {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FixtureError.rejected }
        defer { Darwin.close(fd) }
        guard let acl = acl_get_fd(fd) else {
            XCTAssertEqual(errno, ENOENT); return ""
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        let text = try XCTUnwrap(acl_to_text(acl, nil))
        defer { acl_free(text) }
        return String(cString: text)
    }

    func testInheritedReadAndWriteACLStayPrivateUntilCommitAndSharingIsPreserved() throws {
        for write in [false, true] {
            try inFolder { folder, output in
                try setInheritedACL(folder, write: write)
                // Kernel-created control gives the exact inheritance semantics.
                let control = folder.appendingPathComponent("control")
                let controlFD = Darwin.open(control.path, O_CREAT | O_EXCL | O_RDWR, 0o600)
                XCTAssertGreaterThanOrEqual(controlFD, 0); Darwin.close(controlFD)
                let expected = try aclDescription(control)
                XCTAssertTrue(expected.contains("everyone"))
                try FileManager.default.removeItem(at: control)
                var identity = stat(), checkedClose = false
                var io = SignumFileOutput.OutputIO()
                io.close = { fd in
                    checkedClose = true
                    let stage = try! XCTUnwrap(FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil).first)
                    let stageFD = Darwin.open(stage.path, O_RDONLY | O_DIRECTORY)
                    defer { Darwin.close(stageFD) }
                    XCTAssertEqual(sg_output_is_private(stageFD, 0o700), 0)
                    var current = stat(); XCTAssertEqual(fstat(fd, &current), 0)
                    XCTAssertEqual(current.st_ino, identity.st_ino)
                    XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
                    return Darwin.close(fd)
                }
                try SignumFileOutput.writeNew(bytes, to: output, io: io) { staged in
                    XCTAssertEqual(staged, self.bytes)
                    let stage = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil).first)
                    XCTAssertEqual(try self.aclDescription(stage), "")
                    let payload = stage.appendingPathComponent("output")
                    XCTAssertEqual(try self.aclDescription(payload), "")
                    XCTAssertEqual(lstat(payload.path, &identity), 0)
                }
                XCTAssertTrue(checkedClose)
                XCTAssertEqual(try aclDescription(output), expected)
                var final = stat(); XCTAssertEqual(lstat(output.path, &final), 0)
                XCTAssertEqual(final.st_ino, identity.st_ino)
                XCTAssertEqual(try Data(contentsOf: output), bytes)
            }
        }
    }

    func testFinalACLUsesKernelFileInheritanceIncludingLimitedAndInheritOnlyACE() throws {
        let variants: [[acl_flag_t]] = [[ACL_ENTRY_FILE_INHERIT], [ACL_ENTRY_DIRECTORY_INHERIT],
            [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT, ACL_ENTRY_LIMIT_INHERIT],
            [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT, ACL_ENTRY_ONLY_INHERIT]]
        for flags in variants {
            try inFolder { folder, output in
                try setInheritedACL(folder, write: true, inheritance: flags)
                let control = folder.appendingPathComponent("control")
                let fd = Darwin.open(control.path, O_CREAT | O_EXCL | O_RDWR, 0o600)
                XCTAssertGreaterThanOrEqual(fd, 0); Darwin.close(fd)
                let expected = try aclDescription(control)
                try FileManager.default.removeItem(at: control)
                try SignumFileOutput.writeNew(bytes, to: output)
                XCTAssertEqual(try aclDescription(output), expected)
            }
        }
    }

    func testInheritedACLDoesNotAllowPublishingReplacedPayloadSymlink() throws {
        try inFolder { folder, output in
            try setInheritedACL(folder, write: true)
            let foreign = folder.appendingPathComponent("foreign")
            try Data("Foreign data".utf8).write(to: foreign)
            var stage: URL!, io = SignumFileOutput.OutputIO()
            io.staged = {
                stage = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
                    .first { $0.lastPathComponent.hasPrefix(".signum-staging-") })
            }
            io.beforePublish = {
                let payload = stage.appendingPathComponent("output")
                try FileManager.default.moveItem(at: payload, to: stage.appendingPathComponent("moved"))
                try FileManager.default.createSymbolicLink(at: payload, withDestinationURL: foreign)
            }
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
            XCTAssertEqual(try Data(contentsOf: foreign), Data("Foreign data".utf8))
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: stage.appendingPathComponent("output").path), foreign.path)
        }
    }

    func testRecoveryReclaimsOnlyEmptyInheritanceFixture() throws {
        try inFolder { folder, output in
            let abandoned = folder.appendingPathComponent(".signum-staging-" + UUID().uuidString)
            let chamber = abandoned.appendingPathComponent(".permissions")
            try FileManager.default.createDirectory(at: chamber, withIntermediateDirectories: true)
            XCTAssertEqual(chmod(abandoned.path, 0o700), 0)
            try Data().write(to: chamber.appendingPathComponent("empty"))
            try SignumFileOutput.writeNew(bytes, to: output)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [output.lastPathComponent])
        }
    }

    func testDenyDeletionACLDoesNotBreakInheritanceProbeCleanupOrFinalSharing() throws {
        let scenarios: [([acl_perm_t], [acl_flag_t])] = [
            ([ACL_DELETE], []), ([ACL_DELETE], [ACL_ENTRY_DIRECTORY_INHERIT])]
        for (denials, flags) in scenarios {
            try inFolder { folder, output in
                defer { clearFixtureACL(output); clearFixtureACL(folder, directory: true) }
                try setInheritedACL(folder, write: true)
                try setInheritedACL(folder, write: false, inheritance: flags, deny: true, permissions: denials, append: true)
                let parentACL = try aclDescription(folder)
                let control = folder.appendingPathComponent("control")
                let controlFD = Darwin.open(control.path, O_CREAT | O_EXCL | O_RDWR, 0o600)
                XCTAssertGreaterThanOrEqual(controlFD, 0)
                let expected = try aclDescription(control)
                XCTAssertEqual(sg_output_make_private(controlFD, 0o600), 0); Darwin.close(controlFD)
                try FileManager.default.removeItem(at: control)
                var identity = stat(), io = SignumFileOutput.OutputIO()
                io.staged = {
                    let stage = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil).first)
                    XCTAssertEqual(try self.aclDescription(stage), "")
                    XCTAssertEqual(try self.aclDescription(stage.appendingPathComponent("output")), "")
                    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: stage.path), ["output"])
                    XCTAssertEqual(lstat(stage.appendingPathComponent("output").path, &identity), 0)
                }
                try SignumFileOutput.writeNew(bytes, to: output, io: io) { staged in XCTAssertEqual(staged, self.bytes) }
                XCTAssertEqual(try Data(contentsOf: output), bytes)
                XCTAssertEqual(try aclDescription(output), expected)
                XCTAssertEqual(try aclDescription(folder), parentACL)
                var published = stat(); XCTAssertEqual(lstat(output.path, &published), 0)
                XCTAssertEqual(published.st_ino, identity.st_ino)
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), [output.lastPathComponent])
            }
        }
    }

    func testProbeCapturesDeleteAndDeleteChildDenialsWithoutDiscardingFinalACL() throws {
        let scenarios: [([acl_perm_t], [acl_flag_t])] = [
            ([ACL_DELETE], []), ([ACL_DELETE_CHILD], []),
            ([ACL_DELETE], [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT]),
            ([ACL_DELETE, ACL_DELETE_CHILD], [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT])]
        for (denials, flags) in scenarios {
            try inFolder { folder, _ in
                let control = folder.appendingPathComponent("control"), stage = folder.appendingPathComponent("private")
                let payload = stage.appendingPathComponent("payload")
                defer { clearFixtureACL(control); clearFixtureACL(payload); clearFixtureACL(folder, directory: true) }
                try setInheritedACL(folder, write: true)
                try setInheritedACL(folder, write: false, inheritance: flags, deny: true, permissions: denials, append: true)
                let parentACL = try aclDescription(folder)
                let controlFD = Darwin.open(control.path, O_CREAT | O_EXCL | O_RDWR, 0o600)
                XCTAssertGreaterThanOrEqual(controlFD, 0); Darwin.close(controlFD)
                let expected = try aclDescription(control)
                try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
                let parentFD = Darwin.open(folder.path, O_RDONLY | O_DIRECTORY), stageFD = Darwin.open(stage.path, O_RDONLY | O_DIRECTORY)
                defer { Darwin.close(parentFD); Darwin.close(stageFD) }
                XCTAssertEqual(sg_output_make_private(stageFD, 0o700), 0)
                let final = try XCTUnwrap(sg_output_inherited_acl(parentFD, stageFD))
                defer { acl_free(UnsafeMutableRawPointer(final)) }
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: stage.path), [])
                XCTAssertEqual(sg_output_is_private(stageFD, 0o700), 0)
                let payloadFD = Darwin.open(payload.path, O_CREAT | O_EXCL | O_RDWR, 0o600)
                XCTAssertGreaterThanOrEqual(payloadFD, 0); defer { Darwin.close(payloadFD) }
                XCTAssertEqual(sg_output_apply_acl(payloadFD, final), 0)
                XCTAssertEqual(try aclDescription(payload), expected)
                XCTAssertEqual(try aclDescription(folder), parentACL)
            }
        }
    }

    func testRecoveryCleansEmptyProbeWithDenyDeleteButPreservesUnknownLayouts() throws {
        for layout in 0..<3 {
            let unknown = layout == 1
            try inFolder { folder, output in
                let abandoned = folder.appendingPathComponent(".signum-staging-" + UUID().uuidString)
                let chamber = abandoned.appendingPathComponent(".permissions")
                try FileManager.default.createDirectory(at: chamber, withIntermediateDirectories: true)
                XCTAssertEqual(chmod(abandoned.path, 0o700), 0)
                try setInheritedACL(chamber, write: false, inheritance: [ACL_ENTRY_FILE_INHERIT], deny: true,
                                    permissions: [ACL_DELETE, ACL_DELETE_CHILD])
                let empty = chamber.appendingPathComponent("empty")
                try (layout == 2 ? Data("Foreign nonempty probe".utf8) : Data()).write(to: empty)
                defer { clearFixtureACL(chamber.appendingPathComponent("foreign")); clearFixtureACL(empty); clearFixtureACL(chamber, directory: true) }
                let originalACL = try aclDescription(chamber)
                if unknown { try Data("Foreign synthetic entry".utf8).write(to: chamber.appendingPathComponent("foreign")) }
                try SignumFileOutput.writeNew(bytes, to: output)
                if layout != 0 {
                    XCTAssertEqual(try aclDescription(chamber), originalACL)
                    XCTAssertTrue(FileManager.default.fileExists(atPath: empty.path))
                    if unknown {
                        XCTAssertEqual(try Data(contentsOf: chamber.appendingPathComponent("foreign")), Data("Foreign synthetic entry".utf8))
                    } else {
                        XCTAssertEqual(try Data(contentsOf: empty), Data("Foreign nonempty probe".utf8))
                    }
                } else {
                    XCTAssertFalse(FileManager.default.fileExists(atPath: abandoned.path))
                }
            }
        }
    }

    func testInheritanceFailureRetainsActualErrnoAndForeignFixture() throws {
        try inFolder { folder, _ in
            let stage = folder.appendingPathComponent("private")
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let foreign = stage.appendingPathComponent(".permissions")
            try Data("Foreign synthetic object".utf8).write(to: foreign)
            let parentFD = Darwin.open(folder.path, O_RDONLY | O_DIRECTORY), stageFD = Darwin.open(stage.path, O_RDONLY | O_DIRECTORY)
            defer { Darwin.close(parentFD); Darwin.close(stageFD) }
            errno = 0
            XCTAssertNil(sg_output_inherited_acl(parentFD, stageFD))
            XCTAssertEqual(errno, EEXIST)
            XCTAssertEqual(try Data(contentsOf: foreign), Data("Foreign synthetic object".utf8))
        }
    }

    func testACLHardeningAndFinalACLFailureNeverWriteOrPublish() throws {
        for phase in 0..<3 {
            try inFolder { folder, output in
                try setInheritedACL(folder, write: true)
                var io = SignumFileOutput.OutputIO(), writes = 0, hardenings = 0
                io.harden = { fd, mode in
                    hardenings += 1
                    if hardenings == phase + 1 { errno = EPERM; return -1 }
                    return sg_output_make_private(fd, mode)
                }
                io.write = { fd, p, n in writes += 1; return Darwin.write(fd, p, n) }
                if phase == 2 { io.applyACL = { _, _ in errno = EPERM; return -1 } }
                XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
                XCTAssertEqual(writes, phase < 2 ? 0 : 1)
                try assertEmpty(folder)
            }
        }
    }

    func testACLHardeningSuccessWithoutEffectivePrivacyIsRejected() throws {
        try inFolder { folder, output in
            try setInheritedACL(folder, write: true)
            var io = SignumFileOutput.OutputIO(), writes = 0
            io.harden = { _, _ in 0 } // A claimed success must not bypass readback.
            io.write = { _, _, _ in writes += 1; return 0 }
            XCTAssertThrowsError(try SignumFileOutput.writeNew(bytes, to: output, io: io))
            XCTAssertEqual(writes, 0)
            try assertEmpty(folder)
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
            try setInheritedACL(folder, write: true)
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
            try setInheritedACL(folder, write: true)
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
