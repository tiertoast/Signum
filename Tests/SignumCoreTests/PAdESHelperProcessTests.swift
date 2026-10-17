#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

final class PAdESHelperProcessTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("signum-process-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        try body(folder.appendingPathComponent("synthetic-output.pdf"))
    }
    // Shell fixtures test transport states only, never signature validity.
    // The actual native verifier and PoDoFo fixtures are covered by CTest.
    private func run(_ script: String, output: URL, timeout: TimeInterval = 5) -> PAdESHelperProcess.Outcome {
        var message = Data()
        return PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/sh"),
                              arguments: ["-c", script, "fixture", output.path],
                              input: &message, destination: output, timeout: timeout)
    }
    func testDrainsLargeStderrWithoutDeadlockAndBoundsDiagnostic() throws {
        try fixture { output in
            let outcome = run("/usr/bin/head -c 262144 /dev/zero >&2; exit 7", output: output)
            guard case .failed(let message) = outcome else { return XCTFail("Unexpected transport outcome") }
            XCTAssertLessThanOrEqual(message.utf8.count, 1200)
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }
    func testSuccessRequiresOutputAndAbnormalExitWithOutputIsUncertain() throws {
        try fixture { output in
            XCTAssertEqual(run("printf synthetic > \"$1\"", output: output), .published)
            try FileManager.default.removeItem(at: output)
            guard case .uncertain = run("printf synthetic > \"$1\"; exit 9", output: output) else { return XCTFail("Must preserve uncertain output") }
            XCTAssertEqual(try String(contentsOf: output), "synthetic")
        }
    }
    func testExitZeroWithoutOutputIsUncertain() throws {
        try fixture { output in
            guard case .uncertain = run("exit 0", output: output) else { return XCTFail("Missing output cannot be success") }
        }
    }
    func testTimeoutWithoutOutputFailsWithoutRetry() throws {
        try fixture { output in
            guard case .failed = run("while :; do :; done", output: output, timeout: 0.05) else { return XCTFail("Expected timeout failure") }
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }
    func testTimeoutAfterOutputIsUncertainAndPreservesFile() throws {
        try fixture { output in
            guard case .uncertain = run("printf synthetic > \"$1\"; while :; do :; done", output: output, timeout: 0.05) else { return XCTFail("Expected uncertainty after possible commit") }
            XCTAssertEqual(try String(contentsOf: output), "synthetic")
        }
    }
    func testExistingDestinationIsRejectedBeforeLaunch() throws {
        try fixture { output in
            try Data("Preserve".utf8).write(to: output)
            guard case .failed = run("printf changed > \"$1\"", output: output) else { return XCTFail("Existing destination accepted") }
            XCTAssertEqual(try String(contentsOf: output), "Preserve")
        }
    }
    func testLaunchFailureLeavesNoOutput() throws {
        try fixture { output in
            var message = Data()
            let outcome = PAdESHelperProcess.run(executable: output.deletingLastPathComponent().appendingPathComponent("absent"),
                                                arguments: [], input: &message, destination: output)
            guard case .failed = outcome else { return XCTFail("Expected launch failure") }
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }
}
#endif
