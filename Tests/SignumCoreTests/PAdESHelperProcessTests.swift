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
            guard case .uncertain(let message) = outcome else { return XCTFail("Unexpected transport outcome") }
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
    func testTimeoutWithoutProofRemainsUncertainWithoutRetry() throws {
        try fixture { output in
            guard case .uncertain = run("while :; do :; done", output: output, timeout: 0.05) else { return XCTFail("Expected timeout uncertainty") }
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
    func testCancellationBeforeLaunchDoesNotCreateOutput() throws {
        try fixture { output in
            var input = Data()
            let outcome = PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf unexpected > \"$1\"", "fixture", output.path], input: &input,
                destination: output, isCancelled: { true })
            guard case .cancelled = outcome else { return XCTFail("Pre-launch cancellation was not distinguished") }
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }
    func testCancellationAfterCommitPreservesUncertainOutput() throws {
        try fixture { output in
            var input = Data()
            let outcome = PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf synthetic > \"$1\"; while :; do :; done", "fixture", output.path], input: &input,
                destination: output, isCancelled: { FileManager.default.fileExists(atPath: output.path) })
            guard case .uncertain = outcome else { return XCTFail("Possible commit must stay uncertain") }
            XCTAssertEqual(try String(contentsOf: output), "synthetic")
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
    func testBoundPreAuthenticationStatusAndFinalErrorMapping() throws {
        try fixture { output in
            let job = UUID()
            func reply(_ id: UUID, version: Int = 4, outcome: String = "rejectedBeforeAuthentication", reason: String = "busy") -> PAdESHelperProcess.Outcome {
                var input = Data()
                let message = "{\"version\":\(version),\"jobID\":\"\(id)\",\"outcome\":\"\(outcome)\",\"reason\":\"\(reason)\"}"
                return PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/echo"), arguments: [message],
                    input: &input, destination: output, expectedJobID: job)
            }
            let rejection = reply(job)
            guard case .failed = rejection else { return XCTFail("Known busy must fail ordinarily") }
            XCTAssertThrowsError(try PAdESHelperProcess.requirePublished(rejection)) { error in
                guard case SignumError.module = error else { return XCTFail("Busy became uncertain") }
            }
            for outcome in [reply(UUID()), reply(job, version: 3), reply(job, reason: "unrecognized"),
                            reply(job, outcome: "uncertain", reason: "interrupted"), reply(job, outcome: "published", reason: "none")] {
                guard case .uncertain = outcome else { return XCTFail("Unproved status accepted") }
                XCTAssertThrowsError(try PAdESHelperProcess.requirePublished(outcome)) { error in
                    guard case SignumError.outputUncertain = error else { return XCTFail("Lost uncertainty") }
                }
            }
            XCTAssertThrowsError(try PAdESHelperProcess.requirePublished(.cancelled("before launch"))) { error in
                XCTAssertEqual(error as? SupervisedProcess.Failure, .cancelled)
            }
        }
    }
    func testBoundStatusCannotDowngradeToLegacyOrAcceptMalformedResponse() throws {
        try fixture { output in
            let job = UUID()
            for message in ["malformed", "{}", "{\"version\":4,\"jobID\":\"\(job)\",\"outcome\":\"rejectedBeforeAuthentication\",\"reason\":\"preflight\"}"] {
                var input = Data()
                let result = PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/echo"), arguments: [message],
                    input: &input, destination: output, expectedJobID: job, expectedProtocolVersion: 5)
                guard case .uncertain = result else { return XCTFail("Invalid/legacy status accepted for bound request") }
            }
            var input = Data()
            let message = "{\"version\":5,\"jobID\":\"\(job)\",\"outcome\":\"rejectedBeforeAuthentication\",\"reason\":\"preflight\"}"
            let result = PAdESHelperProcess.run(executable: URL(fileURLWithPath: "/bin/echo"), arguments: [message],
                input: &input, destination: output, expectedJobID: job, expectedProtocolVersion: 5)
            guard case .failed = result else { return XCTFail("Bound pre-authentication rejection lost") }
        }
    }

}
#endif
