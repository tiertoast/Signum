#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

/// PIN refusals proven before C_Sign are ordinary, typed failures; anything
/// after C_Sign stays uncertain. Synthetic provider only, no real PIN.
final class SigningAuthenticationFailureTests: XCTestCase {
    private var worker: IsolatedPKCS11Client {
        .init(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
    }
    private func withJob(phase: Int? = nil, effect: Int = 0,
                         _ body: (SigningJob, MockModule) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let signer = try SoftwareSigner(folder: folder)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase, workerEffect: effect, audit: true)
        let source = folder.appendingPathComponent("source"); try Data("Approved synthetic bytes".utf8).write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: folder)
        defer { snapshot.close() }
        let cert = try XCTUnwrap(worker.certificates(provider: mock.path.path, slot: 7).first)
        let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7, certificate: cert.certificate,
                                 certificateDER: cert.der, destination: folder.appendingPathComponent("signed.p7m"))
        try body(job, mock)
    }
    private func audit(_ mock: MockModule, _ code: String) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8)) ?? "")
            .split(separator: "\n").filter { $0 == code }.count
    }

    func testClassificationNeverHidesAPossibleSignature() {
        let countLow: UInt = 1 << 16, finalTry: UInt = 1 << 17, locked: UInt = 1 << 18
        XCTAssertNil(SigningAuthenticationFailure.classify(signCalled: true, loginRV: 0xA0, tokenFlags: 0))
        XCTAssertNil(SigningAuthenticationFailure.classify(signCalled: true, loginRV: 0, tokenFlags: 0))
        let cases: [(UInt, UInt, SigningAuthenticationFailure)] = [
            (0xA0, 0, .pinIncorrect), (0xA0, countLow, .pinIncorrectCountLow), (0xA0, finalTry | countLow, .pinIncorrectFinalTry),
            (0xA0, locked, .pinLocked), (0xA4, 0, .pinLocked), (0xA1, 0, .pinInvalid), (0xA2, 0, .pinInvalid),
            (0xA3, 0, .pinExpired), (0x05, 0, .notSigned), (0, 0, .notSigned)]
        for (rv, flags, expected) in cases {
            XCTAssertEqual(SigningAuthenticationFailure.classify(signCalled: false, loginRV: rv, tokenFlags: flags), expected)
        }
        XCTAssertEqual(Set(SigningAuthenticationFailure.allCases.filter(\.allowsNewPIN)),
                       [.pinIncorrect, .pinIncorrectCountLow, .pinIncorrectFinalTry, .pinInvalid])
        for value in SigningAuthenticationFailure.allCases {
            XCTAssertEqual(SigningAuthenticationFailure(wire: value.wire), value)
            XCTAssertFalse(value.localizedDescription.isEmpty)
        }
        XCTAssertNil(SigningAuthenticationFailure(wire: "pinIncorrect"))
        XCTAssertNil(SigningAuthenticationFailure(wire: "auth.unknown"))
    }

    func testIncorrectPINIsAnOrdinaryFailureAndKeepsTheSnapshot() throws {
        try withJob(phase: 8, effect: 10) { job, mock in
            let operation = SigningOperation()
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "wrong-fixture", operation: operation)) {
                XCTAssertEqual($0 as? SigningAuthenticationFailure, .pinIncorrect)
            }
            XCTAssertEqual(operation.state, .failed)
            XCTAssertEqual(audit(mock, "8"), 1); XCTAssertEqual(audit(mock, "16"), 0)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
            XCTAssertFalse(job.snapshot.isRetired)
            XCTAssertEqual(try job.verifiedBytes(), Data("Approved synthetic bytes".utf8))
        }
    }

    func testOtherLoginRefusalIsNotUncertainAndRetiresTheSnapshot() throws {
        try withJob(phase: 8, effect: 4) { job, mock in
            let operation = SigningOperation()
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation)) {
                XCTAssertEqual($0 as? SigningAuthenticationFailure, .notSigned)
            }
            XCTAssertEqual(operation.state, .failed)
            XCTAssertEqual(audit(mock, "16"), 0)
            XCTAssertTrue(job.snapshot.isRetired)
        }
    }

    func testFailureAfterSignRemainsUncertain() throws {
        try withJob(phase: 16, effect: 4) { job, mock in
            let operation = SigningOperation()
            XCTAssertThrowsError(try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: operation)) {
                guard case SignumError.outputUncertain = $0 else { return XCTFail("expected uncertain, got \($0)") }
            }
            XCTAssertEqual(operation.state, .outcomeUncertain)
            XCTAssertEqual(audit(mock, "16"), 1)
        }
    }

    func testBundledCMSVerificationRejectsTamperedContent() throws {
        try withJob { job, _ in
            try job.signCAdES(using: worker, pin: "synthetic-fixture", operation: SigningOperation())
            let signed = try Data(contentsOf: job.destination)
            XCTAssertEqual(try CAdESVerifier.verifiedContent(signed), Data("Approved synthetic bytes".utf8))
            let marker = Data("Approved".utf8)
            let range = try XCTUnwrap(signed.range(of: marker))
            var tampered = signed; tampered.replaceSubrange(range, with: Data("Approvex".utf8))
            XCTAssertThrowsError(try CAdESVerifier.verifiedContent(tampered))
            XCTAssertThrowsError(try CAdESVerifier.verifyAttached(data: tampered, expectedDocument: Data("Approvex synthetic bytes".utf8)))
            XCTAssertThrowsError(try CAdESVerifier.verifiedContent(signed + Data([0])))
            XCTAssertThrowsError(try CAdESVerifier.verifiedContent(Data("not cms".utf8)))
        }
    }
}
#endif
