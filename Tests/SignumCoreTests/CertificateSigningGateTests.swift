#if os(macOS)
import XCTest
import Foundation
import Darwin
import CPKCS11
@testable import SignumCore

final class CertificateSigningGateTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data { try CertificateEligibilityTests.fixtures.get().der(name) }
    private func install(_ data: Data, in mock: MockModule) {
        data.withUnsafeBytes { mock.setCertificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count) }
    }
    func testCoreRejectsUnfitAndIndeterminateBeforeAnyPINSubmission() throws {
        let mock = try MockModule(), module = try PKCS11Module(path: mock.path.path)
        let certificate = try XCTUnwrap(module.certificates(slot: 7).first)
        for name in ["expired", "future", "authentication", "wrongKU", "wrongEKU", "ec", "pss", "missingKU", "unknownEKU", "criticalUnknown"] {
            install(try fixture(name), in: mock)
            XCTAssertThrowsError(try module.createCAdES(document: Data("Synthetic".utf8), slot: 7,
                                                       certificate: certificate, pin: "synthetic-test-value"), name)
            XCTAssertThrowsError(try module.signAndVerifyTest(slot: 7, certificate: certificate, pin: "synthetic-test-value"), name)
        }
        install(Data([0x30, 0]), in: mock)
        XCTAssertThrowsError(try module.createCAdES(document: Data([1]), slot: 7, certificate: certificate, pin: "synthetic-test-value"))
        XCTAssertEqual(mock.count(8), 0) // USER login
        XCTAssertEqual(mock.count(9), 0) // CONTEXT login
        XCTAssertEqual(mock.count(15), 0) // SignInit
        XCTAssertEqual(mock.count(6), mock.count(5)) // sessions all closed
    }
    func testCertificateReplacedAfterCoreReadIsRejectedUnderProviderLock() throws {
        let mock = try MockModule(), module = try PKCS11Module(path: mock.path.path)
        let approved = try fixture("valid"), replacement = try fixture("replaced")
        install(approved, in: mock)
        replacement.withUnsafeBytes { mock.replaceCertificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count, 1) }
        let certificate = try XCTUnwrap(module.certificates(slot: 7).first)
        XCTAssertThrowsError(try module.createCAdES(document: Data([1]), slot: 7, certificate: certificate,
                                                   pin: "synthetic-test-value", expectedCertificateDER: approved)) {
            XCTAssertTrue($0.localizedDescription.contains("cambiato"))
        }
        XCTAssertEqual(mock.count(8), 0); XCTAssertEqual(mock.count(16), 0)
        XCTAssertEqual(mock.count(6), mock.count(5))
    }
    func testEligibleCertificateReachesExactlyOneSyntheticSigningAttempt() throws {
        let mock = try MockModule(), module = try PKCS11Module(path: mock.path.path)
        let approved = try fixture("valid"); install(approved, in: mock)
        let certificate = try XCTUnwrap(module.certificates(slot: 7).first)
        // Mock signatures are deliberately not cryptographic: the existing final
        // verification must reject the fake bytes, even though policy passed.
        XCTAssertThrowsError(try module.createCAdES(document: Data([1]), slot: 7, certificate: certificate,
                                                   pin: "synthetic-test-value", expectedCertificateDER: approved))
        XCTAssertEqual(mock.count(8), 1); XCTAssertEqual(mock.count(16), 1)
        XCTAssertEqual(mock.count(10), 0); XCTAssertEqual(mock.count(6), mock.count(5))
    }
    func testCLIRejectsMalformedMockCertificateBeforePINPrompt() throws {
        let mock = try MockModule()
        let cli = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumCLI")
        let process = Process(); process.executableURL = cli
        process.arguments = ["sign-test", "7", "53", mock.path.path]
        let input = Pipe(), output = Pipe(), diagnostics = Pipe()
        process.standardInput = input; process.standardOutput = output; process.standardError = diagnostics
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL); XCTFail("CLI waited for credentials") }
        process.waitUntilExit()
        try input.fileHandleForWriting.close()
        let reason = String(decoding: diagnostics.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 1)
        XCTAssertTrue(reason.contains("malformato"), reason)
        XCTAssertFalse(reason.contains("Token PIN"))
    }
    func testNativeCheckedEntryPointsCannotBypassPolicy() throws {
        let mock = try MockModule()
        var context: OpaquePointer?
        var diagnostics = [CChar](repeating: 0, count: 512)
        XCTAssertEqual(sg_open(mock.path.path, &context, &diagnostics, diagnostics.count), 0)
        defer { sg_close(context) }
        let id: [UInt8] = [0x53], fakeSecret: [UInt8] = [1], message: [UInt8] = [1]
        var signature = [UInt8](repeating: 0xaa, count: 8192), length = 123
        let digest: [UInt8] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20] + Array(repeating: 0, count: 32)
        for name in ["expired", "authentication", "unknownEKU"] {
            let bytes = try fixture(name); install(bytes, in: mock)
            bytes.withUnsafeBytes { expected in
                let der = expected.bindMemory(to: UInt8.self).baseAddress
                XCTAssertNotEqual(sg_sign_test_checked(context, 7, id, id.count, der, bytes.count,
                                                      fakeSecret, fakeSecret.count, message, message.count,
                                                      &signature, signature.count, &length, &diagnostics, diagnostics.count), 0)
                XCTAssertEqual(length, 0); XCTAssertTrue(signature.allSatisfy { $0 == 0 })
                XCTAssertNotEqual(sg_sign_encoded_digest_checked(context, 7, id, id.count, der, bytes.count,
                                                                fakeSecret, fakeSecret.count, digest, digest.count,
                                                                &signature, signature.count, &length, &diagnostics, diagnostics.count), 0)
            }
        }
        XCTAssertEqual(mock.count(8), 0); XCTAssertEqual(mock.count(16), 0)
        XCTAssertEqual(mock.count(6), mock.count(5))
    }
}
#endif
