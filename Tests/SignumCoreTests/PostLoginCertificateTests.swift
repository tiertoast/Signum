#if os(macOS)
import XCTest
import Darwin
import CPKCS11
@testable import SignumCore

final class PostLoginCertificateTests: XCTestCase {
    private func call(_ context: OpaquePointer?, approved: Data, encoded: Bool) -> Int32 {
        let id: [UInt8] = [0x53], secret: [UInt8] = [1]
        let message: [UInt8] = encoded ? [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20] + Array(repeating: 0, count: 32) : [1]
        var output = [UInt8](repeating: 0xAA, count: 8192), length = 123, error = [CChar](repeating: 0, count: 512)
        let status = approved.withUnsafeBytes { bytes in
            (encoded ? sg_sign_encoded_digest_checked : sg_sign_test_checked)(context, 7, id, 1,
                bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, secret, 1, message, message.count,
                &output, output.count, &length, &error, error.count)
        }
        if status != 0 { XCTAssertEqual(length, 0); XCTAssertTrue(output.allSatisfy { $0 == 0 }) }
        return status
    }
    func testPostUSERCheckpointRejectsChangedMissingIneligibleAndInvalidSessionBeforeSignInit() throws {
        let fixtures = try CertificateEligibilityTests.fixtures.get(), approved = fixtures.der("valid")
        for encoded in [false, true] {
            for scenario in 0...4 {
                let mock = try MockModule(certificate: approved, alwaysAuth: true, strictContext: true)
                var context: OpaquePointer?, error = [CChar](repeating: 0, count: 512)
                XCTAssertEqual(sg_open(mock.path.path, &context, &error, error.count), 0)
                defer { sg_close(context) }
                let action = unsafeBitCast(try XCTUnwrap(dlsym(mock.library, "mock_after_user_login")), to: (@convention(c) (Int32) -> Void).self)
                if scenario == 1 || scenario == 4 {
                    let replacement = fixtures.der(scenario == 1 ? "replaced" : "expired")
                    replacement.withUnsafeBytes { mock.replaceCertificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count, UInt32.max) }
                }
                action(Int32(scenario == 4 ? 1 : scenario))
                let status = call(context, approved: approved, encoded: encoded)
                XCTAssertEqual(status == 0, scenario == 0, "scenario \(scenario), encoded \(encoded)")
                XCTAssertEqual(mock.count(8), 1)
                XCTAssertEqual(mock.count(15), scenario == 0 ? 1 : 0)
                XCTAssertEqual(mock.count(9), scenario == 0 ? 1 : 0)
                XCTAssertEqual(mock.count(16), scenario == 0 ? 1 : 0)
            }
        }
    }
    func testSyntheticCheckedSigningCheckpointCost() throws {
        let approved = try CertificateEligibilityTests.fixtures.get().der("valid"), mock = try MockModule()
        approved.withUnsafeBytes { mock.setCertificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count) }
        var context: OpaquePointer?, error = [CChar](repeating: 0, count: 512)
        XCTAssertEqual(sg_open(mock.path.path, &context, &error, error.count), 0); defer { sg_close(context) }
        let begin = ProcessInfo.processInfo.systemUptime
        for _ in 0..<100 { XCTAssertEqual(call(context, approved: approved, encoded: false), 0) }
        print("SYNTHETIC_CHECKPOINT_100_SECONDS=\(ProcessInfo.processInfo.systemUptime - begin)")
        XCTAssertEqual(mock.count(16), 100)
    }
}
#endif
