#if os(macOS)
import XCTest
import CPKCS11
@testable import SignumCore

final class SecureBatchNativeTests: XCTestCase {
    func fixture(always: Bool = true, _ body: (MockModule, OpaquePointer, () -> OpaquePointer?, (Bool, Double) -> Int32) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), alwaysAuth: always)
        var ctx: OpaquePointer?, session: OpaquePointer?, diagnostics = [CChar](repeating: 0, count: 512)
        XCTAssertEqual(sg_open(mock.path.path, &ctx, &diagnostics, diagnostics.count), 0)
        let context = try XCTUnwrap(ctx)
        defer { _ = sg_batch_close(session, &diagnostics, diagnostics.count); sg_close(context) }
        let message = try CAdES.Prepared(document: Data("Native synthetic".utf8), certificateDER: signer.der).attributesToSign
        let secret = Array("synthetic-only".utf8)
        var first = true
        func sign(usePIN: Bool, deadline: Double) -> Int32 {
            var output = [UInt8](repeating: 0, count: 8192), length = 0, reusable: Int32 = 0
            let result = signer.der.withUnsafeBytes { der in message.withUnsafeBytes { bytes in secret.withUnsafeBufferPointer { pin in
                if first {
                    first = false
                    var id: UInt8 = 1
                    return sg_batch_first_temporary(context, 7, "SYNTHETIC-0001", &id, 1,
                        der.bindMemory(to: UInt8.self).baseAddress, der.count, pin.baseAddress, pin.count, deadline,
                        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &session, &reusable,
                        &output, output.count, &length, &diagnostics, diagnostics.count)
                }
                return sg_batch_next_temporary(session, usePIN ? pin.baseAddress : nil, usePIN ? pin.count : 0,
                    bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &output, output.count, &length, &diagnostics, diagnostics.count)
            }}}
            return result
        }
        try body(mock, context, { session }, sign)
    }
    func testContextAuthenticationOccursForEveryApprovedSignature() throws {
        try fixture { mock, _, session, sign in
            for _ in 0..<3 { XCTAssertEqual(sign(true, sg_batch_monotonic_now() + 30), 0) }
            XCTAssertEqual(sg_batch_requires_pin(session()), 1)
            XCTAssertEqual(mock.count(8), 1); XCTAssertEqual(mock.count(9), 3); XCTAssertEqual(mock.count(16), 3)
        }
    }
    func testFalseAttributeNeverRepeatsLoginAndDoesNotNeedRetainedPIN() throws {
        try fixture(always: false) { mock, _, session, sign in
            XCTAssertEqual(sign(true, sg_batch_monotonic_now() + 30), 0)
            XCTAssertEqual(sg_batch_requires_pin(session()), 0)
            XCTAssertEqual(sign(false, 0), 0); XCTAssertEqual(sign(false, 0), 0)
            XCTAssertEqual(mock.count(8), 1); XCTAssertEqual(mock.count(9), 0); XCTAssertEqual(mock.count(16), 3)
        }
    }
    func testPINFailuresAreTerminalAndNeverRetried() throws {
        for rv: UInt in [0xa0, 0xa3, 0xa4, 5] {
            try fixture { mock, _, _, sign in
                XCTAssertEqual(sign(true, sg_batch_monotonic_now() + 30), 0)
                let fail = unsafeBitCast(dlsym(mock.library, "mock_fail"), to: (@convention(c) (Int32, UInt) -> Void).self)
                fail(9, rv)
                XCTAssertNotEqual(sign(true, 0), 0); XCTAssertNotEqual(sign(true, 0), 0)
                XCTAssertEqual(mock.count(9), 2); XCTAssertEqual(mock.count(16), 1)
            }
        }
    }
    func testExpiredInitialPINCannotAttemptUSERLogin() throws {
        try fixture { mock, _, _, sign in
            XCTAssertNotEqual(sign(true, sg_batch_monotonic_now() - 1), 0)
            XCTAssertEqual(mock.count(8), 0); XCTAssertEqual(mock.count(16), 0)
        }
    }
    func testAuthenticationPolicyChangeRetiresTheSession() throws {
        try fixture { mock, _, _, sign in
            XCTAssertEqual(sign(true, sg_batch_monotonic_now() + 30), 0)
            let change = unsafeBitCast(dlsym(mock.library, "mock_always_authenticate"), to: (@convention(c) (Int32) -> Void).self)
            change(0)
            XCTAssertNotEqual(sign(true, 0), 0); XCTAssertNotEqual(sign(true, 0), 0)
            XCTAssertEqual(mock.count(9), 1); XCTAssertEqual(mock.count(16), 1)
        }
    }
}
#endif
