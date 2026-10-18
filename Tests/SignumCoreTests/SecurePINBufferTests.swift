#if os(macOS)
import XCTest
import Darwin
import CSecurePIN

final class SecurePINBufferTests: XCTestCase {
    func testOwnedPageIsLockedBoundedAndExplicitlyCleared() throws {
        let context = try XCTUnwrap(sg_secure_pin_create()); defer { sg_secure_pin_destroy(context) }
        let fixture = Array("synthetic-only".utf8)
        XCTAssertEqual(fixture.withUnsafeBufferPointer { sg_secure_pin_set(context, $0.baseAddress, $0.count) }, 0)
        let pointer = try XCTUnwrap(sg_secure_pin_bytes(context))
        XCTAssertEqual(Array(UnsafeBufferPointer(start: pointer, count: fixture.count)), fixture)
        sg_secure_pin_clear(context)
        XCTAssertEqual(Array(UnsafeBufferPointer(start: pointer, count: 64)), [UInt8](repeating: 0, count: 64))
        XCTAssertNil(sg_secure_pin_bytes(context)); XCTAssertEqual(sg_secure_pin_length(context), 0)
        for bytes in [[], [0], [65, 0, 66], Array(repeating: UInt8(1), count: 65)] as [[UInt8]] {
            XCTAssertEqual(bytes.withUnsafeBufferPointer { sg_secure_pin_set(context, $0.baseAddress, $0.count) }, -1)
            XCTAssertEqual(sg_secure_pin_length(context), 0)
        }
        for _ in 0..<100 { let p = try XCTUnwrap(sg_secure_pin_create()); sg_secure_pin_destroy(p) }
    }
    func testBinaryReceiptBoundsTruncationNULAndTimeoutClearPartialSecret() throws {
        for frame: [UInt8] in [[0,0,0,3,65,66,67], [0,0,0,65], [0,0,0,0], [0,0,0,3,65], [0,0,0,3,65,0,67]] {
            let context = try XCTUnwrap(sg_secure_pin_create()); defer { sg_secure_pin_destroy(context) }
            var fds = [Int32](repeating: -1, count: 2); XCTAssertEqual(pipe(&fds), 0)
            defer { close(fds[0]); close(fds[1]) }
            _ = frame.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, $0.count) }
            let status = sg_secure_pin_receive(context, fds[0], 0.03)
            XCTAssertEqual(status, frame == [0,0,0,3,65,66,67] ? 0 : -1)
            if status != 0 { XCTAssertNil(sg_secure_pin_bytes(context)); XCTAssertEqual(sg_secure_pin_length(context), 0) }
        }
    }
    func testLockFailureRefusesAllocationInAnIsolatedProcess() throws {
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("probe.c"), executable = folder.appendingPathComponent("probe")
        try """
        #include <sys/resource.h>
        #include "SignumSecurePIN.h"
        int main(void) {
            struct rlimit limit = {0,0};
            if (setrlimit(RLIMIT_MEMLOCK, &limit)) return 2;
            SGSecurePIN *p = sg_secure_pin_create();
            if (p) { sg_secure_pin_destroy(p); return 3; }
            return 0;
        }
        """.write(to: source, atomically: false, encoding: .utf8)
        let cc = Process(); cc.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
        cc.arguments = [source.path, repo.appendingPathComponent("Sources/CSecurePIN/secure_pin.c").path,
            "-I", repo.appendingPathComponent("Sources/CSecurePIN/include").path, "-o", executable.path]
        try cc.run(); cc.waitUntilExit(); XCTAssertEqual(cc.terminationStatus, 0)
        let probe = Process(); probe.executableURL = executable
        try probe.run(); probe.waitUntilExit(); XCTAssertEqual(probe.terminationStatus, 0)
    }
}
#endif
