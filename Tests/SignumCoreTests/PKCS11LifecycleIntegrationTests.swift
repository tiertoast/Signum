#if os(macOS)
import XCTest
import Foundation
import Darwin
@testable import SignumCore

// Compiles only our synthetic provider, never loads installed middleware.
final class MockModule: @unchecked Sendable {
    let folder: URL
    let path: URL
    let library: UnsafeMutableRawPointer
    let setCertificate: @convention(c) (UnsafePointer<UInt8>?, Int) -> Void
    let replaceCertificate: @convention(c) (UnsafePointer<UInt8>?, Int, UInt32) -> Void
    let count: @convention(c) (Int32) -> UInt32
    let finalizeOnMain: @convention(c) () -> UInt32
    let block: @convention(c) (Int32) -> Void
    let waitBlocked: @convention(c) () -> Int32
    let release: @convention(c) () -> Void

    init(certificate: Data? = nil, privateKey: Data? = nil, workerPhase: Int? = nil, workerEffect: Int = 0, audit: Bool = false) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        folder = root.appendingPathComponent(".build/swift-provider-tests/" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        path = folder.appendingPathComponent("mock.dylib")
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
        compiler.arguments = ["-dynamiclib", "-pthread", "-I", root.appendingPathComponent("Sources/CPKCS11").path,
                              root.appendingPathComponent("Tools/PKCS11Tests/mock_provider.c").path, "-o", path.path]
        if audit {
            compiler.arguments! += ["-DSIGNUM_MOCK_AUDIT_PATH=" + String(reflecting: folder.appendingPathComponent("operations").path)]
        }
        if let workerPhase {
            compiler.arguments! += ["-DSIGNUM_MOCK_WORKER_PHASE=\(workerPhase)", "-DSIGNUM_MOCK_WORKER_EFFECT=\(workerEffect)"]
        }
        if let certificate {
            let header = folder.appendingPathComponent("public-certificate.h")
            let encoded = certificate.map { String($0) }.joined(separator: ",")
            try Data(("#define SIGNUM_MOCK_BOOTSTRAP_CERTIFICATE 1\nstatic const unsigned char bootstrap_certificate[] = {" + encoded + "};\n").utf8).write(to: header)
            if let privateKey {
                let encodedKey = privateKey.map { String($0) }.joined(separator: ",")
                let addition = "#define SIGNUM_MOCK_SOFTWARE_KEY 1\nstatic const unsigned char bootstrap_private_key[] = {" + encodedKey + "};\n"
                let handle = try FileHandle(forWritingTo: header); try handle.seekToEnd(); try handle.write(contentsOf: Data(addition.utf8)); try handle.close()
                compiler.arguments! += ["-framework", "Security", "-framework", "CoreFoundation"]
            }
            compiler.arguments! += ["-include", header.path]
        }
        compiler.standardOutput = FileHandle.nullDevice
        try compiler.run()
        compiler.waitUntilExit()
        guard compiler.terminationStatus == 0, let handle = dlopen(path.path, RTLD_NOW | RTLD_LOCAL) else {
            throw SignumError.module("Cannot compile/load synthetic provider")
        }
        library = handle
        func symbol<T>(_ name: String, _: T.Type) throws -> T {
            guard let value = dlsym(handle, name) else { throw SignumError.module("Missing mock control") }
            return unsafeBitCast(value, to: T.self)
        }
        setCertificate = try symbol("mock_certificate_der", (@convention(c) (UnsafePointer<UInt8>?, Int) -> Void).self)
        replaceCertificate = try symbol("mock_replace_certificate", (@convention(c) (UnsafePointer<UInt8>?, Int, UInt32) -> Void).self)
        count = try symbol("mock_call_count", (@convention(c) (Int32) -> UInt32).self)
        finalizeOnMain = try symbol("mock_finalize_on_main", (@convention(c) () -> UInt32).self)
        block = try symbol("mock_block", (@convention(c) (Int32) -> Void).self)
        waitBlocked = try symbol("mock_wait_blocked", (@convention(c) () -> Int32).self)
        release = try symbol("mock_release", (@convention(c) () -> Void).self)
    }
    deinit { dlclose(library); try? FileManager.default.removeItem(at: folder) }
}

final class PKCS11LifecycleIntegrationTests: XCTestCase {
    private func eventually(_ predicate: () -> Bool, timeout: TimeInterval = 3, file: StaticString = #filePath, line: UInt = #line) {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !predicate(), ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.005) }
        XCTAssertTrue(predicate(), file: file, line: line)
    }
    func testSwiftContextsUseCanonicalOwnerAndRemainUsable() throws {
        let mock = try MockModule()
        let alias = mock.folder.appendingPathComponent("alias.dylib")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: mock.path)
        var first: PKCS11Module? = try PKCS11Module(path: mock.path.path)
        var second: PKCS11Module? = try PKCS11Module(path: alias.path)
        XCTAssertEqual(first?.modulePath, second?.modulePath)
        XCTAssertEqual(mock.count(0), 1) // C_Initialize
        first = nil
        XCTAssertEqual(try second?.scanTokens().tokens.first?.slot, 7)
        XCTAssertEqual(mock.count(1), 0) // no premature C_Finalize
        second = nil
        eventually { mock.count(1) == 1 }
        XCTAssertEqual(mock.finalizeOnMain(), 0)
    }
    func testBlockedFinalizationDoesNotHoldOtherProvidersOnReleaseQueue() throws {
        let slow = try MockModule(), other = try MockModule()
        var first: PKCS11Module? = try PKCS11Module(path: slow.path.path)
        var second: PKCS11Module? = try PKCS11Module(path: other.path.path)
        XCTAssertNotEqual(first?.modulePath, second?.modulePath)
        slow.block(1)
        defer { slow.release() }
        first = nil
        XCTAssertEqual(slow.waitBlocked(), 1)
        second = nil
        eventually({ other.count(1) == 1 }, timeout: 1)
        XCTAssertEqual(other.finalizeOnMain(), 0)
    }
    func testMainQueueContinuesWhileVendorFinalizationIsBlocked() throws {
        let mock = try MockModule()
        mock.block(1) // C_Finalize
        defer { mock.release() }
        // Watchdog prevents a faulty synchronous deinit from hanging the suite.
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { mock.release() }
        let returned = expectation(description: "main queue returned from releasing provider")
        DispatchQueue.main.async {
            do {
                var module: PKCS11Module? = try PKCS11Module(path: mock.path.path)
                XCTAssertEqual(module?.modulePath, mock.path.path)
                module = nil
            } catch { XCTFail(error.localizedDescription) }
            returned.fulfill()
        }
        wait(for: [returned], timeout: 3)
        XCTAssertEqual(mock.waitBlocked(), 1)
        XCTAssertEqual(mock.finalizeOnMain(), 0)
    }
}
#endif
