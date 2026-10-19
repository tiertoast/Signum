#if os(macOS)
import Foundation
import Darwin

/// Test harness only. Never changes product timeouts or process ownership.
enum FixtureProcess {
    struct Timeout: Error, LocalizedError {
        let command: String
        var errorDescription: String? { "Fixture process exceeded its deadline: " + command }
    }
    static func wait(_ process: Process, timeout: TimeInterval = 30) throws {
        let end = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning, ProcessInfo.processInfo.systemUptime < end { Thread.sleep(forTimeInterval:0.005) }
        guard process.isRunning else { return }
        _ = kill(process.processIdentifier,SIGKILL)
        let reap = ProcessInfo.processInfo.systemUptime + 2
        while process.isRunning, ProcessInfo.processInfo.systemUptime < reap { Thread.sleep(forTimeInterval:0.005) }
        throw Timeout(command: process.executableURL?.lastPathComponent ?? "unknown")
    }
}
enum FixtureFiles {
    static func directory(_ name: String, evidence: Bool = false) throws -> URL {
        let key = evidence ? "SIGNUM_TEST_EVIDENCE_ROOT" : "SIGNUM_TEST_FIXTURE_ROOT"
        let root = ProcessInfo.processInfo.environment[key].map { URL(fileURLWithPath:$0) } ?? FileManager.default.temporaryDirectory.appendingPathComponent("SignumTests")
        let folder = root.appendingPathComponent(name+"-"+UUID().uuidString,isDirectory:true)
        try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let canonical = realpath(folder.path,nil)
        guard let canonical else { throw CocoaError(.fileNoSuchFile) }
        defer { free(canonical) }
        return URL(fileURLWithPath:String(cString:canonical),isDirectory:true)
    }
}
enum FixtureRequirements {
    static func helper() throws -> String {
        guard let path = ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"], FileManager.default.isExecutableFile(atPath:path) else {
            throw NSError(domain:"SignumTestSetup",code:1,userInfo:[NSLocalizedDescriptionKey:"Missing native PAdES helper. Run scripts/test-local.py --group swift with --native-prefix, --cmake, --ctest and --poppler."])
        }
        return path
    }
}
#endif

/// Mutable observations from Sendable fixture callbacks use the same real lock
/// for reads and writes. The value never escapes while it is being mutated.
final class FixtureLocked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Value
    init(_ value: Value) { storage = value }
    func withValue<Result>(_ body: (inout Value) throws -> Result) rethrows -> Result {
        lock.lock(); defer { lock.unlock() }; return try body(&storage)
    }
}
