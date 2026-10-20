#if os(macOS)
import XCTest
@testable import SignumCore
final class FixtureInfrastructureTests: XCTestCase {
    func testEvidenceDirectoriesArePreparedAndNeverReused() throws {
        let first = try FixtureFiles.directory("fixture-infrastructure",evidence:true)
        let second = try FixtureFiles.directory("fixture-infrastructure",evidence:true)
        defer { try? FileManager.default.removeItem(at:first);try? FileManager.default.removeItem(at:second) }
        XCTAssertNotEqual(first,second)
        try Data("first".utf8).write(to:first.appendingPathComponent("same.png"))
        try Data("second".utf8).write(to:second.appendingPathComponent("same.png"))
        XCTAssertEqual(try String(contentsOf:first.appendingPathComponent("same.png")),"first")
    }
    func testFixtureProcessDeadlineKillsNonrespondingChild() throws {
        let process = Process();process.executableURL = URL(fileURLWithPath:"/bin/sleep");process.arguments = ["30"]
        try process.run()
        XCTAssertThrowsError(try FixtureProcess.wait(process,timeout:0.02))
        XCTAssertFalse(process.isRunning)
    }
}
#endif
