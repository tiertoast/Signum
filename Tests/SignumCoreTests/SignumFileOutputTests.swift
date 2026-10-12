import XCTest
import Foundation
@testable import SignumCore

#if os(macOS)
final class SignumFileOutputTests: XCTestCase {
    func testCreatesNewP7MWithoutOverwriting() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("signum-output-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let output = directory.appendingPathComponent("prova.txt.p7m")
        let original = Data("First file".utf8)
        try SignumFileOutput.writeNew(original, to: output)
        XCTAssertEqual(try Data(contentsOf: output), original)
        XCTAssertThrowsError(try SignumFileOutput.writeNew(Data("Overwrite".utf8), to: output))
        XCTAssertEqual(try Data(contentsOf: output), original)
    }

    func testRejectsEmptyData() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("signum-empty-test-\(UUID().uuidString).p7m")
        XCTAssertThrowsError(try SignumFileOutput.writeNew(Data(), to: file))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
}
#endif
