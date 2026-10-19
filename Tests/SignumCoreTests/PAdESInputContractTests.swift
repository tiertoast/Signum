#if os(macOS)
import XCTest
@testable import SignumCore

final class PAdESInputContractTests: XCTestCase {
    func testAcceptedSyntheticBytesAreUnchangedAndUnrepresentableValuesRejected() throws {
        for value in ["synthetic", "é漢字", String(repeating: "X", count: 64)] {
            XCTAssertTrue(PAdESInputContract.validPIN(value))
            let frame = try PAdESInputContract.pinLine(value)
            XCTAssertEqual(Data(frame.dropLast()), Data(value.utf8)); XCTAssertEqual(frame.last, 10)
        }
        for value in ["", String(repeating: "X", count: 65), "X\0Y", "X\rY", "X\nY", "\n"] {
            XCTAssertFalse(PAdESInputContract.validPIN(value))
            XCTAssertThrowsError(try PAdESInputContract.pinLine(value))
        }
    }
}
#endif
