#if os(macOS)
import XCTest
@testable import SignumApp

final class AppVersionTests: XCTestCase {
    func testVersionAndBuildFollowBundleMetadataWithoutAssumingChannel() {
        XCTAssertEqual(AppVersion.label(info: ["CFBundleShortVersionString": "0.3.3", "CFBundleVersion": "1"]), "0.3.3 · build 1")
        XCTAssertEqual(AppVersion.label(info: ["CFBundleShortVersionString": "0.4.7", "CFBundleVersion": "42"]), "0.4.7 · build 42")
        XCTAssertEqual(AppVersion.label(info: ["CFBundleShortVersionString": "0.4.7"]), "0.4.7")
    }
    func testUnbundledDevelopmentExecutableDoesNotInventVersion() {
        XCTAssertEqual(AppVersion.label(info: nil), "Build di sviluppo")
        XCTAssertEqual(AppVersion.label(info: ["CFBundleShortVersionString": " "]), "Build di sviluppo")
    }
}
#endif
