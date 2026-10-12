import XCTest
@testable import SignumCore

final class SignumCoreTests: XCTestCase {
    func testTokenIdentityUsesSlot() {
        let token = SignumToken(slot: 7, label: "Test", manufacturer: "Vendor", model: "Model")
        XCTAssertEqual(token.id, 7)
    }
    func testCertificateIdentifierIsUppercaseHex() {
        let cert = SignumCertificate(label: "DS3", identifier: Data([0x44, 0x53, 0x33]))
        XCTAssertEqual(cert.id, "445333")
    }
    func testRejectsNonAbsoluteModules() {
        XCTAssertThrowsError(try PKCS11Module(path: "relative/module.dylib"))
    }
}
