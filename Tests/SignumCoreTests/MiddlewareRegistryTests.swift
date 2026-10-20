import XCTest
@testable import SignumCore

final class MiddlewareRegistryTests: XCTestCase {
    func testKnownCandidatesAreLimitedAndDistinct() {
        XCTAssertEqual(MiddlewareRegistry.known.map(\.id), ["bit4id", "opensc"])
        XCTAssertEqual(MiddlewareRegistry.known.flatMap(\.candidatePaths), [
            "/Library/bit4id/pkcs11/libbit4xpki.dylib", "/Library/OpenSC/lib/opensc-pkcs11.so"])
        XCTAssertEqual(Set(MiddlewareRegistry.known.map(\.id)).count, 2)
    }
    func testRegistryCanExtendWithoutSigningEngineChanges() {
        let candidate = MiddlewareDefinition(id: "synthetic", name: "Synthetic", manufacturer: "Test", candidatePaths: ["/synthetic/test.dylib"])
        XCTAssertEqual((MiddlewareRegistry.known + [candidate]).last, candidate)
    }
}
