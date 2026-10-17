#if os(macOS)
import XCTest
@testable import SignumApp
@testable import SignumCore

final class ProviderSelectionTests: XCTestCase {
    private func loaded() throws -> ProviderSelection {
        var selection = ProviderSelection()
        selection.changePath("/synthetic/alias-A.dylib")
        let request = selection.beginDiscovery()
        let certificate = SignumCertificate(label: "Synthetic", identifier: Data([1]))
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        var cache = LoadedCertificates()
        cache.certificates = [certificate]; cache.derByID[certificate.id] = der
        cache.assessments[certificate.id] = CertificateEligibility.evaluate(certificateDER: der)
        cache.identities[certificate.id] = try SignumCertificateIdentity(certificateDER: der)
        XCTAssertTrue(selection.acceptDiscovery(request: request, inputPath: selection.path, canonicalPath: "/synthetic/canonical-A.dylib",
            tokens: [SignumToken(slot: 7, label: "Synthetic", manufacturer: "Synthetic", model: "Mock", reader: "Mock")], slot: 7, certificates: cache))
        selection.pin = "synthetic-fixture"
        return selection
    }
    private func assertInvalidated(_ selection: ProviderSelection, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(selection.signingProvider, file: file, line: line)
        XCTAssertNil(selection.activeModulePath, file: file, line: line)
        XCTAssertNil(selection.selectedSlot, file: file, line: line)
        XCTAssertNil(selection.selectedCertificateID, file: file, line: line)
        XCTAssertTrue(selection.tokens.isEmpty && selection.certificates.isEmpty && selection.pin.isEmpty, file: file, line: line)
        XCTAssertTrue(selection.certificateDERs.isEmpty && selection.certificateAssessments.isEmpty && selection.certificateIdentities.isEmpty, file: file, line: line)
    }
    func testProviderEditAtomicallyClearsSelectionAndSecret() throws {
        var selection = try loaded()
        XCTAssertEqual(selection.signingProvider, "/synthetic/canonical-A.dylib")
        XCTAssertNotNil(selection.selectedCertificateID)
        selection.changePath("/synthetic/B.dylib")
        assertInvalidated(selection)
        // Cancelled discovery never applies a result: A must stay unusable.
        selection.beginDiscovery()
        assertInvalidated(selection)
    }
    func testLateCompletionCannotRestorePreviousProviderEvenAfterChangingBack() throws {
        var selection = try loaded()
        let oldPath = selection.path, oldRequest = selection.beginDiscovery()
        selection.changePath("/synthetic/B.dylib")
        selection.changePath(oldPath)
        XCTAssertFalse(selection.acceptDiscovery(request: oldRequest, inputPath: oldPath,
            canonicalPath: "/synthetic/canonical-A.dylib", tokens: [], slot: 7, certificates: LoadedCertificates()))
        assertInvalidated(selection)
    }
    func testFreshDiscoveryBindsExactVisiblePathToCanonicalProvider() throws {
        var selection = try loaded()
        let path = selection.path, request = selection.beginDiscovery()
        assertInvalidated(selection)
        XCTAssertFalse(selection.acceptDiscovery(request: request, inputPath: "/another/path",
            canonicalPath: "/synthetic/canonical-A.dylib", tokens: [], slot: nil, certificates: LoadedCertificates()))
        XCTAssertTrue(selection.acceptDiscovery(request: request, inputPath: path,
            canonicalPath: "/synthetic/canonical-A.dylib", tokens: [], slot: nil, certificates: LoadedCertificates()))
        XCTAssertEqual(selection.signingProvider, "/synthetic/canonical-A.dylib")
    }
    func testSlotChangeInvalidatesCertificateCacheAndPin() throws {
        var selection = try loaded()
        selection.selectedSlot = 8
        selection.beginCertificateLoad()
        XCTAssertEqual(selection.selectedSlot, 8)
        XCTAssertNil(selection.selectedCertificateID)
        XCTAssertTrue(selection.certificates.isEmpty && selection.certificateDERs.isEmpty && selection.pin.isEmpty)
        XCTAssertEqual(selection.signingProvider, "/synthetic/canonical-A.dylib")
    }
}
#endif
