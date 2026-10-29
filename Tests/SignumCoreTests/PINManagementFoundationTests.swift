#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class PINManagementFoundationTests: XCTestCase {
    private func context(generation: UUID = UUID(), serial: String = "SYNTHETIC") -> PINManagementContext {
        var info = stat(); info.st_dev = 1; info.st_ino = 2; info.st_size = 123
        info.st_mtimespec = timespec(tv_sec: 1, tv_nsec: 0); info.st_ctimespec = timespec(tv_sec: 1, tv_nsec: 0)
        let inspection = MiddlewareFileSecurity.Inspection(canonicalPath: "/synthetic/provider", identity: .init(info))
        return .init(provider: inspection.canonicalPath, inspection: inspection, automatic: false,
            token: .init(slot: 7, label: "Synthetic", manufacturer: "Offline", model: "Fixture", reader: "Synthetic reader", serial: serial),
            discoveryID: generation)
    }
    private func request(_ context: PINManagementContext) -> PINManagementWorkerRequest {
        .init(version: 1, id: UUID(), operation: "readPublicStatus", context: context)
    }
    func testPublicContractRoundTripHasNoCredentials() throws {
        let value = request(context())
        let bytes = try JSONEncoder().encode(value)
        XCTAssertTrue(try PINManagementWorkerRequest.decode(bytes).valid)
        let keys = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any]).keys
        XCTAssertEqual(Set(keys), Set(["version", "id", "operation", "context"]))
        XCTAssertFalse(value.context.profile.permitsRealMutation)
        XCTAssertNil(value.context.pinDomain)
    }
    func testMutationOpcodesAndUnknownVersionsAreRejectedBeforeVendorLoad() throws {
        let context = context()
        for operation in ["changePIN", "unblockPIN", "C_SetPIN", "C_InitPIN", "reset"] {
            let value = PINManagementWorkerRequest(version: 1, id: UUID(), operation: operation, context: context)
            XCTAssertThrowsError(try PINManagementWorkerRequest.decode(JSONEncoder().encode(value)))
        }
        let value = PINManagementWorkerRequest(version: 2, id: UUID(), operation: "readPublicStatus", context: context)
        XCTAssertThrowsError(try PINManagementWorkerRequest.decode(JSONEncoder().encode(value)))
    }
    func testUnknownFieldsRejectedAtTopAndNestedLevels() throws {
        let bytes = try JSONEncoder().encode(request(context()))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        object["pin"] = "SYNTHETIC-NOT-A-REAL-PIN"
        XCTAssertThrowsError(try PINManagementWorkerRequest.decode(JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "pin")
        var nested = try XCTUnwrap(object["context"] as? [String: Any]); nested["puk"] = "SYNTHETIC-NOT-A-REAL-PUK"
        object["context"] = nested
        XCTAssertThrowsError(try PINManagementWorkerRequest.decode(JSONSerialization.data(withJSONObject: object)))
    }
    func testContextBindingChangesForGenerationAndTokenReplacement() {
        let generation = UUID(), a = context(generation: generation)
        XCTAssertTrue(a.valid); XCTAssertEqual(a.fingerprint.count, 64)
        XCTAssertNotEqual(a.fingerprint, context().fingerprint)
        XCTAssertNotEqual(a.fingerprint, context(generation: generation, serial: "REPLACED").fingerprint)
        XCTAssertEqual(a.fingerprint, context(generation: generation).fingerprint)
    }
    func testAllProfilesRemainDisabledEvenWithHardwareEvidence() {
        let profile = PINManagementProfile(id: "synthetic-qualified", changeEvidence: .hardwareQualified, unblockEvidence: .hardwareQualified)
        XCTAssertFalse(profile.permitsRealMutation)
    }
    func testConfirmNeverRequestsSecretsOrTouchesSyntheticNonexistentPath() {
        for operation in [PINManagementOperation.changePIN, .unblockPIN] {
            XCTAssertThrowsError(try PINManagementCoordinator.confirm(operation: operation, context: context(), workflowLocked: false)) {
                XCTAssertEqual($0 as? PINManagementFailure, .compatibilityUnverified)
            }
            XCTAssertThrowsError(try PINManagementCoordinator.confirm(operation: operation, context: context(), workflowLocked: true)) {
                XCTAssertEqual($0 as? PINManagementFailure, .busy)
            }
        }
    }
    func testFlagsAreProviderObservationsAndUnknownLimitsStayUnknown() {
        let snapshot = PINStatusSnapshot(version: 1, contextFingerprint: context().fingerprint, readAt: Date(),
            flags: (1 << 18) | (1 << 17), minimumBytes: nil, maximumBytes: nil, moduleVersion: nil)
        XCTAssertTrue(snapshot.valid); XCTAssertTrue(snapshot.userPINLocked); XCTAssertTrue(snapshot.userPINFinalTry)
        XCTAssertNil(snapshot.minimumBytes); XCTAssertNil(snapshot.maximumBytes); XCTAssertFalse(snapshot.limitsConsistent)
        XCTAssertFalse(snapshot.userPINMustChange)
    }
    func testContradictoryBoundsNotCorrectedOrUsedAsPolicy() {
        let snapshot = PINStatusSnapshot(version: 1, contextFingerprint: context().fingerprint, readAt: Date(), flags: 0,
            minimumBytes: 12, maximumBytes: 4, moduleVersion: "1.2")
        XCTAssertTrue(snapshot.valid); XCTAssertFalse(snapshot.limitsConsistent)
        XCTAssertEqual(snapshot.minimumBytes, 12); XCTAssertEqual(snapshot.maximumBytes, 4)
        XCTAssertFalse(snapshot.userPINLocked)
        XCTAssertTrue(snapshot.statusDescription.contains("non è accertata"))
    }
}
#endif
