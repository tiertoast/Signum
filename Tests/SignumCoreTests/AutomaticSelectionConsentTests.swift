#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class AutomaticSelectionConsentTests: XCTestCase {
    func testRefreshRevokesDisplayedReviewAndApprovedJobNeverFollowsNewSelection() async throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false);defer{try? FileManager.default.removeItem(at:root)}
        let file=root.appendingPathComponent("synthetic.txt");try Data("Approved bytes".utf8).write(to:file)
        let batch=BatchSigningCoordinator();defer{batch.reset()};await batch.addDocuments([file],format:.cades)
        let f=DeviceSelectionTests(),der=try CertificateEligibilityTests.fixtures.get().der("valid")
        var devices=DeviceSelection();let initial=devices.beginDiscovery();devices.acceptCompleteFixture([f.provider(der:der)],request:initial)
        let route=try XCTUnwrap(devices.selectedRoute);XCTAssertEqual(devices.selectionOrigin,.automatic)
        let review=SigningReview()
        func context()->SigningReviewContext? {
            guard let r=devices.selectedRoute else {return nil}
            return .init(revision:batch.revision,provider:r.providerPath,slot:r.token.slot,certificate:r.certificate,der:r.der,
                destination:.originalFolders,routeID:r.id,discoveryID:devices.requestID)
        }
        await review.prepare(context(),batch:batch,validate:{})
        let old=try XCTUnwrap(review.approval)
        let refresh=devices.beginDiscovery();batch.invalidateReview()
        XCTAssertNil(context());XCTAssertThrowsError(try batch.freezeReview(old))
        await review.prepare(nil,batch:batch,validate:{XCTFail("No credential during refresh")})
        XCTAssertNil(review.approval);XCTAssertFalse(batch.isApproved)
        devices.acceptCompleteFixture([f.provider(der:der)],request:refresh)
        await review.prepare(context(),batch:batch,validate:{})
        let approved=try XCTUnwrap(review.approval);try batch.freezeReview(approved);try batch.confirm(approved)
        let identity=approved.jobs[0].id
        let later=devices.beginDiscovery();devices.acceptCompleteFixture([f.provider("other",der:try CertificateEligibilityTests.fixtures.get().der("replaced"),slot:99)],request:later)
        // The real GUI prohibits refresh while frozen; even an independent
        // selection value cannot mutate these already approved Core jobs.
        await review.prepare(context(),batch:batch,validate:{XCTFail("Frozen job must not be prepared again")})
        XCTAssertEqual(batch.approval?.jobs[0].id,identity)
        XCTAssertEqual(batch.approval?.jobs[0].certificateDER,der)
        XCTAssertEqual(batch.approval?.jobs[0].slot,7)
        XCTAssertEqual(batch.approval?.jobs[0].providerPath,route.providerPath)
        XCTAssertFalse(FileManager.default.fileExists(atPath:approved.jobs[0].destination.path))
    }
    func testAvailabilityFailureLeavesNoApprovalAndReportsExplicitInvalidationState() async throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false);defer{try? FileManager.default.removeItem(at:root)}
        let file=root.appendingPathComponent("synthetic.txt");try Data("Synthetic bytes".utf8).write(to:file)
        let batch=BatchSigningCoordinator();defer{batch.reset()};await batch.addDocuments([file],format:.cades)
        let review=SigningReview(),context=SigningReviewContext(revision:batch.revision,provider:"/synthetic/provider",slot:7,
            certificate:.init(label:"Synthetic",identifier:Data([1])),der:try CertificateEligibilityTests.fixtures.get().der("valid"),destination:.originalFolders,routeID:"observed",discoveryID:UUID())
        await review.prepare(context,batch:batch,validate:{throw DeviceCertificateRoute.AvailabilityFailure.unavailable})
        XCTAssertTrue(review.credentialUnavailable);XCTAssertFalse(review.issue.isEmpty)
        XCTAssertNil(review.approval);XCTAssertNil(batch.review);XCTAssertFalse(batch.isApproved)
        await review.prepare(nil,batch:batch,validate:{})
        XCTAssertFalse(review.credentialUnavailable);XCTAssertNil(review.approval)
    }
}
#endif
