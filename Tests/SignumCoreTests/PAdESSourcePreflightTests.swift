#if os(macOS)
import XCTest
import PDFKit
@testable import SignumCore
@testable import SignumApp

final class PAdESSourcePreflightTests: XCTestCase {
    private func fixture(_ body: (URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root, try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map { URL(fileURLWithPath:$0) }))
    }
    func testOrdinaryMultipageRotationsAndSnapshotBinding() throws {
        try fixture { root, helper in
            for rotation in [0,90,180,270] {
                let file = root.appendingPathComponent("input.pdf")
                try PAdESAppearanceTests().pdf(rotation:rotation,pages:rotation == 0 ? 1 : 3).write(to:file)
                let snapshot = try DocumentSnapshot.capture(source:file,format:.pades,privateRoot:root)
                defer { snapshot.close() }
                let result = try PAdESSourcePreflight.inspect(snapshot,helper:helper)
                XCTAssertEqual(result.status,.accepted); XCTAssertEqual(result.sha256,snapshot.identity.sha256)
                try result.requireAccepted(for:snapshot)
                try Data("changed original".utf8).write(to:file)
                XCTAssertEqual(try PAdESSourcePreflight.inspect(snapshot,helper:helper),result)
                XCTAssertEqual(chmod(snapshot.fileURL.path,0o600),0)
                try Data("tamper".utf8).write(to:snapshot.fileURL)
                XCTAssertThrowsError(try PAdESSourcePreflight.inspect(snapshot,helper:helper))
            }
        }
    }
    func testPreflightDoesNotIntroduceAnArbitraryPageLimitFromThePreviewReader() throws {
        try fixture { root,helper in
            let file = root.appendingPathComponent("many-pages.pdf")
            try PAdESAppearanceTests().pdf(pages:1001).write(to:file)
            let snapshot = try DocumentSnapshot.capture(source:file,format:.pades,privateRoot:root)
            defer { snapshot.close() }
            try PAdESSourcePreflight.inspect(snapshot,helper:helper).requireAccepted(for:snapshot)
        }
    }
    func testTypedRejectionAndCancellationWithoutOutput() throws {
        try fixture { root, helper in
            let file = root.appendingPathComponent("malformed.pdf")
            try Data("%PDF-1.7 malformed".utf8).write(to:file)
            let snapshot = try DocumentSnapshot.capture(source:file,format:.cades,privateRoot:root)
            defer { snapshot.close() }
            let result = try PAdESSourcePreflight.inspect(snapshot,helper:helper)
            XCTAssertEqual(result.status,.rejected); XCTAssertFalse(result.reason.isEmpty)
            XCTAssertThrowsError(try result.requireAccepted(for:snapshot))
            XCTAssertThrowsError(try PAdESSourcePreflight.inspect(snapshot,helper:helper,isCancelled:{true})) {
                XCTAssertEqual($0 as? SupervisedProcess.Failure,.cancelled)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath:root.appendingPathComponent("output.pdf").path))
        }
    }
    func testSupportedPriorSignatureIsAcceptedAndCanBeSignedAgain() throws {
        try fixture { root, helper in
            let fixture = PAdESAppearanceTests(), signer = try SoftwareSigner(folder:root)
            let mock = try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
            let (first,_) = try fixture.signed(fixture.pdf(rotation:90),configuration:fixture.config(),root:root,signer:signer,mock:mock,name:"first")
            let file = root.appendingPathComponent("approved.pdf"); try first.write(to:file)
            let snapshot = try DocumentSnapshot.capture(source:file,format:.pades,privateRoot:root)
            defer { snapshot.close() }
            let before = try Data(contentsOf:mock.folder.appendingPathComponent("operations"))
            try PAdESSourcePreflight.inspect(snapshot,helper:helper).requireAccepted(for:snapshot)
            XCTAssertEqual(try Data(contentsOf:mock.folder.appendingPathComponent("operations")),before)
            let (second,_) = try fixture.signed(first,configuration:fixture.config(),root:root,signer:signer,mock:mock,name:"second")
            let report = try SignumVerificationService.verify(data:second,name:"second.pdf",helper:helper)
            XCTAssertEqual(report.signatures.count,2); XCTAssertEqual(report.integrity,.verified)
        }
    }
}
#endif
