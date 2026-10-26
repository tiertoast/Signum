#if os(macOS)
import XCTest
import CryptoKit
@testable import SignumCore
@testable import SignumApp
import SignumVerificationReports

@MainActor final class CumulativeVerificationTests: XCTestCase {
    private let verifier: VerificationWorkspace.Verifier = { url, _ in
        .init(id: UUID(), documentName: url.lastPathComponent, sha256: SHA256.hash(data: Data(url.path.utf8)).map { String(format: "%02x", $0) }.joined(), format: .unknown, signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: Data(url.path.utf8))
    }
    func testTwoThreeAndManyAppendPreservingReportIdentityAndSelectedRow() async throws {
        for count in [2,3,12] {
            let workspace = VerificationWorkspace()
            let urls = (0..<count).map { URL(fileURLWithPath: "/synthetic/\($0).p7m") }
            await workspace.verify(urls, using: verifier)
            let old = workspace.rows
            workspace.selectedDocument = old[1].id
            await workspace.verify([URL(fileURLWithPath: "/synthetic/additional.p7m")], using: verifier)
            XCTAssertEqual(workspace.rows.count, count + 1)
            XCTAssertEqual(workspace.selectedDocument, old[1].id)
            for i in old.indices {
                XCTAssertEqual(workspace.rows[i].id, old[i].id)
                XCTAssertEqual(workspace.rows[i].report?.id, old[i].report?.id)
                XCTAssertEqual(workspace.rows[i].verificationDate, old[i].verificationDate)
                XCTAssertEqual(workspace.rows[i].report?.sha256, old[i].report?.sha256)
            }
        }
    }
    func testNamesakesDifferentPathsExportTheirOwnReportAndRemovalKeepsNeighbour() async throws {
        let workspace = VerificationWorkspace()
        await workspace.verify([URL(fileURLWithPath: "/synthetic/a/same.p7m"), URL(fileURLWithPath: "/synthetic/b/same.p7m"), URL(fileURLWithPath: "/synthetic/c/same.p7m")], using: verifier)
        let rows = workspace.rows
        for row in rows {
            let report = try XCTUnwrap(row.report), date = try XCTUnwrap(row.verificationDate)
            let document = try VerificationReportDocument(report: report, validations: [], verificationDate: date)
            let text = String(decoding: try VerificationReportExporter.data(document, format: .text), as: UTF8.self)
            XCTAssertTrue(text.contains(report.sha256))
            for other in rows where other.id != row.id { XCTAssertFalse(text.contains(try XCTUnwrap(other.report).sha256)) }
        }
        workspace.selectedDocument = rows[1].id
        XCTAssertTrue(workspace.remove(rows[1].id));XCTAssertEqual(workspace.selectedDocument,rows[2].id)
        XCTAssertTrue(workspace.remove(rows[0].id));XCTAssertEqual(workspace.rows[0].report?.id,rows[2].report?.id)
        XCTAssertTrue(workspace.remove(rows[2].id));XCTAssertNil(workspace.selectedDocument)
    }
    func testOneFailureDoesNotEraseSuccessfulReports() async throws {
        let workspace = VerificationWorkspace()
        await workspace.verify([URL(fileURLWithPath: "/synthetic/valid"), URL(fileURLWithPath: "/synthetic/altered")]) { url, _ in
            if url.lastPathComponent == "altered" { throw SignumError.invalidCertificate }
            return .init(id: UUID(), documentName: url.lastPathComponent, sha256: "valid", format: .unknown, signatures: [], documentState: "unsupported", issue: "", previewPDF: nil, originalContent: nil)
        }
        XCTAssertNotNil(workspace.rows[0].report);XCTAssertNil(workspace.rows[1].report)
        XCTAssertFalse(workspace.rows[1].issue.isEmpty)
        let id = workspace.rows[0].report?.id
        await workspace.verify([URL(fileURLWithPath: "/synthetic/third")], using: verifier)
        XCTAssertEqual(workspace.rows[0].report?.id,id);XCTAssertEqual(workspace.rows.count,3)
    }
    func testSessionLimitAppliesAcrossAdditionsWithoutErasingExistingRows() async throws {
        let workspace = VerificationWorkspace()
        await workspace.verify((0..<31).map { URL(fileURLWithPath: "/synthetic/\($0)") }, using: verifier)
        let ids = workspace.rows.map(\.id)
        await workspace.verify([URL(fileURLWithPath: "/synthetic/31"),URL(fileURLWithPath: "/synthetic/32")], using: verifier)
        XCTAssertEqual(workspace.rows.map(\.id),ids);XCTAssertFalse(workspace.issue.isEmpty)
        await workspace.verify([URL(fileURLWithPath: "/synthetic/31")], using: verifier)
        XCTAssertEqual(workspace.rows.count,32)
    }
    func testCancelPreservesFinishedReportsAndRejectsLateQueuedCallbacks() async throws {
        let workspace = VerificationWorkspace()
        await workspace.verify([URL(fileURLWithPath: "/synthetic/complete")], using: verifier)
        let complete = workspace.rows[0]
        let ready = expectation(description:"waiting"),release = DispatchSemaphore(value:0)
        let active = workspace.start([URL(fileURLWithPath:"/synthetic/late")]) { url,_ in
            ready.fulfill();_ = release.wait(timeout:.now()+3)
            return .init(id:UUID(),documentName:url.lastPathComponent,sha256:"late",format:.unknown,signatures:[],documentState:"unsupported",issue:"",previewPDF:nil,originalContent:nil)
        }
        await fulfillment(of:[ready],timeout:2)
        let queued = workspace.start([URL(fileURLWithPath:"/synthetic/queued")],using:verifier)
        workspace.cancel();release.signal();await active.value;await queued.value
        XCTAssertEqual(workspace.rows[0].report?.id,complete.report?.id)
        XCTAssertTrue(workspace.rows.dropFirst().allSatisfy { $0.report == nil && $0.issue == "Verifica annullata." })
        XCTAssertFalse(workspace.busy)
        await workspace.verify([URL(fileURLWithPath:"/synthetic/recover")],using:verifier)
        XCTAssertEqual(workspace.rows.count,4)
    }
    func testRetainedContentLimitIsSharedAcrossQueuedBatches() async throws {
        let workspace = VerificationWorkspace()
        let bytes = Data(repeating: 0, count: 65 * 1024 * 1024)
        let verify: VerificationWorkspace.Verifier = { url,_ in
            .init(id:UUID(),documentName:url.lastPathComponent,sha256:"synthetic",format:.unknown,signatures:[],documentState:"unsupported",issue:"",previewPDF:nil,originalContent:bytes)
        }
        await workspace.verify([URL(fileURLWithPath:"/synthetic/one")],using:verify)
        await workspace.verify([URL(fileURLWithPath:"/synthetic/two")],using:verify)
        XCTAssertNotNil(workspace.rows[0].report?.originalContent)
        XCTAssertNil(workspace.rows[1].report?.originalContent)
        XCTAssertFalse(workspace.rows[1].issue.isEmpty)
        XCTAssertEqual(workspace.rows.reduce(0) { $0 + ($1.report?.originalContent?.count ?? 0) },bytes.count)
    }
    func testResetClearsSessionAndLateAcquisitionCannotReturn() async throws {
        let workspace = VerificationWorkspace(), ready = expectation(description:"drop"), drop = ControlledDrop(1,ready:ready)
        let acquisition = workspace.acquire(using:{await drop.resolve()},verifier:verifier)
        await fulfillment(of:[ready],timeout:2);workspace.reset();drop.send(0,"late");await acquisition.value
        XCTAssertTrue(workspace.rows.isEmpty);XCTAssertFalse(workspace.busy)
        await workspace.verify([URL(fileURLWithPath:"/synthetic/new")],using:verifier)
        XCTAssertEqual(workspace.rows.count,1)
    }
}
#endif
