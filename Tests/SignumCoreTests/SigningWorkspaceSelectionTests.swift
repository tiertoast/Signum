#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class SigningWorkspaceSelectionTests: XCTestCase {
    func testSelectedDocumentDrivesPaneAndRejectsLateCallbacksIncludingReselection() async throws {
        try await SigningFormatStabilizationTests().fixture { root, batch, file in
            await batch.addDocuments([file], format: .cades)
            let pdf = root.appendingPathComponent("second.pdf")
            var data = try Data(contentsOf: file); data.append(Data("\n% second".utf8)); try data.write(to: pdf)
            await batch.addDocuments([pdf], format: .pades)
            let cades = batch.documents[0].snapshot, pades = batch.documents[1].snapshot
            let selection = SigningWorkspaceSelection(snapshot: cades)
            XCTAssertFalse(selection.showsPAdESPreview)
            selection.select(pades); let first = selection.generation
            XCTAssertTrue(selection.showsPAdESPreview)
            XCTAssertTrue(selection.accepts(pades.identity.id, generation: first))
            selection.showingPDFPreview = false; XCTAssertFalse(selection.showsPAdESPreview)
            selection.select(pades)
            XCTAssertTrue(selection.showsPAdESPreview, "Selecting the same PAdES row reopens its preview")
            selection.select(cades)
            XCTAssertFalse(selection.showingPDFPreview); XCTAssertFalse(selection.showsPAdESPreview)
            XCTAssertFalse(selection.accepts(pades.identity.id, generation: first))
            for _ in 0..<20 { selection.select(pades); selection.select(cades) }
            selection.select(pades)
            XCTAssertTrue(selection.showsPAdESPreview)
            XCTAssertFalse(selection.accepts(pades.identity.id, generation: first))
            selection.select(nil)
            XCTAssertNil(selection.snapshot); XCTAssertFalse(selection.showsPAdESPreview)
        }
    }
    func testNewSessionAndCompletedJobDoNotChangeAcquiredFormat() async throws {
        try await SigningFormatStabilizationTests().fixture { _, batch, file in
            await batch.addDocuments([file], format: .cades)
            let selection = SigningWorkspaceSelection(snapshot: batch.documents[0].snapshot)
            selection.showingPDFPreview = true // even a stale tab cannot show PAdES for CAdES
            XCTAssertFalse(selection.showsPAdESPreview)
            let id = selection.snapshot?.identity.id, generation = selection.generation
            batch.reset(); selection.select(nil)
            XCTAssertFalse(selection.accepts(try XCTUnwrap(id), generation: generation))
            XCTAssertFalse(selection.showsPAdESPreview)
        }
    }
}
#endif
