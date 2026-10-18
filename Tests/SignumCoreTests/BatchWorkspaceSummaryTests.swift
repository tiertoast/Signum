#if os(macOS)
import XCTest
@testable import SignumApp
@testable import SignumCore

final class BatchWorkspaceSummaryTests: XCTestCase {
    func testSuccessSummaryRequiresEveryDocumentCompleted() {
        XCTAssertEqual(BatchWorkspaceSummary.summary([]), "Nessun documento")
        XCTAssertEqual(BatchWorkspaceSummary.summary([.completed]), "Documento firmato correttamente")
        XCTAssertEqual(BatchWorkspaceSummary.summary(Array(repeating: .completed, count: 7)), "7 documenti firmati correttamente")
        let partial = BatchWorkspaceSummary.summary([.completed, .failed, .uncertain, .cancelled, .waitingForAuthorization])
        XCTAssertTrue(partial.contains("1 firmato")); XCTAssertTrue(partial.contains("1 non riuscito"))
        XCTAssertTrue(partial.contains("1 da verificare")); XCTAssertTrue(partial.contains("1 annullato")); XCTAssertTrue(partial.contains("1 in attesa"))
        XCTAssertFalse(partial.contains("correttamente"))
    }
    func testShortRowStatesRemainDistinctAndMeaningful() {
        XCTAssertEqual(BatchWorkspaceSummary.status(.uncertain), "Da verificare")
        XCTAssertNotEqual(BatchWorkspaceSummary.status(.uncertain), BatchWorkspaceSummary.status(.completed))
        XCTAssertEqual(BatchWorkspaceSummary.symbol(.completed), "checkmark.circle")
        XCTAssertEqual(BatchWorkspaceSummary.symbol(.failed), "exclamationmark.triangle")
        XCTAssertEqual(BatchWorkspaceSummary.status(.waitingForAuthorization), "PIN richiesto")
    }
}
#endif
