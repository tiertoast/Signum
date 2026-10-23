#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class SigningIncomingFormatTests: XCTestCase {
    func testAutomaticFollowsSelectionAndExplicitOverrideOnlyAffectsNewDocuments() async throws {
        try await SigningFormatStabilizationTests().fixture { root, batch, pdf in
            await batch.addDocuments([pdf], format: .cades)
            let first = try XCTUnwrap(batch.documents.first)
            XCTAssertEqual(SigningIncomingFormat.resolve(override: nil, selected: first.format, fallback: .xades), .cades)
            try batch.setFormat(.pades, for: first.id)
            XCTAssertEqual(SigningIncomingFormat.resolve(override: nil, selected: batch.documents[0].format, fallback: .cades), .pades)
            let second = root.appendingPathComponent("second.pdf")
            var bytes = try Data(contentsOf: pdf); bytes.append(Data("\n% second document".utf8)); try bytes.write(to: second)
            let choice = SigningIncomingFormat.resolve(override: .cadesDetached, selected: batch.documents[0].format, fallback: .cades)
            await batch.addDocuments([second], format: try XCTUnwrap(SigningFormat(rawValue: choice.rawValue)))
            XCTAssertEqual(batch.documents.map(\.format), [.pades, .cadesDetached])
            XCTAssertEqual(batch.documents[0].id, first.id)
            XCTAssertEqual(try Data(contentsOf: pdf), try batch.documents[0].snapshot.verifiedBytes())
            XCTAssertEqual(SigningIncomingFormat.resolve(override: nil, selected: batch.documents[0].format, fallback: .cades), .pades)
        }
    }
    func testAutomaticAndOverrideRetainSpecialFormatIdentifiers() {
        for format in SignumFormat.allCases {
            let core = SigningFormat(rawValue: format.rawValue)!
            XCTAssertEqual(SigningIncomingFormat.resolve(override: nil, selected: core, fallback: .cades), format)
            XCTAssertEqual(SigningIncomingFormat.resolve(override: format, selected: .pades, fallback: .cades), format)
        }
        XCTAssertEqual(SigningIncomingFormat.resolve(override: nil, selected: nil, fallback: .asice), .asice)
    }
}
#endif
