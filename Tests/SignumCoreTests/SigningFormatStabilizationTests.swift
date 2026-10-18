#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

@MainActor final class SigningFormatStabilizationTests: XCTestCase {
    func fixture(_ body: (URL, BatchSigningCoordinator, URL) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let bytes = NSMutableData(); var box = CGRect(x: 0, y: 0, width: 595, height: 842)
        let sink = try XCTUnwrap(CGDataConsumer(data: bytes))
        let cg = try XCTUnwrap(CGContext(consumer: sink, mediaBox: &box, nil))
        cg.beginPDFPage(nil); cg.endPDFPage(); cg.closePDF()
        let file = root.appendingPathComponent("synthetic.pdf"); try (bytes as Data).write(to: file)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        try await body(root, batch, file)
    }
    func testChangingNewDocumentDefaultDoesNotConvertAcquiredSnapshotOrApprovedJob() async throws {
        for initial in [SigningFormat.cades, .pades] {
            try await fixture { root, batch, file in
                var nextFormat = initial
                await batch.addDocuments([file], format: nextFormat)
                nextFormat = initial == .cades ? .pades : .cades
                let snapshot = try XCTUnwrap(batch.documents.first?.snapshot)
                XCTAssertEqual(snapshot.format, initial); XCTAssertNotEqual(snapshot.format, nextFormat)
                let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7,
                    certificate: .init(label: "Synthetic", identifier: Data([1])),
                    der: CertificateEligibilityTests.fixtures.get().der("valid"), destination: .originalFolders)
                XCTAssertEqual(plan.jobs[0].format, initial)
                XCTAssertEqual(plan.jobs[0].destination.pathExtension, initial == .cades ? "p7m" : "pdf")
                XCTAssertTrue(plan.jobs[0].approvalDescription.contains(initial.rawValue.uppercased()))
                try batch.freezeReview(plan); try batch.confirm(plan)
                await batch.addDocuments([file], format: nextFormat)
                XCTAssertEqual(batch.documents.count, 1)
                XCTAssertEqual(batch.approval?.jobs[0].format, initial)
            }
        }
    }
    func testMixedBatchRetainsPerDocumentFormatsAndDestinations() async throws {
        try await fixture { root, batch, file in
            await batch.addDocuments([file], format: .cades)
            let other = root.appendingPathComponent("other.pdf")
            var bytes = try Data(contentsOf: file); bytes.append(Data("\n% distinct synthetic document".utf8)); try bytes.write(to: other)
            await batch.addDocuments([other], format: .pades)
            let plan = try await batch.prepareReview(provider: "/synthetic/provider", slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])),
                der: CertificateEligibilityTests.fixtures.get().der("valid"), destination: .originalFolders)
            XCTAssertEqual(plan.jobs.map(\.format), [.cades, .pades])
            XCTAssertEqual(plan.jobs.map { $0.destination.pathExtension }, ["p7m", "pdf"])
        }
    }
}
#endif
