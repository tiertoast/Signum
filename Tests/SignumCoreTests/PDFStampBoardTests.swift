#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

/// Lifecycle of visible PDF stamps in one signing session (no UI, no token).
@MainActor final class PDFStampBoardTests: XCTestCase {
    private let der1 = Data("synthetic-certificate-1".utf8), der2 = Data("synthetic-certificate-2".utf8)

    private func pdf(_ root: URL, _ name: String, _ size: CGSize = CGSize(width: 595, height: 842), pages: Int = 1) throws -> URL {
        let output = NSMutableData(); var box = CGRect(origin: .zero, size: size)
        let context = try XCTUnwrap(CGContext(consumer: try XCTUnwrap(CGDataConsumer(data: output as CFMutableData)), mediaBox: &box, nil))
        for _ in 0..<pages { context.beginPDFPage(nil); context.endPDFPage() }
        context.closePDF()
        let url = root.appendingPathComponent(name); try (output as Data).write(to: url); return url
    }
    private func fixture(_ body: (URL, BatchSigningCoordinator, PDFStampBoard) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        try await body(root, batch, PDFStampBoard())
    }
    private func settle(_ board: PDFStampBoard) async {
        for _ in 0..<500 where board.isWorking { try? await Task.sleep(nanoseconds: 2_000_000) }
        await Task.yield()
    }
    private func sync(_ board: PDFStampBoard, _ batch: BatchSigningCoordinator, frozen: Bool = false, der: Data? = nil) async {
        board.sync(documents: batch.documents, frozen: frozen, certificateDER: der ?? der1); await settle(board)
    }
    /// The user's hand-made stamp: bottom-left at (60, 70), confirmed in the editor.
    private func confirmByHand(_ board: PDFStampBoard, _ batch: BatchSigningCoordinator, _ id: UUID,
                               at origin: CGPoint = CGPoint(x: 60, y: 70), der: Data? = nil) throws {
        let entry = try XCTUnwrap(batch.documents.first { $0.id == id })
        let page = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: entry.snapshot.approvedBytes as CFData)))?.page(at: 1))
        let geometry = try PAdESPageGeometry(page: page)
        var config = try geometry.defaultAppearance(); config.showSigner = false; config.customText = "Synthetic"
        config.rectangle.origin = origin
        let rendered = try PAdESAppearanceRenderer.render(config, certificateDER: der ?? der1, cropBox: geometry.cropBox, pageRotation: geometry.rotation)
        board.edit(PAdESPlacement(pageIndex: 0, rectangle: config.rectangle, appearance: rendered, draft: config), for: id)
        board.previewReady(id, true)
        board.confirmStamp(id, in: batch.documents)
    }
    private func origin(_ board: PDFStampBoard, _ id: UUID) -> CGPoint? { board.confirmedAppearance(id)?.configuration.rectangle.origin }

    func testApplyToAllThenAddedAndRemovedDocumentsKeepFollowingTheTemplate() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf", CGSize(width: 595.32, height: 841.92))], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id
            await sync(board, batch)
            XCTAssertNil(board.template)
            try confirmByHand(board, batch, a)
            XCTAssertEqual(board.template?.id, a)
            XCTAssertFalse(board.isConfirmed(b))
            board.applyToAll(in: batch.documents); await settle(board)
            XCTAssertTrue(board.isConfirmed(b)); XCTAssertTrue(board.followsTemplate)
            XCTAssertEqual(origin(board, b)?.x ?? 0, 60, accuracy: 0.01)
            XCTAssertEqual(board.notice, "Timbro applicato a 1 PDF.")
            // A file added later receives the stamp without pressing anything.
            await batch.addDocuments([try pdf(root, "c.pdf", CGSize(width: 842, height: 1191))], format: .pades)
            let c = try XCTUnwrap(batch.documents.last?.id)
            await sync(board, batch)
            XCTAssertTrue(board.isConfirmed(c))
            XCTAssertEqual(origin(board, c)?.y ?? 0, 70, accuracy: 0.01)
            // Removing the template's document promotes a stamp: still re-applicable.
            batch.remove(a); await sync(board, batch)
            XCTAssertNotNil(board.template); XCTAssertTrue(board.followsTemplate)
            XCTAssertTrue(board.isConfirmed(b)); XCTAssertTrue(board.isConfirmed(c))
            await batch.addDocuments([try pdf(root, "d.pdf")], format: .pades)
            let d = try XCTUnwrap(batch.documents.last?.id)
            await sync(board, batch)
            XCTAssertEqual(origin(board, d)?.x ?? 0, 60, accuracy: 0.01)
        }
    }

    func testDeclinedApprovalKeepsStampsAndApplyToAllAvailable() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf")], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id
            await sync(board, batch)
            try confirmByHand(board, batch, a)
            board.applyToAll(in: batch.documents); await settle(board)
            // Approval freezes everything: no edits, no copies.
            await sync(board, batch, frozen: true)
            try confirmByHand(board, batch, b, at: CGPoint(x: 200, y: 300))
            XCTAssertEqual(board.template?.id, a)
            XCTAssertEqual(origin(board, b)?.x ?? 0, 60, accuracy: 0.01)
            // Declined or cancelled: the same session can re-apply immediately.
            await sync(board, batch, frozen: false)
            XCTAssertNotNil(board.template); XCTAssertTrue(board.isConfirmed(a)); XCTAssertTrue(board.isConfirmed(b))
            board.applyToAll(in: batch.documents); await settle(board)
            XCTAssertEqual(origin(board, b)?.x ?? 0, 60, accuracy: 0.01)
        }
    }

    func testEditingAndConfirmingACopyMakesItTheNewTemplateForTheOthers() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf"), try pdf(root, "c.pdf")], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id, c = batch.documents[2].id
            await sync(board, batch)
            try confirmByHand(board, batch, a)
            board.applyToAll(in: batch.documents); await settle(board)
            // Viewing a copy and confirming it unchanged keeps it a copy.
            board.previewReady(b, false); board.previewReady(b, true); board.confirmStamp(b, in: batch.documents)
            XCTAssertEqual(board.template?.id, a); XCTAssertTrue(board.isCopy(b))
            // Moving it in the editor and confirming makes it the template; c follows, a keeps its own.
            board.setEditing(b, in: batch.documents)
            try confirmByHand(board, batch, b, at: CGPoint(x: 300, y: 400))
            board.setEditing(nil, in: batch.documents); await settle(board)
            XCTAssertEqual(board.template?.id, b)
            XCTAssertEqual(origin(board, c)?.x ?? 0, 300, accuracy: 0.01)
            XCTAssertEqual(origin(board, a)?.x ?? 0, 60, accuracy: 0.01)
        }
    }

    func testPDFOpenInTheEditorIsNeverOverwrittenByACopy() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf")], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id
            await sync(board, batch)
            try confirmByHand(board, batch, a)
            board.setEditing(b, in: batch.documents)
            board.applyToAll(in: batch.documents); await settle(board)
            XCTAssertFalse(board.isConfirmed(b))
            board.setEditing(nil, in: batch.documents); await settle(board)
            XCTAssertTrue(board.isConfirmed(b)) // Follow mode copies it once the editor closes.
        }
    }

    func testCertificateChangeRerendersEveryStampForTheNewCertificate() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf")], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id
            await sync(board, batch)
            try confirmByHand(board, batch, a)
            board.applyToAll(in: batch.documents); await settle(board)
            let fingerprint = DocumentSnapshot.digest(der2)
            await sync(board, batch, der: der2)
            XCTAssertEqual(board.confirmedAppearance(a)?.certificateSHA256, fingerprint)
            XCTAssertEqual(board.confirmedAppearance(b)?.certificateSHA256, fingerprint)
            XCTAssertEqual(origin(board, a)?.x ?? 0, 60, accuracy: 0.01)
        }
    }

    func testFormatChangesAndResetAreReconciled() async throws {
        try await fixture { root, batch, board in
            await batch.addDocuments([try pdf(root, "a.pdf"), try pdf(root, "b.pdf")], format: .pades)
            let a = batch.documents[0].id, b = batch.documents[1].id
            await sync(board, batch)
            try confirmByHand(board, batch, a)
            board.applyToAll(in: batch.documents); await settle(board)
            try batch.setFormat(.cades, for: b); await sync(board, batch)
            XCTAssertFalse(board.isConfirmed(b)); XCTAssertNil(board.placement(b))
            try batch.setFormat(.pades, for: b); await sync(board, batch)
            XCTAssertTrue(board.isConfirmed(b)) // Back to PDF: follows the template again.
            board.reset()
            XCTAssertNil(board.template); XCTAssertTrue(board.confirmed.isEmpty); XCTAssertFalse(board.followsTemplate)
            _ = a
        }
    }
}
#endif
