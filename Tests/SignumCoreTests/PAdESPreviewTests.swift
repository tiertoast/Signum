#if os(macOS)
import XCTest
import PDFKit
import CoreGraphics
@testable import SignumApp
@testable import SignumCore

final class PAdESPreviewTests: XCTestCase {
    private let field = PAdESPlacement(pageIndex: 0, rectangle: CGRect(x: 12, y: 25, width: 190, height: 62))

    private func pdf() throws -> Data {
        let bytes = NSMutableData()
        let consumer = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
        var box = CGRect(x: 0, y: 0, width: 400, height: 500)
        let context = try XCTUnwrap(CGContext(consumer: consumer, mediaBox: &box, nil))
        context.beginPDFPage(nil); context.endPDFPage(); context.closePDF()
        return bytes as Data
    }

    @MainActor func testSignerChangesWithoutMovingOrDuplicatingAnnotation() async throws {
        let viewer = PlacementPDFView(); viewer.document = try XCTUnwrap(PDFDocument(data: pdf()))
        viewer.updatePreview(field, name: "Synthetic A", visible: true)
        let old = try XCTUnwrap(viewer.previewAnnotation)
        viewer.updatePreview(field, name: "Synthetic B", visible: true)
        let current = try XCTUnwrap(viewer.previewAnnotation)
        XCTAssertFalse(old === current)
        XCTAssertNil(old.page)
        XCTAssertEqual(current.contents, "Firmato digitalmente da\nSynthetic B")
        XCTAssertEqual(current.bounds, field.rectangle)
        XCTAssertEqual(viewer.currentPreviewPlacement, field)
        XCTAssertEqual(viewer.document?.page(at: 0)?.annotations.count, 1)
        viewer.updatePreview(field, name: "Synthetic B", visible: true)
        XCTAssertTrue(current === viewer.previewAnnotation)
    }

    @MainActor func testDiscoveryAfterPlacementReplacesPlaceholder() async throws {
        let viewer = PlacementPDFView(); viewer.document = try XCTUnwrap(PDFDocument(data: pdf()))
        viewer.updatePreview(field, name: "Seleziona un certificato", visible: true)
        viewer.updatePreview(field, name: "Synthetic discovered signer", visible: true)
        XCTAssertEqual(viewer.previewAnnotation?.contents, "Firmato digitalmente da\nSynthetic discovered signer")
        XCTAssertEqual(viewer.previewAnnotation?.bounds, field.rectangle)
        XCTAssertEqual(viewer.document?.page(at: 0)?.annotations.count, 1)
    }

    @MainActor func testVisibilityAndAbsentPlacementNeverLeaveStaleSigner() async throws {
        let viewer = PlacementPDFView(); viewer.document = try XCTUnwrap(PDFDocument(data: pdf()))
        viewer.updatePreview(field, name: "Synthetic A", visible: true)
        viewer.updatePreview(field, name: "Synthetic B", visible: false)
        XCTAssertNil(viewer.previewAnnotation)
        viewer.updatePreview(field, name: "Synthetic B", visible: true)
        XCTAssertEqual(viewer.previewAnnotation?.contents, "Firmato digitalmente da\nSynthetic B")
        viewer.updatePreview(nil, name: "Synthetic C", visible: true)
        XCTAssertNil(viewer.previewAnnotation)
        XCTAssertEqual(viewer.document?.page(at: 0)?.annotations.count, 0)
    }

    @MainActor func testCertificateSwitchMatchesConfirmationAndPreservesApprovedJobAndBytes() async throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("source.pdf"), bytes = try pdf()
        try bytes.write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: folder)
        defer { snapshot.close() }
        let fixtures = try CertificateEligibilityTests.fixtures.get()
        let a = fixtures.der("valid"), b = fixtures.der("otherSigner")
        let nameA = try SignumCertificateIdentity(certificateDER: a).fullName
        let nameB = try SignumCertificateIdentity(certificateDER: b).fullName
        XCTAssertNotEqual(nameA, nameB)
        let certificate = SignumCertificate(label: nameB, identifier: Data([2]))
        let job = try SigningJob(snapshot: snapshot, providerPath: "/synthetic/provider.dylib", slot: 7,
                                certificate: certificate, certificateDER: b, destination: folder.appendingPathComponent("signed.pdf"))
        let id = job.id, hash = job.contentSHA256, identity = job.snapshotIdentity
        let viewer = PlacementPDFView(); viewer.document = try XCTUnwrap(PDFDocument(data: snapshot.approvedBytes))
        viewer.updatePreview(field, name: nameA, visible: true)
        viewer.updatePreview(field, name: nameB, visible: true)
        let confirmation = signingApprovalMessage(holder: nameB, job: job)
        XCTAssertEqual(viewer.previewAnnotation?.contents, "Firmato digitalmente da\n" + nameB)
        XCTAssertTrue(confirmation.hasPrefix("Firmatario: " + nameB + "\n"))
        XCTAssertTrue(confirmation.contains(hash))
        XCTAssertEqual(viewer.previewAnnotation?.bounds, field.rectangle)
        XCTAssertEqual(job.id, id); XCTAssertEqual(job.snapshotIdentity, identity)
        XCTAssertEqual(job.contentSHA256, hash); XCTAssertEqual(job.certificateDER, b)
        XCTAssertEqual(try job.verifiedBytes(), bytes)
        XCTAssertEqual(try Data(contentsOf: source), bytes)
    }
}
#endif
