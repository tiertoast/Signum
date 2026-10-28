#if os(macOS)
import XCTest
import PDFKit
import SignumVerificationReports
@testable import SignumCore
@testable import SignumApp

/// S01: synthetic, deterministic PDF structure; keys exist only in private temporary folders.
/// No external PDF, provider, credential or hardware is used.
final class PDFRevisionCoverageTests: XCTestCase {
    private let originalText = "ORIGINAL SYNTHETIC DOCUMENT"
    private let changedText = "CHANGED UNSIGNED CONTENT"
    private func run(_ executable: String, _ arguments: [String], in root: URL) throws {
        let p = Process(); p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments; p.currentDirectoryURL = root
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); try FixtureProcess.wait(p)
        guard p.terminationStatus == 0 else { throw SignumError.module("S01 fixture command failed: " + executable) }
    }
    private func stream(_ text: String) -> String {
        let content = "BT /F1 18 Tf 70 400 Td (\(text)) Tj ET\n"
        return "<< /Length \(content.utf8.count) >>\nstream\n" + content + "endstream"
    }
    private func signed(_ root: URL) throws -> Data {
        _ = try SoftwareSigner(folder: root)
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R /AcroForm 8 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [20 30 520 630] /CropBox [50 70 450 520] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R /Annots [7 0 R] >>",
            stream(originalText), "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0000000000 0000000000 0000000000 0000000000] /Contents <" + String(repeating: "0", count: 32768) + "> >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Synthetic1) /V 6 0 R /Rect [0 0 0 0] /P 3 0 R >>",
            "<< /Fields [7 0 R] /SigFlags 3 >>"
        ]
        var pdf = Data("%PDF-1.7\n% S01 synthetic document\n".utf8), offsets = [0]
        for (index, object) in objects.enumerated() {
            offsets.append(pdf.count); pdf.append(Data("\(index+1) 0 obj\n\(object)\nendobj\n".utf8))
        }
        let xref = pdf.count
        pdf.append(Data("xref\n0 9\n0000000000 65535 f \n".utf8))
        for offset in offsets.dropFirst() { pdf.append(Data(String(format: "%010d 00000 n \n", offset).utf8)) }
        pdf.append(Data("trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n\(xref)\n%%EOF\n".utf8))
        let marker = try XCTUnwrap(pdf.range(of: Data("/Contents <".utf8)))
        let start = marker.upperBound-1, end = start+32770
        let placeholder = Data("[0000000000 0000000000 0000000000 0000000000]".utf8)
        let range = try XCTUnwrap(pdf.range(of: placeholder))
        pdf.replaceSubrange(range, with: Data(String(format: "[%010d %010d %010d %010d]", 0, start, end, pdf.count-end).utf8))
        var covered = Data(pdf[..<start]); covered.append(pdf[end...])
        try covered.write(to: root.appendingPathComponent("covered.bin"))
        try run("/usr/bin/openssl", ["cms", "-sign", "-binary", "-md", "sha256", "-in", "covered.bin", "-signer", "certificate.pem", "-inkey", "key.pem", "-outform", "DER", "-out", "signature.der"], in: root)
        let cms = try Data(contentsOf: root.appendingPathComponent("signature.der"))
        let hex = cms.map { String(format: "%02X", $0) }.joined()
        guard hex.count <= 32768 else { throw SignumError.module("S01 CMS too large") }
        pdf.replaceSubrange(start+1..<end-1, with: Data((hex+String(repeating: "0", count: 32768-hex.count)).utf8))
        return pdf
    }
    private func incremental(_ pdf: Data, objects: [(Int, String)], size: Int = 9) throws -> Data {
        let text = String(decoding: pdf.suffix(1024), as: UTF8.self)
        let tail = try XCTUnwrap(text.components(separatedBy: "startxref\n").last)
        let previous = try XCTUnwrap(Int(tail.components(separatedBy: "\n")[0]))
        var result = pdf, offsets = [(Int, Int)]()
        for (id, object) in objects { offsets.append((id, result.count)); result.append(Data("\(id) 0 obj\n\(object)\nendobj\n".utf8)) }
        let xref = result.count; result.append(Data("xref\n".utf8))
        for (id, offset) in offsets { result.append(Data("\(id) 1\n".utf8)); result.append(Data(String(format: "%010d 00000 n \n", offset).utf8)) }
        result.append(Data("trailer\n<< /Size \(size) /Root 1 0 R /Prev \(previous) >>\nstartxref\n\(xref)\n%%EOF\n".utf8))
        return result
    }
    private func withPDF(_ body: (URL, Data) throws -> Void) throws {
        let root = try FixtureFiles.directory("s01-coverage")
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root, signed(root))
    }
    private func text(_ bytes: Data, root: URL, name: String) throws -> String {
        try bytes.write(to: root.appendingPathComponent(name+".pdf"))
        let poppler = ProcessInfo.processInfo.environment["SIGNUM_TEST_POPPLER"].map { URL(fileURLWithPath: $0).deletingLastPathComponent().appendingPathComponent("pdftotext").path } ?? "/opt/homebrew/bin/pdftotext"
        try run(poppler, ["-layout", name+".pdf", name+".txt"], in: root)
        return try String(contentsOf: root.appendingPathComponent(name+".txt"), encoding: .utf8)
    }
    // Before S01 this is the production summary's exact mapping. After the fix,
    // route this adapter through the new document-aware production mapping.
    private func documentCheck(_ report: VerificationReport) -> VerificationCheck {
        VerificationPresentation.integrity(report.integrity)
    }
    @discardableResult private func assess(_ pdf: Data, root: URL, name: String, expected: VerificationTone) throws -> VerificationReport {
        let helper = URL(fileURLWithPath: try FixtureRequirements.helper())
        let report = try SignumVerificationService.verify(data: pdf, name: name+".pdf", helper: helper)
        let check = documentCheck(report)
        XCTAssertEqual(check.tone, expected, name)
        XCTAssertEqual(check.symbol, expected == .positive ? "checkmark.circle.fill" : expected == .negative ? "xmark.circle.fill" : "questionmark.circle", name)
        if expected == .uncertain {
            XCTAssertTrue(report.summary.contains("non valutate"), report.summary)
            XCTAssertTrue(check.value.contains("non valutate"), check.value)
        }
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        let document = try VerificationReportDocument(report: report.withoutPreview(), validations: [], verificationDate: at, exportedAt: at)
        // The verdict must be in the overview, before the individual signature details.
        let overview = document.fields.map { $0.value }.joined(separator: " ")
        if expected == .uncertain { XCTAssertTrue(overview.contains("non valutate"), overview) }
        let txt = try VerificationReportExporter.data(document, format: .text)
        let exported = try VerificationReportExporter.data(document, format: .pdf)
        let extracted = try text(exported, root: root, name: name+"-report")
        if expected == .uncertain {
            XCTAssertTrue(String(decoding: txt, as: UTF8.self).contains("non valutate"))
            XCTAssertTrue(extracted.contains("non valutate"))
        }
        let evidence = try FixtureFiles.directory("s01-"+name, evidence: true)
        try pdf.write(to: evidence.appendingPathComponent(name+".pdf"))
        try exported.write(to: evidence.appendingPathComponent("report.pdf"))
        try txt.write(to: evidence.appendingPathComponent("report.txt"))
        try Data(extracted.utf8).write(to: evidence.appendingPathComponent("report-pdftotext.txt"))
        try Data(("tone=\(check.tone) symbol=\(check.symbol) summary=\(report.summary) signatures=\(report.signatures.map { $0.integrity.rawValue }) ends=\(report.signatures.compactMap(\.signedRevisionEnd)) later=\(report.signatures.map(\.laterChanges))\n").utf8).write(to: evidence.appendingPathComponent("outcome.txt"))
        return report
    }
    func testAValidSignatureCoversCurrentDocument() throws {
        try withPDF { root, pdf in
            XCTAssertTrue(try text(pdf, root: root, name: "a-source").contains(originalText))
            let r = try assess(pdf, root: root, name: "a-covered", expected: .positive)
            XCTAssertEqual(r.signatures.map(\.integrity), [.verified]); XCTAssertEqual(r.signatures[0].signedRevisionEnd, pdf.count)
        }
    }
    func testBUnsignedContentStreamChangeIsNotGloballyPositive() throws {
        try withPDF { root, pdf in
            let changed = try incremental(pdf, objects: [(4, stream(changedText))])
            XCTAssertEqual(changed.prefix(pdf.count), pdf)
            XCTAssertTrue(try text(pdf, root: root, name: "b-before").contains(originalText))
            let after = try text(changed, root: root, name: "b-after")
            XCTAssertTrue(after.contains(changedText)); XCTAssertFalse(after.contains(originalText))
            let r = try assess(changed, root: root, name: "b-content", expected: .uncertain)
            XCTAssertEqual(r.signatures.map(\.integrity), [.verified]); XCTAssertTrue(r.signatures[0].laterChanges)
        }
    }
    func testCTwoIncrementalSignaturesLastCoversAllIncludingSignumSigning() throws {
        try withPDF { root, pdf in
            let fixture = PAdESAppearanceTests(), signerRoot = root.appendingPathComponent("second-signer")
            try FileManager.default.createDirectory(at: signerRoot, withIntermediateDirectories: false)
            let signer = try SoftwareSigner(folder: signerRoot), mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER())
            var configuration = fixture.config(); configuration.visible = false
            let (second, _) = try fixture.signed(pdf, configuration: configuration, root: root, signer: signer, mock: mock, name: "signum-second")
            XCTAssertEqual(second.prefix(pdf.count), pdf)
            XCTAssertTrue(try text(second, root: root, name: "c-source").contains(originalText))
            let r = try assess(second, root: root, name: "c-multiple", expected: .positive)
            XCTAssertEqual(r.signatures.map(\.integrity), [.verified, .verified])
            XCTAssertEqual(r.signatures.map(\.laterChanges), [true, false]); XCTAssertEqual(r.signatures.last?.signedRevisionEnd, second.count)
        }
    }
    func testDDSSOnlyUpdateRemainsUnassessedWithoutProofOfBenignChanges() throws {
        try withPDF { root, pdf in
            // An empty synthetic DSS is structurally valid. Presence of /DSS alone
            // proves neither exclusivity of changes nor DocMDP/FieldMDP compliance.
            let dss = try incremental(pdf, objects: [(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 8 0 R /DSS 9 0 R >>"), (9, "<< /Certs [] /OCSPs [] /CRLs [] >>")], size: 10)
            XCTAssertTrue(try text(dss, root: root, name: "d-source").contains(originalText))
            let r = try assess(dss, root: root, name: "d-dss", expected: .uncertain)
            XCTAssertEqual(r.signatures.map(\.integrity), [.verified])
        }
    }
    func testEUnclassifiedTrailingBytesAreNotGloballyPositive() throws {
        try withPDF { root, pdf in
            var changed = pdf; changed.append(Data("\n% S01 unclassified trailing comment\n".utf8))
            XCTAssertTrue(try text(changed, root: root, name: "e-source").contains(originalText))
            let r = try assess(changed, root: root, name: "e-tail", expected: .uncertain)
            XCTAssertEqual(r.signatures.map(\.integrity), [.verified])
        }
    }
    func testFTamperingInsideSignedByteRangeIsNegative() throws {
        try withPDF { root, pdf in
            var tampered = pdf; let range = try XCTUnwrap(tampered.range(of: Data(originalText.utf8)))
            tampered[range.lowerBound] = 88
            XCTAssertTrue(try text(tampered, root: root, name: "f-source").contains("XRIGINAL"))
            let r = try assess(tampered, root: root, name: "f-tampered", expected: .negative)
            XCTAssertEqual(r.signatures.map(\.integrity), [.invalid])
        }
    }
    func testGInvalidEarlierSignatureAndLaterContentChangeStayNegative() throws {
        try withPDF { root, pdf in
            var tampered = pdf; let range = try XCTUnwrap(tampered.range(of: Data(originalText.utf8)))
            tampered[range.lowerBound] = 88
            let changed = try incremental(tampered, objects: [(4, stream(changedText))])
            XCTAssertTrue(try text(changed, root: root, name: "g-source").contains(changedText))
            let r = try assess(changed, root: root, name: "g-invalid-later", expected: .negative)
            XCTAssertEqual(r.signatures.map(\.integrity), [.invalid])
        }
    }
}
#endif
