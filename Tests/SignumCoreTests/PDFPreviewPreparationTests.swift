#if os(macOS)
import XCTest
import CoreGraphics
import ImageIO
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class PDFPreviewPreparationTests: XCTestCase {
    private func pdf(pages: Int = 1, vectors: Int = 0) throws -> Data {
        let output = NSMutableData(); var box = CGRect(x: 0, y: 0, width: 595, height: 842)
        let sink = try XCTUnwrap(CGDataConsumer(data: output))
        let context = try XCTUnwrap(CGContext(consumer: sink, mediaBox: &box, nil))
        for _ in 0..<pages {
            context.beginPDFPage(nil)
            context.setFillColor(CGColor(red: 1, green: 0, blue: 0, alpha: 1))
            context.fill(CGRect(x: 20, y: 30, width: 100, height: 60))
            for index in 0..<vectors { context.stroke(CGRect(x: index % 590, y: index % 830, width: 5, height: 7)) }
            context.endPDFPage()
        }
        context.closePDF(); return output as Data
    }
    func testOrdinaryComplexAndManyPageDocumentsKeepExactBytes() async throws {
        for (pages, vectors) in [(1,0), (4,20_000), (1001,0)] {
            let bytes = try pdf(pages: pages, vectors: vectors)
            let root = try FixtureFiles.directory("preview"); defer { try? FileManager.default.removeItem(at: root) }
            let source = root.appendingPathComponent("document.pdf"); try bytes.write(to: source)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root); defer { snapshot.close() }
            let start = ProcessInfo.processInfo.systemUptime
            let result = try await PDFPreviewPreparation.document(snapshot)
            let preparationSeconds = ProcessInfo.processInfo.systemUptime-start
            XCTAssertEqual(result.bytes, bytes); XCTAssertEqual(result.pageCount, pages)
            let mainStart = ProcessInfo.processInfo.systemUptime
            let document = try XCTUnwrap(PDFDocument(data: result.bytes))
            XCTAssertEqual(document.pageCount, pages)
            print("CQ08 main-PDFKit-init pages=\(pages) seconds=\(ProcessInfo.processInfo.systemUptime-mainStart)")
            print("CQ08 prepare pages=\(pages) vectors=\(vectors) bytes=\(bytes.count) seconds=\(preparationSeconds)")
        }
    }
    func testRasterUsesPrivateDocumentAndReturnsBoundedPixels() async throws {
        let bytes = try pdf(pages: 3, vectors: 500)
        let image = try await PDFPreviewPreparation.page(bytes, index: 2)
        XCTAssertEqual(image.pageCount, 3)
        let source = try XCTUnwrap(CGImageSourceCreateWithData(image.png as CFData, nil))
        let cg = try XCTUnwrap(CGImageSourceCreateImageAtIndex(source, 0, nil))
        XCTAssertLessThanOrEqual(cg.width, 1000); XCTAssertLessThanOrEqual(cg.height, 1000)
        XCTAssertThrowsError(try PDFPreviewPreparation.raster(bytes, index: 3))
    }
    func testCorruptAndCancelledPDFsRejectBeforePublication() throws {
        XCTAssertThrowsError(try PDFPreviewPreparation.inspect(Data("corrupt".utf8)))
        XCTAssertThrowsError(try PDFPreviewPreparation.raster(Data("corrupt".utf8), index: 0))
        let bytes = try pdf(pages: 10)
        var checkpoints = 0
        XCTAssertThrowsError(try PDFPreviewPreparation.inspect(bytes, isCancelled: { checkpoints += 1; return checkpoints == 3 }))
        XCTAssertEqual(checkpoints, 3)
        XCTAssertThrowsError(try PDFPreviewPreparation.raster(bytes, index: 0, isCancelled: { true }))
    }
    func testLargeAppearanceDecodeAndInvalidImageAreOffMain() async throws {
        let root = try FixtureFiles.directory("image-preview"); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("large.png")
        try PAdESPlacementPerformanceTests.png(2048).write(to: file)
        let start = ProcessInfo.processInfo.systemUptime
        let image = try await PDFPreviewPreparation.image(file)
        XCTAssertEqual(image.width, 2048)
        print("CQ08 appearance-decode pixels=\(image.width*image.height) seconds=\(ProcessInfo.processInfo.systemUptime-start)")
        let invalid = root.appendingPathComponent("bad.png"); try Data("not PNG".utf8).write(to: invalid)
        do { _ = try await PDFPreviewPreparation.image(invalid); XCTFail("Bad image accepted") } catch {}
    }
    func testRapidSelectionsAndClosureCannotPublishRetiredPreparation() async throws {
        let root = try FixtureFiles.directory("preview-selection"); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("document.pdf"); try pdf(pages: 3).write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root); defer { snapshot.close() }
        let entered = expectation(description: "parse started"), release = DispatchSemaphore(value: 0)
        let first = Task {
            try await PDFPreviewPreparation.document(snapshot, preparing: { bytes, _ in
                XCTAssertFalse(Thread.isMainThread)
                entered.fulfill(); XCTAssertEqual(release.wait(timeout: .now()+5), .success)
                return try PDFPreviewPreparation.inspect(bytes)
            })
        }
        await fulfillment(of: [entered], timeout: 5)
        // MainActor remains available while parsing is suspended on the worker.
        first.cancel()
        let second = Task { try await PDFPreviewPreparation.document(snapshot) }; second.cancel()
        let third = try await PDFPreviewPreparation.document(snapshot)
        XCTAssertEqual(third.pageCount, 3)
        release.signal()
        do { _ = try await first.value; XCTFail("Old selection published") } catch {}
        do { _ = try await second.value; XCTFail("Intermediate selection published") } catch {}
    }
    func testRetirementDuringPreparationRejectsEvenUncooperativeParser() async throws {
        let root = try FixtureFiles.directory("preview-close"); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("document.pdf"); try pdf().write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root)
        let entered = expectation(description: "parse started"), release = DispatchSemaphore(value: 0)
        let work = Task { try await PDFPreviewPreparation.document(snapshot, preparing: { bytes, _ in
            entered.fulfill(); XCTAssertEqual(release.wait(timeout: .now()+5), .success)
            return try PDFPreviewPreparation.inspect(bytes)
        }) }
        await fulfillment(of: [entered], timeout: 5)
        snapshot.close(); release.signal()
        do { _ = try await work.value; XCTFail("Retired snapshot published") } catch {}
    }
    func testCancelledOrClosedSnapshotCannotProducePreview() async throws {
        let root = try FixtureFiles.directory("cancel-preview"); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("document.pdf"); try pdf().write(to: source)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root)
        snapshot.close()
        do { _ = try await PDFPreviewPreparation.document(snapshot); XCTFail("Closed snapshot accepted") } catch {}
        let work = Task { try await PDFPreviewPreparation.page(try pdf(pages: 10), index: 0) }
        work.cancel()
        do { _ = try await work.value; XCTFail("Cancelled preview published") } catch {}
    }
}
#endif
