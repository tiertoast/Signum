#if os(macOS)
import XCTest
import SwiftUI
import PDFKit
@testable import SignumApp
@testable import SignumCore

@MainActor final class DynamicFormatWorkspaceTests: XCTestCase {
    func testReadOnlyPDFPaperUsesBlackDefaultInkAndPreservesExplicitColors() throws {
        let stream = "BT /F1 18 Tf 10 40 Td (Default ink) Tj ET\n1 0 0 rg BT /F1 18 Tf 10 10 Td (Red ink) Tj ET\n"
        let objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 80] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", "<< /Length \(stream.utf8.count) >>\nstream\n" + stream + "endstream"]
        var data = Data("%PDF-1.4\n".utf8), offsets = [Int]()
        for (i, object) in objects.enumerated() { offsets.append(data.count); data.append(Data("\(i+1) 0 obj\n\(object)\nendobj\n".utf8)) }
        let xref = data.count
        data.append(Data("xref\n0 6\n0000000000 65535 f \n".utf8))
        for offset in offsets { data.append(Data(String(format: "%010d 00000 n \n", offset).utf8)) }
        data.append(Data("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n\(xref)\n%%EOF\n".utf8))
        let document = try XCTUnwrap(PDFDocument(data: data)), delegate = PaperDocumentDelegate()
        document.delegate = delegate
        let page = try XCTUnwrap(document.page(at: 0))
        let context = try XCTUnwrap(CGContext(data: nil, width: 200, height: 80, bitsPerComponent: 8, bytesPerRow: 800,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.setFillColor(CGColor(gray: 1, alpha: 1)); context.fill(CGRect(x: 0, y: 0, width: 200, height: 80))
        page.draw(with: .mediaBox, to: context)
        let pixels = try XCTUnwrap(context.data).assumingMemoryBound(to: UInt8.self)
        var black = 0, red = 0
        for i in 0..<(200*80) {
            let p = i*4
            if pixels[p] < 60 && pixels[p+1] < 60 && pixels[p+2] < 60 { black += 1 }
            if pixels[p] > 180 && pixels[p+1] < 60 && pixels[p+2] < 60 { red += 1 }
        }
        XCTAssertGreaterThan(black, 20, "Default PDF ink must not inherit a white UI fill")
        XCTAssertGreaterThan(red, 20, "Explicit document colors must remain unchanged")
    }

    func testCAdESPDFHasReadOnlyPDFKitPreviewWithoutApprovingPAdES() async throws {
        try await SigningFormatStabilizationTests().fixture { _, batch, file in
            await batch.addDocuments([file], format: .cades)
            let snapshot = batch.documents[0].snapshot, original = try snapshot.verifiedBytes()
            let defaults = try XCTUnwrap(UserDefaults(suiteName: UUID().uuidString))
            let view = SignumWindow(batch: batch, selectedSnapshot: snapshot, automaticallyDiscover: false, defaults: defaults)
            let host = NSHostingView(rootView: view)
            let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 1200, height: 800), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = host; window.orderFront(nil)
            defer { window.close() }
            let deadline = Date().addingTimeInterval(5)
            while !PAdESGeometryStabilizationTests().descendants(host).contains(where: { ($0 as? PDFView)?.document != nil }) && Date() < deadline {
                try await Task.sleep(nanoseconds: 10_000_000); host.layoutSubtreeIfNeeded()
            }
            let previews = PAdESGeometryStabilizationTests().descendants(host).compactMap { $0 as? PDFView }
            XCTAssertEqual(previews.first?.document?.pageCount, 1)
            XCTAssertFalse(previews.contains { $0 is PlacementPDFView })
            XCTAssertFalse(batch.isApproved); XCTAssertEqual(batch.documents[0].format, .cades)
            XCTAssertEqual(try snapshot.verifiedBytes(), original)
        }
    }

    func testSameSnapshotChangingFormatRevokesPreviousPaneCallbacks() async throws {
        try await SigningFormatStabilizationTests().fixture { _,batch,file in
            await batch.addDocuments([file],format:.cades)
            let snapshot=batch.documents[0].snapshot, workspace=SigningWorkspaceSelection(snapshot:batch.documents[0].snapshot,format:.cades)
            XCTAssertFalse(workspace.showsPAdESPreview)
            try batch.setFormat(.pades,for:snapshot.identity.id);workspace.updateFormat(batch.documents[0].format)
            let old=workspace.generation
            XCTAssertTrue(workspace.showsPAdESPreview)
            try batch.setFormat(.cades,for:snapshot.identity.id);workspace.updateFormat(batch.documents[0].format)
            XCTAssertFalse(workspace.showsPAdESPreview);XCTAssertFalse(workspace.accepts(snapshot.identity.id,generation:old))
            try batch.setFormat(.pades,for:snapshot.identity.id);workspace.updateFormat(batch.documents[0].format)
            XCTAssertTrue(workspace.showsPAdESPreview);XCTAssertFalse(workspace.accepts(snapshot.identity.id,generation:old))
            XCTAssertTrue(workspace.snapshot === snapshot)
        }
    }
    func testNativeWorkspaceFollowsCurrentConfigurationInsteadOfAcquisitionHint() async throws {
        try await SigningFormatStabilizationTests().fixture { _,batch,file in
            await batch.addDocuments([file],format:.cades)
            let snapshot=batch.documents[0].snapshot, workspace=SigningWorkspaceSelection(snapshot:batch.documents[0].snapshot,format:.cades)
            let defaultsName=UUID().uuidString, defaults=try XCTUnwrap(UserDefaults(suiteName:defaultsName))
            defer { defaults.removePersistentDomain(forName:defaultsName) }
            let root=SignumWindow(batch:batch,selectedSnapshot:snapshot,automaticallyDiscover:false,defaults:defaults,workspace:workspace)
            let host=NSHostingView(rootView:root), window=NSWindow(contentRect:CGRect(x:0,y:0,width:1100,height:760),styleMask:[.titled,.resizable],backing:.buffered,defer:false)
            window.isReleasedWhenClosed=false;window.contentView=host;window.orderFront(nil);defer { window.close() }
            @MainActor func settle() async throws { host.layoutSubtreeIfNeeded();try await Task.sleep(nanoseconds:100_000_000);host.layoutSubtreeIfNeeded() }
            @MainActor func previews()->[PlacementPDFView] { PAdESGeometryStabilizationTests().descendants(host).compactMap { $0 as? PlacementPDFView } }
            try await settle();XCTAssertTrue(previews().isEmpty)
            for _ in 0..<3 {
                try batch.setFormat(.pades,for:snapshot.identity.id)
                try await settle();XCTAssertTrue(workspace.showsPAdESPreview);XCTAssertEqual(previews().count,1)
                let generation=workspace.generation
                try batch.setFormat(.cades,for:snapshot.identity.id)
                try await settle();XCTAssertFalse(workspace.showsPAdESPreview);XCTAssertTrue(previews().isEmpty)
                XCTAssertFalse(workspace.accepts(snapshot.identity.id,generation:generation))
            }
            XCTAssertEqual(snapshot.format,.cades);XCTAssertEqual(batch.documents[0].format,.cades)
        }
    }
}
#endif
