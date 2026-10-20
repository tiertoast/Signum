#if os(macOS)
import XCTest
import SwiftUI
import PDFKit
@testable import SignumApp
@testable import SignumCore

@MainActor final class DynamicFormatWorkspaceTests: XCTestCase {
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
