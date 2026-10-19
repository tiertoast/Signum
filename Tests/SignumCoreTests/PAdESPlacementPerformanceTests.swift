#if os(macOS)
import XCTest
import PDFKit
import ImageIO
import SwiftUI
import Darwin
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESPlacementPerformanceTests: XCTestCase {
    static func png(_ size: Int) throws -> Data {
        let context = try XCTUnwrap(CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        for x in stride(from: 0, to: size, by: 32) {
            context.setFillColor(CGColor(red: Double(x%255)/255, green: 0.2, blue: 0.6, alpha: 0.8))
            context.fill(CGRect(x: x, y: 0, width: 32, height: size))
        }
        let result = NSMutableData(), destination = try XCTUnwrap(CGImageDestinationCreateWithData(result,"public.png" as CFString,1,nil))
        CGImageDestinationAddImage(destination,try XCTUnwrap(context.makeImage()),nil)
        XCTAssertTrue(CGImageDestinationFinalize(destination)); return result as Data
    }
    func testThirtyAndOneHundredTwentyMovesReuseBytesHashAndAnnotationForEveryImageSize() throws {
        let crop = CGRect(x: 0, y: 0, width: 3370, height: 2384)
        for pixels in [0,1024,2800] {
            var config = PAdESAppearanceConfiguration(); config.showSigner = false
            if pixels > 0 { config.image = try PAdESAppearanceImage(data: Self.png(pixels)) }
            let artwork = try PAdESAppearanceRenderer.render(config,certificateDER:Data(),cropBox:crop)
            let view = PlacementPDFView(frame:CGRect(x:0,y:0,width:850,height:600))
            view.install(document:try XCTUnwrap(PDFDocument(data:PAdESGeometryStabilizationTests.pdf(media:crop,vectors:10000))),pageIndex:0)
            view.layoutSubtreeIfNeeded(); XCTAssertNil(view.updateAppearance(artwork))
            let annotation = try XCTUnwrap(view.previewAnnotation)
            for events in [30,120] {
                var times:[Double] = []
                for index in 0..<events {
                    config.rectangle.origin = CGPoint(x: 40+index*2, y: 80)
                    let start = ProcessInfo.processInfo.systemUptime
                    let placed = try artwork.placed(config,cropBox:crop)
                    XCTAssertNil(view.updateAppearance(placed))
                    times.append((ProcessInfo.processInfo.systemUptime-start)*1000)
                    XCTAssertEqual(placed.pdf,artwork.pdf); XCTAssertEqual(placed.sha256,artwork.sha256)
                    XCTAssertEqual(placed.artworkID,artwork.artworkID)
                    XCTAssertEqual(view.previewAnnotation?.bounds,config.rectangle)
                    XCTAssertTrue(annotation === view.previewAnnotation)
                    XCTAssertEqual(view.appearanceBuildCount,1)
                    if index > 0 { XCTAssertNotEqual(placed.approvalIdentity,artwork.approvalIdentity) }
                }
                let sorted=times.sorted()
                print("STABILIZATION placement pixels=\(pixels) events=\(events) median_ms=\(sorted[events/2]) p95_ms=\(sorted[Int(Double(events)*0.95)]) artwork_builds=\(view.appearanceBuildCount)")
            }
            for change in 0..<5 {
                var changed=config
                switch change {
                case 0: changed.customText="changed"
                case 1: changed.rectangle.size.width += 10
                case 2: changed.fontSize += 1
                case 3: changed.visible=false
                default: changed.localDate=Date()
                }
                XCTAssertThrowsError(try artwork.placed(changed,cropBox:crop))
            }
        }
    }
    final class ProbeState {
        var placement:PAdESPlacement?, commits=0, ready=0
        var eventTime=0.0, latencies:[Double]=[]
    }
    func testRealPaneDragAtSixtyEventsPerSecondDoesNotRenderOrApproveDuringMovement() async throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false)
        defer { try? FileManager.default.removeItem(at:root) }
        let crop=CGRect(x:0,y:0,width:3370,height:2384), file=root.appendingPathComponent("synthetic-vector.pdf")
        try PAdESGeometryStabilizationTests.pdf(media:crop,vectors:10000).write(to:file)
        for pixels in [0,1024,2800] {
            let snapshot=try DocumentSnapshot.capture(source:file,format:.pades); defer { snapshot.close() }
            var config=PAdESAppearanceConfiguration(); config.showSigner=false
            if pixels>0 { config.image=try PAdESAppearanceImage(data:Self.png(pixels)) }
            let artwork=try PAdESAppearanceRenderer.render(config,certificateDER:Data(),cropBox:crop)
            let state=ProbeState(); state.placement=PAdESPlacement(pageIndex:0,rectangle:config.rectangle,appearance:artwork)
            let coordinator=PAdESRenderCoordinator()
            let pane=PAdESPlacementPane(snapshot:snapshot,previewReady:{ _,ready in if ready { state.ready+=1 } },holder:"Synthetic",
                placement:Binding(get:{state.placement},set:{ value in
                    state.placement=value; state.commits+=1
                    if state.eventTime>0 { state.latencies.append((ProcessInfo.processInfo.systemUptime-state.eventTime)*1000) }
                }),renderCoordinator:coordinator)
            let host=NSHostingView(rootView:pane), window=NSWindow(contentRect:CGRect(x:0,y:0,width:850,height:700),styleMask:[.titled,.resizable],backing:.buffered,defer:false)
            window.isReleasedWhenClosed=false; window.title="Signum — fixture sintetica"; window.contentView=host; window.orderFront(nil)
            defer { window.close() }
            for _ in 0..<100 { host.layoutSubtreeIfNeeded(); if state.ready>0 && coordinator.isIdle { break }; try await Task.sleep(nanoseconds:10_000_000) }
            let view=try XCTUnwrap(PAdESGeometryStabilizationTests().descendants(host).compactMap { $0 as? PlacementPDFView }.first)
            let page=try XCTUnwrap(view.document?.page(at:0))
            let builds=view.signatureOverlay.artworkBuildCount, rasters=view.signatureOverlay.artworkView.drawCount, renders=coordinator.started
            let payloadHash=state.placement?.appearance?.sha256
            XCTAssertGreaterThan(state.ready,0)
            @MainActor func event(_ type:NSEvent.EventType, _ raw:CGPoint)->NSEvent {
                let p=view.convert(view.convert(raw,from:page),to:nil)
                return NSEvent.mouseEvent(with:type,location:p,modifierFlags:[],timestamp:ProcessInfo.processInfo.systemUptime,
                    windowNumber:window.windowNumber,context:nil,eventNumber:1,clickCount:1,pressure:1)!
            }
            let startPoint=view.convert(CGPoint(x:view.bounds.midX,y:view.bounds.midY),to:page)
            for count in [30,120] {
                view.mouseDown(with:event(.leftMouseDown,startPoint)); try await Task.sleep(nanoseconds:30_000_000)
                state.ready=0; state.commits=0; state.latencies=[]
                let begin=ProcessInfo.processInfo.systemUptime
                var last=startPoint
                for i in 1...count {
                    last=CGPoint(x:startPoint.x+CGFloat(i),y:startPoint.y)
                    state.eventTime=ProcessInfo.processInfo.systemUptime
                    view.mouseDragged(with:event(.leftMouseDragged,last))
                    let remaining=begin+Double(i)/60-ProcessInfo.processInfo.systemUptime
                    if remaining>0 { try await Task.sleep(nanoseconds:UInt64(remaining*1_000_000_000)) }
                    XCTAssertEqual(state.ready,0,"No consent/preflight readiness during drag")
                }
                state.eventTime=0
                view.mouseUp(with:event(.leftMouseUp,last)); try await Task.sleep(nanoseconds:50_000_000)
                XCTAssertEqual(coordinator.started,renders); XCTAssertEqual(view.signatureOverlay.artworkBuildCount,builds)
                XCTAssertEqual(view.signatureOverlay.artworkView.drawCount,rasters)
                XCTAssertGreaterThanOrEqual(state.commits,count-1); XCTAssertEqual(state.ready,1)
                XCTAssertEqual(state.placement?.appearance?.sha256,payloadHash)
                let values=state.latencies.sorted()
                XCTAssertFalse(values.isEmpty)
                if !values.isEmpty {
                    var usage=rusage(); _=getrusage(RUSAGE_SELF,&usage)
                    print("STABILIZATION real_pane pixels=\(pixels) events=\(count) commits=\(state.commits) renders_during_drag=\(coordinator.started-renders) overlay_builds_during_drag=\(view.signatureOverlay.artworkBuildCount-builds) rasterizations_during_drag=\(view.signatureOverlay.artworkView.drawCount-rasters) median_ms=\(values[values.count/2]) p95_ms=\(values[min(values.count-1,Int(Double(values.count)*0.95))]) elapsed_ms=\((ProcessInfo.processInfo.systemUptime-begin)*1000) ready_after_release=\(state.ready) process_peak_rss_bytes=\(usage.ru_maxrss)")
                }
                // A no-op click must restore readiness on release.
                state.ready=0; view.mouseDown(with:event(.leftMouseDown,last)); view.mouseUp(with:event(.leftMouseUp,last))
                try await Task.sleep(nanoseconds:30_000_000); XCTAssertEqual(state.ready,1)
            }
        }
    }

}
#endif
