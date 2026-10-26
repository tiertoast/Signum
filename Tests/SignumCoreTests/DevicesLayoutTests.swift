#if os(macOS)
import XCTest
import SwiftUI
import AppKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class DevicesLayoutTests: XCTestCase {
    func testSyntheticDevicesRenderInLightAndDarkWithoutAccessingMiddleware() async throws {
        guard !NSScreen.screens.isEmpty else { throw XCTSkip("Requires WindowServer") }
        _ = NSApplication.shared
        let fixture = DevicesPresentationTests()
        let dna = try fixture.observed("dna",model:"DigitalDNA",certificates:["valid","authentication","expired"])
        let cns = try fixture.observed("cns",model:"CNS",certificates:["replaced"],serial:"CNS-TEST")
        let selection = fixture.selection([dna,cns])
        let folder = try FixtureFiles.directory("build11-devices-synthetic",evidence:true)
        let previous = NSApp.appearance
        defer { NSApp.appearance = previous }
        for dark in [false,true] {
            let name: NSAppearance.Name = dark ? .darkAqua:.aqua
            NSApp.appearance = NSAppearance(named:name)
            let pane = DevicesExperiencePane(selection:selection,locked:false,status:selection.message,
                configure:{XCTFail("Rendering cannot configure a module")},selectRoute:{_ in XCTFail("Rendering cannot select a route")})
            let root = pane.environment(\.colorScheme,dark ? .dark:.light)
                .safeAreaInset(edge:.bottom) { Text("DATI SINTETICI · anteprima di test, nessun dispositivo fisico").font(.caption).padding(8) }
            let host = NSHostingView(rootView:root)
            let frame = NSRect(x:0,y:0,width:1000,height:1000)
            let window = NSWindow(contentRect:frame,styleMask:[.titled],backing:.buffered,defer:false)
            window.isReleasedWhenClosed=false;window.contentView=host;host.frame=frame
            window.orderFront(nil);host.layoutSubtreeIfNeeded()
            await Task.yield();host.layoutSubtreeIfNeeded();window.displayIfNeeded()
            let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in:host.bounds))
            host.cacheDisplay(in:host.bounds,to:bitmap)
            let image = try XCTUnwrap(bitmap.representation(using:.png,properties:[:]))
            try image.write(to:folder.appendingPathComponent(dark ? "Dispositivi-sintetici-Dark.png":"Dispositivi-sintetici-Light.png"))
            window.close()
        }
        XCTAssertNil(selection.selectedRouteID)
    }
}
#endif
