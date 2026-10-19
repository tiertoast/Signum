import AppKit
import SwiftUI
import PDFKit
import SignumCore

final class ProbeDelegate:NSObject,NSApplicationDelegate {
    var snapshot:DocumentSnapshot?
    var temporary:URL?
    func applicationWillTerminate(_ notification:Notification) {
        snapshot?.close()
        if let temporary {try? FileManager.default.removeItem(at:temporary)}
    }
}
@MainActor final class PlacementState {
    var placement:PAdESPlacement?
}
@main struct OrientationProbe {
    @MainActor static func main() throws {
        setbuf(stdout,nil)
        _=NSApplication.shared;NSApp.setActivationPolicy(.regular)
        let delegate=ProbeDelegate();NSApp.delegate=delegate
        let input:URL
        if CommandLine.arguments.count==2, !CommandLine.arguments[1].hasPrefix("--") {input=URL(fileURLWithPath:CommandLine.arguments[1])}
        else {
            let root=FileManager.default.temporaryDirectory.appendingPathComponent("SignumOrientation-"+UUID().uuidString)
            try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
            delegate.temporary=root;input=root.appendingPathComponent("synthetic.pdf")
            let bytes=NSMutableData();var box=CGRect(x:0,y:0,width:1304,height:1843)
            let c=CGContext(consumer:CGDataConsumer(data:bytes)!,mediaBox:&box,nil)!
            c.beginPDFPage(nil);c.setStrokeColor(CGColor(gray:0.8,alpha:1))
            for i in 0..<10000 {c.move(to:CGPoint(x:i%1200,y:i%1800));c.addLine(to:CGPoint(x:(i%1200)+20,y:(i%1800)+20));c.strokePath()}
            c.endPDFPage();c.closePDF()
            let doc=PDFDocument(data:bytes as Data)!;doc.page(at:0)!.rotation=90
            try doc.dataRepresentation()!.write(to:input)
        }
        let snapshot=try DocumentSnapshot.capture(source:input,format:.pades);delegate.snapshot=snapshot
        let doc=PDFDocument(data:snapshot.approvedBytes)!,page=doc.page(at:0)!.pageRef!
        let crop=page.getBoxRect(.cropBox).intersection(page.getBoxRect(.mediaBox)),rotation=Int(page.rotationAngle)
        var config=PAdESAppearanceConfiguration();config.showSigner=false;config.customText="READ 123 ->"
        config.rectangle=CGRect(x:crop.midX-120,y:crop.midY-45,width:240,height:90)
        config=try config.reoriented(to:.automatic,fromPageRotation:0,toPageRotation:rotation,cropBox:crop)
        let art=try PAdESAppearanceRenderer.render(config,certificateDER:Data(),cropBox:crop,pageRotation:rotation)
        let state=PlacementState();state.placement=PAdESPlacement(pageIndex:0,rectangle:config.rectangle,appearance:art)
        let pane=PAdESPlacementPane(snapshot:snapshot,previewReady:{_,ready in print("READY",ready)},holder:"Synthetic",
            placement:Binding(get:{state.placement},set:{p in
                state.placement=p
                if let p,let a=p.appearance {print("PLACEMENT",a.configuration.orientation.rawValue,"page_rotation",a.pageRotation ?? -1,"rect",p.rectangle)}
            }))
        let window=NSWindow(contentRect:CGRect(x:30,y:30,width:1000,height:850),styleMask:[.titled,.closable,.resizable],backing:.buffered,defer:false)
        window.isReleasedWhenClosed=false;window.title="Signum B12 — orientation preview only"
        window.contentView=NSHostingView(rootView:pane)
        let menu=NSMenu(),item=NSMenuItem(),appMenu=NSMenu()
        appMenu.addItem(withTitle:"Quit probe",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q")
        item.submenu=appMenu;menu.addItem(item);NSApp.mainMenu=menu
        window.makeKeyAndOrderFront(nil);NSApp.activate(ignoringOtherApps:true)
        if CommandLine.arguments.contains("--smoke") {
            DispatchQueue.main.asyncAfter(deadline:.now()+2) {NSApp.terminate(nil)}
        }
        NSApp.run();withExtendedLifetime((window,delegate,state)){}
    }
}
