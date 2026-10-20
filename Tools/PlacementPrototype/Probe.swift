import AppKit
import SwiftUI
import PDFKit
import ImageIO
import SignumCore

func pdf(origin:CGPoint,rotation:Int)->Data {
 let media=CGRect(origin:origin,size:CGSize(width:3370,height:2384)),crop=media.insetBy(dx:10,dy:20)
 let content=(0..<10000).map { i in "0.75 G \(origin.x+Double(i%3300)) \(origin.y+Double(i%2300)) m \(origin.x+Double(i%3300)+30) \(origin.y+Double(i%2300)+40) l S" }.joined(separator:"\n")
 let objects=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [\(media.minX) \(media.minY) \(media.maxX) \(media.maxY)] /CropBox [\(crop.minX) \(crop.minY) \(crop.maxX) \(crop.maxY)] /Rotate \(rotation) /Contents 4 0 R >>","<< /Length \(content.utf8.count) >>\nstream\n"+content+"\nendstream"]
 var bytes=Data("%PDF-1.7\n".utf8),offsets=[0]
 for (i,o) in objects.enumerated() {offsets.append(bytes.count);bytes.append(Data("\(i+1) 0 obj\n\(o)\nendobj\n".utf8))}
 let x=bytes.count;bytes.append(Data("xref\n0 5\n0000000000 65535 f \n".utf8));for n in offsets.dropFirst(){bytes.append(Data(String(format:"%010d 00000 n \n",n).utf8))};bytes.append(Data("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n\(x)\n%%EOF\n".utf8));return bytes
}
final class ProbeAction:NSObject {
 let body:()->Void
 init(_ body:@escaping ()->Void) {self.body=body}
 @objc func invokeZoom(_ sender:NSButton) {body()}
}
@main struct Probe {
 @MainActor static func main() throws {
  setbuf(stdout,nil)
  _=NSApplication.shared;NSApp.setActivationPolicy(.regular)
  let variant=CommandLine.arguments.dropFirst().first ?? "zero"
  let origin:CGPoint = variant == "zero" ? .zero : CGPoint(x:10000,y:-50000)
  let rotation=variant == "rotated" ? 90 : 0
  let bytes:Data
  bytes=pdf(origin:origin,rotation:rotation)
  let ref=PDFDocument(data:bytes)!.page(at:0)!.pageRef!
  let crop=ref.getBoxRect(.cropBox).intersection(ref.getBoxRect(.mediaBox))
  var config=PAdESAppearanceConfiguration();config.showSigner=false;config.customText="SYNTHETIC STAMP";config.rectangle=CGRect(x:crop.minX+30,y:crop.minY+30,width:240,height:100)
  let art=try PAdESAppearanceRenderer.render(config,certificateDER:Data(),cropBox:crop)
  let window=NSWindow(contentRect:CGRect(x:60,y:60,width:1240,height:720),styleMask:[.titled,.closable,.resizable],backing:.buffered,defer:false)
  window.isReleasedWhenClosed=false;window.title="Signum B11 — ANNOTATION LEFT / OVERLAY RIGHT — \(variant)"
  let root=NSView(frame:CGRect(x:0,y:0,width:1240,height:720));window.contentView=root
  let old=ReferencePlacementPDFView(frame:CGRect(x:0,y:0,width:610,height:680)),fresh=PlacementPDFView(frame:CGRect(x:630,y:0,width:610,height:680))
  root.addSubview(old);root.addSubview(fresh)
  let overlay=fresh.signatureOverlay
  old.install(document:PDFDocument(data:bytes)!,pageIndex:0);fresh.install(document:PDFDocument(data:bytes)!,pageIndex:0)
  old.updateAppearance(art);fresh.updatePlacementOverlay(art)
  let place:(PDFPage,CGPoint)->Void = { _,point in
   config.rectangle.origin=CGPoint(x:min(max(point.x-120,crop.minX),crop.maxX-240),y:min(max(point.y-50,crop.minY),crop.maxY-100))
   if let moved=try? art.placed(config,cropBox:crop) {old.updateAppearance(moved);fresh.updatePlacementOverlay(moved)}
  }
  old.onChoose=place;fresh.onChoose=place
  var actions:[ProbeAction]=[]
  for (i,zoom) in [0.25,1.0,2.0].enumerated() {
   let action=ProbeAction {
    for v in [old as PDFView,fresh as PDFView] {v.scaleFactor=zoom;v.go(to:PDFDestination(page:v.document!.page(at:0)!,at:CGPoint(x:crop.midX,y:crop.midY)))}
   }
   actions.append(action)
   let button=NSButton(title:"Zoom \(Int(zoom*100))%",target:action,action:#selector(ProbeAction.invokeZoom(_:)))
   button.frame=CGRect(x:20+i*160,y:685,width:145,height:28);root.addSubview(button)
  }
  window.makeKeyAndOrderFront(nil);NSApp.activate(ignoringOtherApps:true)
  DispatchQueue.main.asyncAfter(deadline:.now()+1) {
   for v in [old as PDFView,fresh as PDFView] {v.layoutSubtreeIfNeeded();v.scaleFactor=1;v.go(to:PDFDestination(page:v.document!.page(at:0)!,at:CGPoint(x:crop.midX,y:crop.midY)))}
   DispatchQueue.main.asyncAfter(deadline:.now()+1) {
    let page=old.document!.page(at:0)!, center=old.convert(CGPoint(x:old.bounds.midX,y:old.bounds.midY),to:page)
    config.rectangle.origin=CGPoint(x:center.x-120,y:center.y-50)
    let moved=try! art.placed(config,cropBox:crop)
    old.updateAppearance(moved);fresh.updatePlacementOverlay(moved);window.displayIfNeeded()
    print("PROBE_READY window=\(window.windowNumber) pid=\(ProcessInfo.processInfo.processIdentifier) rect=\(moved.configuration.rectangle) active_overlay_painted=\(overlay.artworkView.hasPainted)")
    if CommandLine.arguments.contains("--auto-close") { window.close(); exit(0) }
   }
  }
  NSApp.run();withExtendedLifetime((window,old,fresh,overlay,actions)) {}
 }
}
