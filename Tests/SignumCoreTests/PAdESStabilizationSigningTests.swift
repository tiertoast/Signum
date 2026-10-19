#if os(macOS)
import XCTest
import PDFKit
import ImageIO
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESStabilizationSigningTests: XCTestCase {
    func testFrozenMovedArtworkIsActuallySignedOnLargeRotatedVectorPages() async throws {
        guard let helper=ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Local helper required") }
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false)
        defer { try? FileManager.default.removeItem(at:root) }
        let signer=try SoftwareSigner(folder:root), mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
        for rotation in [0,90,180,270] {
            let media=CGRect(x:20,y:30,width:rotation == 270 ? 14400 : 3370,height:rotation == 270 ? 10000 : 2384)
            let crop=media.insetBy(dx:10,dy:20)
            let original=PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:rotation == 270 ? 10 : 1,vectors:10000)
            let file=root.appendingPathComponent("synthetic-\(rotation).pdf"); try original.write(to:file)
            let batch=BatchSigningCoordinator(); defer { batch.reset() }
            await batch.addDocuments([file],format:.pades)
            let snapshot=try XCTUnwrap(batch.documents.first?.snapshot)
            var c=PAdESAppearanceConfiguration(); c.showSigner=false; c.showLabel=false
            c.rectangle=CGRect(x:crop.minX+40,y:crop.minY+50,width:240,height:100)
            c.image=try PAdESAppearanceImage(data:PAdESAppearanceTests().image())
            let artwork=try PAdESAppearanceRenderer.render(c,certificateDER:signer.der,cropBox:crop)
            c.rectangle.origin=CGPoint(x:crop.midX,y:crop.midY)
            let approved=try artwork.placed(c,cropBox:crop)
            let viewer=PlacementPDFView(frame:CGRect(x:0,y:0,width:800,height:650))
            let window=SignaturePlacementOverlayTests().window(viewer);defer {window.close()}
            let preview=try XCTUnwrap(PDFDocument(data:snapshot.approvedBytes))
            viewer.install(document:preview,pageIndex:0);viewer.layoutSubtreeIfNeeded()
            XCTAssertNil(viewer.updatePlacementOverlay(approved))
            viewer.signatureOverlay.artworkView.displayIfNeeded()
            XCTAssertGreaterThan(try SignaturePlacementOverlayTests().pixels(viewer.signatureOverlay.artworkView),0)
            let mapped=viewer.signatureOverlay.convert(viewer.signatureOverlay.artworkView.frame,to:viewer)
            let expected=viewer.convert(approved.configuration.rectangle,from:try XCTUnwrap(preview.page(at:0)))
            XCTAssertEqual(mapped.midX,expected.midX,accuracy:0.01)
            XCTAssertEqual(mapped.midY,expected.midY,accuracy:0.01)
            XCTAssertEqual(viewer.signatureOverlay.approvedAppearance?.pdf,approved.pdf)
            let plan=try await batch.prepareReview(provider:mock.path.path,slot:7,
                certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders,
                appearances:[snapshot.identity.id:approved])
            try batch.freezeReview(plan); try batch.confirm(plan)
            c.rectangle.origin.x += 100 // mutable draft cannot affect the approved job
            // Even a later presentation change/closure cannot replace the frozen AP.
            viewer.updatePlacementOverlay(try approved.placed(c,cropBox:crop))
            viewer.updatePlacementOverlay(nil)
            let frozen=try XCTUnwrap(plan.jobs[0].padesAppearance)
            XCTAssertEqual(frozen.approvalIdentity,approved.approvalIdentity)
            try await batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in
                try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:operation,
                    executable:URL(fileURLWithPath:helper))
            }
            XCTAssertEqual(batch.documents[0].state,.completed,batch.documents[0].result)
            let job=plan.jobs[0], output=try Data(contentsOf:job.destination)
            XCTAssertTrue(output.starts(with:original)); XCTAssertEqual(try Data(contentsOf:file),original)
            let result=try SignumVerificationService.verify(data:output,name:"synthetic.pdf",helper:URL(fileURLWithPath:helper))
            XCTAssertTrue(result.signatures.allSatisfy { $0.integrity == .verified })
            let cg=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:output as CFData))))
            let page=try XCTUnwrap(cg.page(at:1)); var annotations:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(page.dictionary),"Annots",&annotations))
            let array=try XCTUnwrap(annotations); var annotation:CGPDFDictionaryRef?
            XCTAssertTrue(CGPDFArrayGetDictionary(array,CGPDFArrayGetCount(array)-1,&annotation))
            var ap:CGPDFDictionaryRef?, stream:CGPDFStreamRef?, rect:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(annotation),"AP",&ap))
            XCTAssertTrue(CGPDFDictionaryGetStream(try XCTUnwrap(ap),"N",&stream))
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(annotation),"Rect",&rect))
            for (i,value) in [approved.configuration.rectangle.minX,approved.configuration.rectangle.minY,approved.configuration.rectangle.maxX,approved.configuration.rectangle.maxY].enumerated() {
                var n:CGPDFReal=0; XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(rect),i,&n)); XCTAssertEqual(n,value,accuracy:0.001)
            }
            // Compare actual /AP rendering with the same bytes flattened into page
            // content using independent Poppler, when explicitly supplied locally.
            if let poppler=ProcessInfo.processInfo.environment["SIGNUM_TEST_POPPLER"] {
                let flat=NSMutableData(); var box=media
                let context=try XCTUnwrap(CGContext(consumer:try XCTUnwrap(CGDataConsumer(data:flat)),mediaBox:&box,nil))
                context.beginPDFPage(nil)
                let src=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:original as CFData))))
                context.drawPDFPage(try XCTUnwrap(src.page(at:1)))
                context.translateBy(x:approved.configuration.rectangle.minX,y:approved.configuration.rectangle.minY)
                let artwork=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:approved.pdf as CFData))))
                context.drawPDFPage(try XCTUnwrap(artwork.page(at:1))); context.endPDFPage(); context.closePDF()
                let reference=try XCTUnwrap(PDFDocument(data:flat as Data)), rp=try XCTUnwrap(reference.page(at:0))
                rp.rotation=rotation; rp.setBounds(crop,for:.cropBox)
                let referenceURL=root.appendingPathComponent("reference.pdf"); try XCTUnwrap(reference.dataRepresentation()).write(to:referenceURL)
                var centers:[CGPoint]=[]
                for (name,pdf) in [("actual",job.destination),("reference",referenceURL)] {
                    let prefix=root.appendingPathComponent(name)
                    let process=Process(); process.executableURL=URL(fileURLWithPath:poppler)
                    process.arguments=["-f","1","-singlefile","-cropbox","-scale-to","1600","-png",pdf.path,prefix.path]
                    process.standardOutput=FileHandle.nullDevice; process.standardError=FileHandle.nullDevice
                    try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus,0)
                    let source=try XCTUnwrap(CGImageSourceCreateWithURL(prefix.appendingPathExtension("png") as CFURL,nil))
                    let image=try XCTUnwrap(CGImageSourceCreateImageAtIndex(source,0,nil))
                    let bitmap=try XCTUnwrap(CGContext(data:nil,width:image.width,height:image.height,bitsPerComponent:8,bytesPerRow:image.width*4,
                        space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
                    bitmap.draw(image,in:CGRect(x:0,y:0,width:image.width,height:image.height))
                    let bytes=bitmap.data!.assumingMemoryBound(to:UInt8.self); var points:[CGPoint]=[]
                    for y in 0..<image.height { for x in 0..<image.width { let i=(y*image.width+x)*4
                        if bytes[i]>200 && Int(bytes[i])-Int(bytes[i+1])>60 { points.append(CGPoint(x:x,y:y)) }
                    } }
                    XCTAssertFalse(points.isEmpty,"Actual signed /AP must contain red pixels")
                    centers.append(CGPoint(x:points.map(\.x).reduce(0,+)/CGFloat(max(1,points.count)),y:points.map(\.y).reduce(0,+)/CGFloat(max(1,points.count))))
                }
                XCTAssertEqual(centers[0].x,centers[1].x,accuracy:2)
                XCTAssertEqual(centers[0].y,centers[1].y,accuracy:2)
                print("STABILIZATION actual_signed_ap rotation=\(rotation) poppler_red_centroids=\(centers) crypto=valid original=unchanged")
            }
        }
    }
}
#endif
