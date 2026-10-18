#if os(macOS)
import XCTest
import PDFKit
import ImageIO
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

final class PAdESAppearanceTests: XCTestCase {
    let crop = CGRect(x:50,y:70,width:400,height:450)
    func image(_ jpeg:Bool = false) throws -> Data {
        let ctx=try XCTUnwrap(CGContext(data:nil,width:24,height:16,bitsPerComponent:8,bytesPerRow:0,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        ctx.setFillColor(CGColor(red:1,green:0,blue:0,alpha:jpeg ? 1 : 0.5)); ctx.fill(CGRect(x:0,y:0,width:20,height:16))
        let data=NSMutableData(), cg=try XCTUnwrap(ctx.makeImage())
        let dest=try XCTUnwrap(CGImageDestinationCreateWithData(data,jpeg ? "public.jpeg" as CFString : "public.png" as CFString,1,nil))
        CGImageDestinationAddImage(dest,cg,nil); XCTAssertTrue(CGImageDestinationFinalize(dest)); return data as Data
    }
    func pdf(rotation:Int = 0, pages:Int = 2) throws -> Data {
        let bytes=NSMutableData(); var media=CGRect(x:20,y:30,width:500,height:600)
        let ctx=try XCTUnwrap(CGContext(consumer:try XCTUnwrap(CGDataConsumer(data:bytes)),mediaBox:&media,nil))
        for _ in 0..<pages { ctx.beginPDFPage(nil); ctx.endPDFPage() }; ctx.closePDF()
        let doc=try XCTUnwrap(PDFDocument(data:bytes as Data))
        for index in 0..<pages { let p=try XCTUnwrap(doc.page(at:index)); p.rotation=rotation; p.setBounds(crop,for:.cropBox) }
        return try XCTUnwrap(doc.dataRepresentation())
    }
    func config() -> PAdESAppearanceConfiguration {
        var c=PAdESAppearanceConfiguration(); c.rectangle=CGRect(x:80,y:100,width:280,height:110); return c
    }
    func testTypedTextDateUnicodeIdentityAndInvisibleConfiguration() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("valid")
        for variant in 0..<6 {
            var c=config()
            if variant == 0 { c.visible=false }
            if variant == 1 { c.showSigner=false }
            if variant == 2 { c.localDate=Date(timeIntervalSince1970:1_800_000_000) }
            if variant == 3 { c.customText="Nota personalizzata àè — sintetica" }
            if variant == 4 { c.alignment = .center }
            if variant == 5 { c.showLabel=false; c.alignment = .trailing }
            let rendered=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop)
            XCTAssertEqual(rendered.configuration,c)
            if !c.visible { XCTAssertTrue(rendered.pdf.isEmpty) }
            else { XCTAssertEqual(PDFDocument(data:rendered.pdf)?.pageCount,1); XCTAssertFalse(rendered.pdf.isEmpty) }
        }
        var c=config(); c.rectangle.size=CGSize(width:80,height:40); c.customText=String(repeating:"testo lungo ",count:80)
        XCTAssertThrowsError(try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop))
        c=config(); XCTAssertThrowsError(try PAdESAppearanceRenderer.render(c,certificateDER:Data([1,2]),cropBox:crop))
    }
    func testPNGJPEGTransparencyAndMalformedOrOversizedInputs() throws {
        for jpeg in [false,true] {
            let value=try PAdESAppearanceImage(data:image(jpeg)); XCTAssertEqual(value.width,24); XCTAssertEqual(value.height,16)
            var c=config(); c.image=value
            let der=try CertificateEligibilityTests.fixtures.get().der("valid")
            XCTAssertFalse(try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop).pdf.isEmpty)
        }
        let huge=try XCTUnwrap(CGContext(data:nil,width:4096,height:2048,bitsPerComponent:8,bytesPerRow:0,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        let hugeData=NSMutableData(),hugeDest=try XCTUnwrap(CGImageDestinationCreateWithData(hugeData,"public.png" as CFString,1,nil))
        CGImageDestinationAddImage(hugeDest,try XCTUnwrap(huge.makeImage()),nil);XCTAssertTrue(CGImageDestinationFinalize(hugeDest))
        XCTAssertThrowsError(try PAdESAppearanceImage(data:hugeData as Data))
        for data in [Data([1,2,3]),Data(repeating:1,count:PAdESAppearanceImage.maximumBytes+1),Data(try image().prefix(40))] {
            XCTAssertThrowsError(try PAdESAppearanceImage(data:data))
        }
    }
    func testBoundsAndApprovalIdentityIncludePagePositionAndCertificate() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("valid")
        var c=config(); let first=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop)
        c.rectangle.origin.x+=1
        let moved=try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop)
        XCTAssertNotEqual(first.approvalIdentity,moved.approvalIdentity)
        for r in [CGRect(x:0,y:0,width:200,height:90),CGRect(x:80,y:100,width:79,height:40),CGRect(x:80,y:100,width:801,height:40),CGRect(x:80,y:100,width:100,height:501)] {
            c.rectangle=r; XCTAssertThrowsError(try c.validate(cropBox:crop))
        }
        c=config(); c.showSigner=false; c.rectangle=CGRect(x:50,y:70,width:80,height:40); c.fontSize=7
        XCTAssertNoThrow(try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop))
        c.rectangle=CGRect(x:0,y:0,width:800,height:500)
        XCTAssertNoThrow(try c.validate(cropBox:CGRect(x:0,y:0,width:1000,height:1000)))
    }
    @MainActor func testPDFKitCoordinatesRoundTripAtZoomForRotatedCropBoxes() throws {
        for rotation in [0,90,180,270] {
            let doc=try XCTUnwrap(PDFDocument(data:pdf(rotation:rotation)))
            let view=PlacementPDFView(frame:CGRect(x:0,y:0,width:750,height:600)); view.document=doc; view.displayMode = .singlePage
            let page=try XCTUnwrap(doc.page(at:0))
            for zoom in [0.5,1,2] {
                view.scaleFactor=zoom
                let original=CGPoint(x:140,y:180), point=view.convert(original,from:page), back=view.convert(point,to:page)
                XCTAssertEqual(original.x,back.x,accuracy:0.01); XCTAssertEqual(original.y,back.y,accuracy:0.01)
                let beforeScroll=view.convert(original,from:page)
                view.go(to:PDFDestination(page:page,at:CGPoint(x:200,y:300)))
                view.documentView?.scroll(CGPoint(x:40,y:60))
                let scrolled=view.convert(view.convert(original,from:page),to:page)
                XCTAssertEqual(original.x,scrolled.x,accuracy:0.01);XCTAssertEqual(original.y,scrolled.y,accuracy:0.01)
                if zoom == 2 { XCTAssertNotEqual(beforeScroll,view.convert(original,from:page),"A zoomed preview must actually scroll") }
            }
        }
    }
    func signed(_ source:Data,configuration:PAdESAppearanceConfiguration,root:URL,signer:SoftwareSigner,mock:MockModule,name:String) throws -> (Data,RenderedPAdESAppearance) {
        guard let helper=ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Native helper required") }
        let file=root.appendingPathComponent(name+".pdf"); try source.write(to:file)
        let snapshot=try DocumentSnapshot.capture(source:file,format:.pades,privateRoot:root)
        let job=try SigningJob(snapshot:snapshot,providerPath:mock.path.path,slot:7,certificate:.init(label:"Untrusted label",identifier:Data([1])),certificateDER:signer.der,destination:root.appendingPathComponent(name+"-signed.pdf"))
        let appearance=try PAdESAppearanceRenderer.render(configuration,certificateDER:signer.der,cropBox:crop)
        try SignumPAdESHelper.sign(job:job,pin:"synthetic-fixture",appearanceName:"Ignored unverified label",field:nil,executable:URL(fileURLWithPath:helper),appearance:appearance)
        XCTAssertEqual(try Data(contentsOf:file),source); XCTAssertFalse(FileManager.default.fileExists(atPath:snapshot.fileURL.path))
        return (try Data(contentsOf:job.destination),appearance)
    }
    @MainActor func testSignedPDFContainsActualAppearanceForTextPNGJPEGAndEveryRotation() throws {
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]); defer { try? FileManager.default.removeItem(at:root) }
        let signer=try SoftwareSigner(folder:root), mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
        for (i,rotation) in [0,90,180,270].enumerated() {
            var c=config(); c.pageIndex=i%2; c.localDate=Date(timeIntervalSince1970:1_800_000_000); c.customText="Nota sintetica"
            if i>0 { c.image=try PAdESAppearanceImage(data:image(i==2)) }
            let original=try pdf(rotation:rotation)
            let (bytes,appearance)=try signed(original,configuration:c,root:root,signer:signer,mock:mock,name:"rotation-\(rotation)")
            let cg=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:bytes as CFData))))
            let page=try XCTUnwrap(cg.page(at:c.pageIndex+1)); var annotations:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(page.dictionary),"Annots",&annotations)); let array=try XCTUnwrap(annotations)
            var widget:CGPDFDictionaryRef?; XCTAssertTrue(CGPDFArrayGetDictionary(array,CGPDFArrayGetCount(array)-1,&widget))
            var ap:CGPDFDictionaryRef?, stream:CGPDFStreamRef?, rect:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(widget),"AP",&ap))
            XCTAssertTrue(CGPDFDictionaryGetStream(try XCTUnwrap(ap),"N",&stream))
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(widget),"Rect",&rect))
            for (index,expected) in [c.rectangle.minX,c.rectangle.minY,c.rectangle.maxX,c.rectangle.maxY].enumerated() {
                var number:CGPDFReal=0; XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(rect),index,&number)); XCTAssertEqual(number,expected,accuracy:0.001)
            }
            var resources:CGPDFDictionaryRef?
            XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(CGPDFStreamGetDictionary(try XCTUnwrap(stream))),"Resources",&resources))
            var font:CGPDFDictionaryRef?; XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(resources),"Font",&font))
            if c.image != nil { var images:CGPDFDictionaryRef?; XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(resources),"XObject",&images)); XCTAssertGreaterThan(CGPDFDictionaryGetCount(try XCTUnwrap(images)),0) }
            let outputDocument=try XCTUnwrap(PDFDocument(data:bytes)), previewDocument=try XCTUnwrap(PDFDocument(data:original))
            _ = try XCTUnwrap(outputDocument.page(at:c.pageIndex))
            let previewPage=try XCTUnwrap(previewDocument.page(at:c.pageIndex))
            previewPage.addAnnotation(try XCTUnwrap(AppearancePDFAnnotation(appearance:appearance)))
            func raster(_ page:PDFPage) throws -> (pixels:[UInt8],image:CGImage) {
                let thumbnail=page.thumbnail(of:CGSize(width:600,height:600),for:.mediaBox)
                let image=try XCTUnwrap(thumbnail.cgImage(forProposedRect:nil,context:nil,hints:nil))
                let context=try XCTUnwrap(CGContext(data:nil,width:600,height:600,bitsPerComponent:8,bytesPerRow:2400,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
                context.setFillColor(CGColor(gray:1,alpha:1));context.fill(CGRect(x:0,y:0,width:600,height:600));context.draw(image,in:CGRect(x:0,y:0,width:image.width,height:image.height))
                return (Array(UnsafeBufferPointer(start:context.data!.assumingMemoryBound(to:UInt8.self),count:2400*600)),try XCTUnwrap(context.makeImage()))
            }
            // A flattened reference draws the exact same appearance PDF bytes
            // into page content. It is not a second appearance layout pipeline.
            let referenceBytes=NSMutableData();var media=CGRect(x:20,y:30,width:500,height:600)
            let referenceContext=try XCTUnwrap(CGContext(consumer:try XCTUnwrap(CGDataConsumer(data:referenceBytes)),mediaBox:&media,nil))
            referenceContext.beginPDFPage(nil);referenceContext.translateBy(x:c.rectangle.minX,y:c.rectangle.minY)
            let artwork=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:appearance.pdf as CFData))))
            referenceContext.drawPDFPage(try XCTUnwrap(artwork.page(at:1)));referenceContext.endPDFPage();referenceContext.closePDF()
            let referenceDoc=try XCTUnwrap(PDFDocument(data:referenceBytes as Data)),referencePage=try XCTUnwrap(referenceDoc.page(at:0))
            referencePage.rotation=rotation;referencePage.setBounds(crop,for:.cropBox)
            let expected=try raster(previewPage),actual=try raster(referencePage)
            let debug=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/04b-rendered")
            try FileManager.default.createDirectory(at:debug,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            try bytes.write(to:debug.appendingPathComponent("signed-\(rotation).pdf"))
            try XCTUnwrap(referenceDoc.dataRepresentation()).write(to:debug.appendingPathComponent("reference-\(rotation).pdf"))
            for (name,image) in [("preview",expected.image),("final",actual.image)] {
                let dest=try XCTUnwrap(CGImageDestinationCreateWithURL(debug.appendingPathComponent("page-\(name)-\(rotation).png") as CFURL,"public.png" as CFString,1,nil));CGImageDestinationAddImage(dest,image,nil);XCTAssertTrue(CGImageDestinationFinalize(dest))
            }
            XCTAssertLessThan(Double(zip(expected.pixels,actual.pixels).filter{abs(Int($0)-Int($1))>20}.count)/Double(actual.pixels.count),0.001)
            XCTAssertTrue(actual.pixels.enumerated().contains{$0.offset%4 != 3 && $0.element<100})
            withExtendedLifetime((outputDocument,previewDocument,referenceDoc)) {}
        }
    }
    func testInvisibleAndAlreadySignedPDFKeepValidIncrementalSignatures() throws {
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
        var c=config(); c.visible=false
        let (first,_)=try signed(pdf(),configuration:c,root:root,signer:signer,mock:mock,name:"invisible")
        c.visible=true;c.pageIndex=1
        let (second,_)=try signed(first,configuration:c,root:root,signer:signer,mock:mock,name:"second-signature")
        XCTAssertTrue(second.starts(with:first)); XCTAssertGreaterThan(second.count,first.count)
    }
    @MainActor func testThreePAdESUseDistinctFrozenAppearancesAndOnePINPerDocument() async throws {
        guard let helper=ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Native helper required") }
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try?FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
        let files=try (0..<3).map { index -> URL in let url=root.appendingPathComponent("batch-\(index).pdf");try pdf(rotation:index*90).write(to:url);return url }
        let batch=BatchSigningCoordinator();defer{batch.reset()};await batch.addDocuments(files,format:.pades)
        let plan=try await batch.prepareApproval(provider:mock.path.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der)
        let appearances=try plan.jobs.enumerated().map { index,job -> RenderedPAdESAppearance in
            var c=config();c.pageIndex=index%2;c.visible=index != 1;c.customText="Documento \(index)";return try PAdESAppearanceRenderer.render(c,certificateDER:job.certificateDER,cropBox:crop)
        }
        try batch.confirm(plan)
        for (index,_) in plan.jobs.enumerated() {
            let value=appearances[index]
            try await batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in
                try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:operation,executable:URL(fileURLWithPath:helper),appearance:value)
            }
        }
        XCTAssertTrue(batch.documents.allSatisfy{$0.state == .completed})
        let audit=try String(contentsOf:mock.folder.appendingPathComponent("operations")).split(separator:"\n")
        XCTAssertEqual(audit.filter{$0=="8"}.count,3);XCTAssertEqual(audit.filter{$0=="16"}.count,3)
    }
    func testAppearanceCannotChangeCertificateAndImagePathIsNeverReopened() throws {
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try?FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
        let input=root.appendingPathComponent("stamp.png");try image().write(to:input)
        var c=config();c.image=try PAdESAppearanceImage.load(input)
        let frozen=try PAdESAppearanceRenderer.render(c,certificateDER:signer.der,cropBox:crop)
        try Data("replaced".utf8).write(to:input)
        let (_,actual)=try signed(pdf(),configuration:c,root:root,signer:signer,mock:mock,name:"frozen-image")
        XCTAssertEqual(frozen.configuration.image,actual.configuration.image)
        let other=try CertificateEligibilityTests.fixtures.get().der("otherSigner")
        let inputPDF=root.appendingPathComponent("changed-cert.pdf");try pdf().write(to:inputPDF)
        let snapshot=try DocumentSnapshot.capture(source:inputPDF,format:.pades,privateRoot:root)
        let changed=try SigningJob(snapshot:snapshot,providerPath:mock.path.path,slot:7,certificate:.init(label:"label does not authorize",identifier:Data([1])),certificateDER:other,destination:root.appendingPathComponent("forbidden.pdf"))
        XCTAssertThrowsError(try SignumPAdESHelper.sign(job:changed,pin:"synthetic-fixture",appearanceName:"unused",field:nil,executable:ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map{URL(fileURLWithPath:$0)},appearance:frozen)) { XCTAssertTrue($0.localizedDescription.contains("Appearance non vincolata")) }
        XCTAssertFalse(FileManager.default.fileExists(atPath:changed.destination.path))
        var contextA=SigningReviewContext(revision:UUID(),provider:"/synthetic",slot:7,certificate:.init(label:"a",identifier:Data([1])),der:signer.der,destination:.originalFolders,routeID:"route",discoveryID:UUID())
        var contextB=contextA;contextA.appearanceHashes=[UUID():frozen.approvalIdentity]
        XCTAssertNotEqual(contextA,contextB)
        contextB.appearanceHashes=contextA.appearanceHashes;XCTAssertEqual(contextA,contextB)
    }
    func testNativeAppearanceTimeoutAndCrashDoNotPublishOrRetry() throws {
        guard let helper=ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Native helper required") }
        for effect in [2,3] {
            let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try?FileManager.default.removeItem(at:root)}
            let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),workerPhase:16,workerEffect:effect,audit:true)
            let file=root.appendingPathComponent("synthetic.pdf");try pdf().write(to:file)
            let snapshot=try DocumentSnapshot.capture(source:file,format:.pades,privateRoot:root)
            let job=try SigningJob(snapshot:snapshot,providerPath:mock.path.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:signer.der,destination:root.appendingPathComponent("out.pdf"))
            let appearance=try PAdESAppearanceRenderer.render(config(),certificateDER:signer.der,cropBox:crop)
            XCTAssertThrowsError(try SignumPAdESHelper.sign(job:job,pin:"synthetic-fixture",appearanceName:"unused",field:nil,executable:URL(fileURLWithPath:helper),timeout:0.3,appearance:appearance))
            XCTAssertFalse(FileManager.default.fileExists(atPath:job.destination.path))
            let audit=(try?String(contentsOf:mock.folder.appendingPathComponent("operations")))?.split(separator:"\n") ?? []
            XCTAssertEqual(audit.filter{$0=="16"}.count,1);XCTAssertEqual(audit.filter{$0=="8"}.count,1)
        }
    }

}
#endif
