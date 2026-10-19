#if os(macOS)
import XCTest
import PDFKit
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESDefaultSigningTests: XCTestCase {
    func testDefaultSignedAppearanceRectPhysicalMarginsOrientationCMSAndIndependentPixels() async throws {
        let helper=try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let poppler=try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_POPPLER"])
        let root=try PAdESOrientationWorkflowTests().folder();defer{try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
        for rotation in [0,90,180,270] {for unit in [1.0,2.0,0.5,0.1] {
            let media=CGRect(x:20,y:-50,width:1304/CGFloat(unit),height:1843/CGFloat(unit)),crop=media.insetBy(dx:2,dy:3)
            let source=PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:unit >= 1 ? Int(unit):1,vectors:10000)
            // Replace an equal-length numeric token, preserving synthetic xref offsets.
            let original=unit >= 1 ? source:Data(String(decoding:source,as:UTF8.self).replacingOccurrences(of:"/UserUnit 1 /Contents",with:unit == 0.5 ? "/UserUnit .5/Contents":"/UserUnit .1/Contents").utf8)
            let file=root.appendingPathComponent("synthetic-\(rotation)-\(unit).pdf");try original.write(to:file)
            let batch=BatchSigningCoordinator(padesHelper: ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map { URL(fileURLWithPath: $0) });defer{batch.reset()};await batch.addDocuments([file],format:.pades)
            let snapshot=try XCTUnwrap(batch.documents.first?.snapshot)
            let g=try PAdESPageGeometry(mediaBox:media,cropBox:crop,rotation:rotation,userUnit:CGFloat(unit))
            var c=try g.defaultAppearance();c.showSigner=false;c.showLabel=false;c.image=try PAdESOrientationTests.marker()
            let art=try PAdESAppearanceRenderer.render(c,certificateDER:signer.der,cropBox:crop,pageRotation:rotation)
            let plan=try await batch.prepareReview(provider:mock.path.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders,appearances:[snapshot.identity.id:art])
            try batch.freezeReview(plan);try batch.confirm(plan)
            try await batch.authorizeNext(pin:"synthetic-fixture") {job,pin,op in
                try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:op,executable:URL(fileURLWithPath:helper))
            }
            XCTAssertEqual(batch.documents[0].state,.completed,batch.documents[0].result)
            let output=plan.jobs[0].destination,signed=try Data(contentsOf:output)
            XCTAssertTrue(signed.starts(with:original));XCTAssertEqual(try Data(contentsOf:file),original)
            XCTAssertEqual(try SignumVerificationService.verify(data:signed,name:"synthetic.pdf",helper:URL(fileURLWithPath:helper)).integrity,.verified)
            let doc=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:signed as CFData)))),page=try XCTUnwrap(doc.page(at:1))
            XCTAssertEqual(Int(page.rotationAngle),rotation);XCTAssertEqual(try PAdESPageGeometry(page:page).userUnit,CGFloat(unit))
            var array:CGPDFArrayRef?,field:CGPDFDictionaryRef?,ap:CGPDFDictionaryRef?,stream:CGPDFStreamRef?,rect:CGPDFArrayRef?,bbox:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(page.dictionary),"Annots",&array))
            XCTAssertTrue(CGPDFArrayGetDictionary(try XCTUnwrap(array),0,&field))
            let widget=try XCTUnwrap(field)
            XCTAssertTrue(CGPDFDictionaryGetArray(widget,"Rect",&rect))
            for (i,n) in [c.rectangle.minX,c.rectangle.minY,c.rectangle.maxX,c.rectangle.maxY].enumerated() {
                var value:CGPDFReal=0;XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(rect),i,&value));XCTAssertEqual(value,n,accuracy:0.001)
            }
            XCTAssertTrue(CGPDFDictionaryGetDictionary(widget,"AP",&ap))
            XCTAssertTrue(CGPDFDictionaryGetStream(try XCTUnwrap(ap),"N",&stream))
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(CGPDFStreamGetDictionary(try XCTUnwrap(stream))),"BBox",&bbox))
            for (i,n) in [0.0,0,c.rectangle.width,c.rectangle.height].enumerated() {
                var value:CGPDFReal=0;XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(bbox),i,&value));XCTAssertEqual(value,n,accuracy:0.001)
            }
            let independent=PAdESOrientationOutputTests()
            try independent.independentCMS(signed,field:widget,root:root)
            let raster=root.appendingPathComponent("actual")
            try independent.run(poppler,["-f","1","-singlefile","-cropbox","-scale-to","1600","-png",output.path,raster.path])
            let image=try XCTUnwrap(CGImageSourceCreateImageAtIndex(try XCTUnwrap(CGImageSourceCreateWithURL(raster.appendingPathExtension("png") as CFURL,nil)),0,nil))
            let bounds=try PAdESDefaultPlacementTests().coloredBounds(image)
            let pw=(rotation%180==90 ? crop.height:crop.width)*CGFloat(unit),ph=(rotation%180==90 ? crop.width:crop.height)*CGFloat(unit)
            XCTAssertEqual(bounds.midX,CGFloat(image.width)*(1-(10*72/25.4+120)/pw),accuracy:2)
            XCTAssertEqual(bounds.midY,CGFloat(image.height)*(10*72/25.4+45)/ph,accuracy:2)
            let centers=try independent.imageCenters(image)
            XCTAssertGreaterThan(centers[1].x,centers[0].x);XCTAssertEqual(centers[1].y,centers[0].y,accuracy:2)
            XCTAssertGreaterThan(centers[2].y,centers[0].y,"Automatic artwork must be upright")
        }}
    }
}
#endif
