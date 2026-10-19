#if os(macOS)
import XCTest
import PDFKit
import ImageIO
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESOrientationOutputTests: XCTestCase {
    func run(_ executable:String,_ args:[String]) throws {
        let p=Process();p.executableURL=URL(fileURLWithPath:executable);p.arguments=args
        p.standardOutput=FileHandle.nullDevice;p.standardError=FileHandle.nullDevice
        try p.run();p.waitUntilExit();XCTAssertEqual(p.terminationStatus,0)
    }
    func centers(_ url:URL) throws -> [CGPoint] {
        let source=try XCTUnwrap(CGImageSourceCreateWithURL(url as CFURL,nil))
        let image=try XCTUnwrap(CGImageSourceCreateImageAtIndex(source,0,nil))
        return try imageCenters(image)
    }
    func imageCenters(_ image:CGImage) throws -> [CGPoint] {
        let ctx=try XCTUnwrap(CGContext(data:nil,width:image.width,height:image.height,bitsPerComponent:8,bytesPerRow:image.width*4,
            space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue))
        ctx.draw(image,in:CGRect(x:0,y:0,width:image.width,height:image.height))
        let bytes=ctx.data!.assumingMemoryBound(to:UInt8.self)
        var points=[[CGPoint]](repeating:[],count:3)
        for y in 0..<image.height {for x in 0..<image.width {
            let i=(y*image.width+x)*4,r=bytes[i],g=bytes[i+1],b=bytes[i+2]
            if r>180 && g<70 && b<70 {points[0].append(CGPoint(x:x,y:y))}
            if g>180 && r<70 && b<70 {points[1].append(CGPoint(x:x,y:y))}
            if b>180 && r<70 && g<70 {points[2].append(CGPoint(x:x,y:y))}
        }}
        return try points.map { ps in
            XCTAssertFalse(ps.isEmpty,"Asymmetric marker color must be visible")
            guard !ps.isEmpty else {throw SignumError.module("Missing marker")}
            return CGPoint(x:ps.map(\.x).reduce(0,+)/CGFloat(ps.count),y:ps.map(\.y).reduce(0,+)/CGFloat(ps.count))
        }
    }
    func independentCMS(_ data:Data,field:CGPDFDictionaryRef,root:URL) throws {
        var value:CGPDFDictionaryRef?,ranges:CGPDFArrayRef?,contents:CGPDFStringRef?
        XCTAssertTrue(CGPDFDictionaryGetDictionary(field,"V",&value))
        XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(value),"ByteRange",&ranges))
        var r=[Int](repeating:0,count:4)
        for i in 0..<4 {var n:CGPDFInteger=0;XCTAssertTrue(CGPDFArrayGetInteger(try XCTUnwrap(ranges),i,&n));r[i]=Int(n)}
        XCTAssertEqual(r[0],0);XCTAssertEqual(r[2]+r[3],data.count)
        var content=Data(data.prefix(r[1]));content.append(data[r[2]..<r[2]+r[3]])
        XCTAssertTrue(CGPDFDictionaryGetString(try XCTUnwrap(value),"Contents",&contents))
        let str=try XCTUnwrap(contents)
        let raw=Data(bytes:try XCTUnwrap(CGPDFStringGetBytePtr(str)),count:CGPDFStringGetLength(str))
        XCTAssertEqual(raw.first,0x30)
        let long=Int(raw[1]&0x7f),header=raw[1]<128 ? 2:2+long
        let length=raw[1]<128 ? Int(raw[1]):raw[2..<header].reduce(0){($0<<8)|Int($1)}
        try Data(raw.prefix(header+length)).write(to:root.appendingPathComponent("cms.der"))
        try content.write(to:root.appendingPathComponent("content.bin"))
        try run("/usr/bin/openssl",["cms","-verify","-binary","-inform","DER","-in",root.appendingPathComponent("cms.der").path,
            "-content",root.appendingPathComponent("content.bin").path,"-noverify","-out","/dev/null"])
    }
    func testSignedOrientationMatchesIndependentUprightClockwiseReferenceAndOpenSSL() async throws {
        let helper=try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let poppler=try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_POPPLER"])
        let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer {try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
        for rotation in [0,90,180,270] {for orientation in PAdESAppearanceOrientation.allCases {
            let media=CGRect(x:20,y:-50,width:1304,height:1843),crop=media.insetBy(dx:10,dy:20)
            let original=PAdESGeometryStabilizationTests.pdf(media:media,crop:crop,rotation:rotation,unit:rotation==270 ? 10:1,vectors:10000)
            let file=root.appendingPathComponent("synthetic-\(rotation)-\(orientation.rawValue).pdf");try original.write(to:file)
            let batch=BatchSigningCoordinator(padesHelper: ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map { URL(fileURLWithPath: $0) });defer{batch.reset()}
            await batch.addDocuments([file],format:.pades)
            let snapshot=try XCTUnwrap(batch.documents.first?.snapshot)
            let c=try PAdESOrientationTests.config(crop:crop,rotation:rotation,orientation:orientation)
            let art=try PAdESAppearanceRenderer.render(c,certificateDER:signer.der,cropBox:crop,pageRotation:rotation)
            let plan=try await batch.prepareReview(provider:mock.path.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),
                der:signer.der,destination:.originalFolders,appearances:[snapshot.identity.id:art])
            try batch.freezeReview(plan);try batch.confirm(plan)
            XCTAssertEqual(plan.jobs[0].padesAppearance?.pageRotation,rotation)
            XCTAssertEqual(plan.jobs[0].padesAppearance?.configuration.orientation,orientation)
            try await batch.authorizeNext(pin:"synthetic-fixture") {job,pin,op in
                try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:op,executable:URL(fileURLWithPath:helper))
            }
            XCTAssertEqual(batch.documents[0].state,.completed,batch.documents[0].result)
            let signed=try Data(contentsOf:plan.jobs[0].destination)
            XCTAssertTrue(signed.starts(with:original));XCTAssertEqual(try Data(contentsOf:file),original)
            let report=try SignumVerificationService.verify(data:signed,name:"synthetic.pdf",helper:URL(fileURLWithPath:helper))
            XCTAssertEqual(report.integrity,.verified)
            let doc=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:signed as CFData)))),page=try XCTUnwrap(doc.page(at:1))
            XCTAssertEqual(Int(page.rotationAngle),rotation)
            var annotations:CGPDFArrayRef?,field:CGPDFDictionaryRef?,ap:CGPDFDictionaryRef?,stream:CGPDFStreamRef?,rect:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(page.dictionary),"Annots",&annotations))
            XCTAssertTrue(CGPDFArrayGetDictionary(try XCTUnwrap(annotations),0,&field))
            let widget=try XCTUnwrap(field)
            XCTAssertTrue(CGPDFDictionaryGetArray(widget,"Rect",&rect))
            for (i,n) in [c.rectangle.minX,c.rectangle.minY,c.rectangle.maxX,c.rectangle.maxY].enumerated() {
                var value:CGPDFReal=0;XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(rect),i,&value));XCTAssertEqual(value,n,accuracy:0.001)
            }
            XCTAssertTrue(CGPDFDictionaryGetDictionary(widget,"AP",&ap))
            XCTAssertTrue(CGPDFDictionaryGetStream(try XCTUnwrap(ap),"N",&stream))
            let form=try XCTUnwrap(CGPDFStreamGetDictionary(try XCTUnwrap(stream)))
            var bbox:CGPDFArrayRef?,matrix:CGPDFArrayRef?
            XCTAssertTrue(CGPDFDictionaryGetArray(form,"BBox",&bbox))
            for (i,n) in [0.0,0.0,c.rectangle.width,c.rectangle.height].enumerated() {
                var v:CGPDFReal=0;XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(bbox),i,&v));XCTAssertEqual(v,n,accuracy:0.001)
            }
            if CGPDFDictionaryGetArray(form,"Matrix",&matrix) {
                for (i,n) in [1.0,0,0,1,0,0].enumerated() {
                    var v:CGPDFReal=0;XCTAssertTrue(CGPDFArrayGetNumber(try XCTUnwrap(matrix),i,&v));XCTAssertEqual(v,n,accuracy:0.001)
                }
            } // Absent /Matrix means identity under the PDF specification.
            try independentCMS(signed,field:widget,root:root)
            // Independent reference has NO /Rotate and uses only the requested
            // screen-clockwise angle, never the production compensation function.
            let visual=rotation%180==90 ? CGSize(width:crop.height,height:crop.width):crop.size
            var referenceBox=CGRect(origin:.zero,size:visual)
            let data=NSMutableData(),ctx=try XCTUnwrap(CGContext(consumer:try XCTUnwrap(CGDataConsumer(data:data)),mediaBox:&referenceBox,nil))
            let center=CGPoint(x:c.rectangle.midX,y:c.rectangle.midY).applying(page.getDrawingTransform(.cropBox,rect:referenceBox,rotate:0,preserveAspectRatio:false))
            var upright=c;upright.orientation = .degrees0;upright.rectangle=CGRect(x:0,y:0,width:240,height:100)
            let base=try PAdESAppearanceRenderer.render(upright,certificateDER:signer.der,cropBox:upright.rectangle,pageRotation:0)
            let raw=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:base.pdf as CFData))))
            let clockwise=try orientation.resolve(pageRotation:0).viewerClockwiseDegrees
            ctx.beginPDFPage(nil);ctx.translateBy(x:center.x,y:center.y)
            ctx.rotate(by:-CGFloat(clockwise)*CGFloat.pi/180);ctx.translateBy(x:-120,y:-50)
            ctx.drawPDFPage(try XCTUnwrap(raw.page(at:1)));ctx.endPDFPage();ctx.closePDF()
            let reference=root.appendingPathComponent("reference.pdf");try (data as Data).write(to:reference)
            var colors:[[CGPoint]]=[]
            for (name,url) in [("actual",plan.jobs[0].destination),("expected",reference)] {
                let prefix=root.appendingPathComponent(name)
                try run(poppler,["-f","1","-singlefile","-cropbox","-scale-to","1600","-png",url.path,prefix.path])
                colors.append(try centers(prefix.appendingPathExtension("png")))
            }
            for i in 0..<3 {
                XCTAssertEqual(colors[0][i].x,colors[1][i].x,accuracy:2,"rotation=\(rotation) orientation=\(orientation)")
                XCTAssertEqual(colors[0][i].y,colors[1][i].y,accuracy:2)
            }
            // Poppler PNG coordinate system: x right, y down. R→G is the
            // asymmetric image's reading axis; these signs prove clockwise semantics.
            let dx=colors[0][1].x-colors[0][0].x,dy=colors[0][1].y-colors[0][0].y
            switch clockwise {
            case 0: XCTAssertGreaterThan(dx,5);XCTAssertEqual(dy,0,accuracy:1)
            case 90: XCTAssertGreaterThan(dy,5);XCTAssertEqual(dx,0,accuracy:1)
            case 180: XCTAssertLessThan(dx,-5);XCTAssertEqual(dy,0,accuracy:1)
            default: XCTAssertLessThan(dy,-5);XCTAssertEqual(dx,0,accuracy:1)
            }
            print("B12 actual_ap page_rotation=\(rotation) orientation=\(orientation.rawValue) axis_dx=\(dx) axis_dy=\(dy) reference=matched cms=openssl_verified")
        }}
    }
}
#endif
