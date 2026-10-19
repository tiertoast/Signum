#if os(macOS)
import Foundation
import CoreGraphics
import CoreText
import ImageIO
import CryptoKit
import Darwin

public struct PAdESAppearanceConfiguration: Equatable, Sendable {
    public enum Alignment: String, CaseIterable, Sendable { case leading, center, trailing }
    public var visible = true
    public var pageIndex = 0
    public var orientation: PAdESAppearanceOrientation = .automatic
    public var rectangle = CGRect(x: 30, y: 30, width: 240, height: 90)
    public var showSigner = true
    public var showLabel = true
    public var localDate: Date? = nil
    public var customText = ""
    public var alignment: Alignment = .leading
    public var fontSize: Double = 10
    public var image: PAdESAppearanceImage? = nil
    public init() {}
    /// Page and origin place existing pixels; size and every other input may
    /// change the artwork. Compare immutable inputs without hashing image bytes.
    public func hasSameArtwork(as other: Self) -> Bool {
        var a = self, b = other
        a.pageIndex = 0; b.pageIndex = 0
        a.rectangle.origin = .zero; b.rectangle.origin = .zero
        return a == b
    }
    public func validate(cropBox: CGRect, pageRotation: Int = 0) throws {
        let r = rectangle, size = try contentSize(pageRotation:pageRotation)
        guard pageIndex >= 0, !visible || ([r.minX,r.minY,r.width,r.height,cropBox.minX,cropBox.minY,cropBox.width,cropBox.height].allSatisfy(\.isFinite) &&
            size.width >= 80 && size.height >= 40 && size.width <= 800 && size.height <= 500 && cropBox.contains(r)),
            (7...18).contains(fontSize), fontSize.isFinite, customText.utf8.count <= 1024,
            !customText.unicodeScalars.contains(where: { $0.value < 32 && $0.value != 10 }),
            localDate.map({ $0.timeIntervalSince1970.isFinite }) ?? true else {
            throw SignumError.module("Aspetto o rettangolo della firma non valido: deve rientrare nella pagina (80–800 × 40–500 pt).")
        }
    }
}

public struct PAdESAppearanceImage: Equatable, Sendable {
    public static let maximumBytes = 5 * 1024 * 1024
    public let data: Data
    public let width: Int, height: Int
    public init(data: Data) throws {
        guard !data.isEmpty, data.count <= Self.maximumBytes else { throw SignumError.module("Immagine superiore a 5 MiB o vuota.") }
        // Reject compressed/custom ICC metadata before ImageIO can expand it.
        let bytes = [UInt8](data)
        if bytes.starts(with: [137,80,78,71,13,10,26,10]) {
            var offset = 8, chunks = 0
            while offset + 12 <= bytes.count {
                let n = bytes[offset..<offset+4].reduce(0) { ($0 << 8) | Int($1) }
                guard n <= bytes.count-offset-12, chunks < 4096 else { throw SignumError.module("PNG malformato.") }
                let type = String(bytes: bytes[offset+4..<offset+8], encoding: .ascii)
                guard !["iCCP", "zTXt", "iTXt"].contains(type ?? "") else { throw SignumError.module("Profilo ICC o metadati compressi non supportati: esporta in sRGB senza metadati incorporati.") }
                offset += n + 12; chunks += 1
                if type == "IEND" { break }
            }
        } else if bytes.starts(with: [255,216]) {
            var offset = 2, markers = 0
            while offset + 4 <= bytes.count, bytes[offset] == 255 {
                let marker = bytes[offset+1]; offset += 2
                if marker == 218 || marker == 217 { break }
                guard marker != 0, marker != 255, offset + 2 <= bytes.count else { throw SignumError.module("JPEG malformato.") }
                let n = (Int(bytes[offset]) << 8) | Int(bytes[offset+1])
                guard n >= 2, n <= bytes.count-offset, markers < 4096 else { throw SignumError.module("JPEG malformato.") }
                guard marker != 226 else { throw SignumError.module("JPEG con profilo esteso non supportato: esporta in sRGB senza profilo incorporato.") }
                offset += n; markers += 1
            }
        } else { throw SignumError.module("Serve un'immagine PNG o JPEG reale.") }
        guard let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              CGImageSourceGetCount(source) == 1,
              let type = CGImageSourceGetType(source) as String?, ["public.png", "public.jpeg"].contains(type),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString:Any],
              let w = properties[kCGImagePropertyPixelWidth] as? Int, let h = properties[kCGImagePropertyPixelHeight] as? Int,
              w > 0, h > 0, w <= 4096, h <= 4096, w * h <= 8_000_000,
              let image = CGImageSourceCreateImageAtIndex(source, 0, [kCGImageSourceShouldCacheImmediately:true] as CFDictionary),
              [.rgb, .monochrome, .indexed].contains(image.colorSpace?.model ?? .unknown), image.width == w, image.height == h else {
            throw SignumError.module("Immagine non decodificabile o oltre i limiti: 4096 px per lato, 8 milioni di pixel, RGB/grigio.")
        }
        self.data = data; width = w; height = h
    }
    public static func load(_ url: URL) throws -> Self {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SignumError.module("Immagine non disponibile o collegamento simbolico.") }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_size > 0, before.st_size <= maximumBytes else {
            throw SignumError.module("Serve un'immagine regolare fino a 5 MiB.")
        }
        var data = Data(count: Int(before.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = read(fd, bytes.baseAddress!.advanced(by: offset), bytes.count-offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw SignumError.module("Lettura immagine incompleta.") }; offset += n
            }
        }
        var extra: UInt8 = 0, after = stat()
        guard read(fd, &extra, 1) == 0, fstat(fd, &after) == 0, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw SignumError.module("Immagine cambiata durante la lettura.")
        }
        return try Self(data: data)
    }
}

public struct RenderedPAdESAppearance: Equatable, Sendable {
    public let configuration: PAdESAppearanceConfiguration
    /// Final, already oriented vector PDF. Shared unchanged by preview and helper.
    public let pdf: Data
    public let certificateSHA256: String
    public let artworkID: UUID
    public let contentArtworkID: UUID
    public let sha256: String
    public let approvalIdentity: String
    /// Nil preserves legacy callers that supply only a CropBox and raw artwork.
    /// The GUI always supplies and freezes the actual snapshot page rotation.
    public let pageRotation: Int?
    public let resolvedOrientation: PAdESAppearanceResolution?
    private let uprightPDF: Data?

    public init(configuration: PAdESAppearanceConfiguration, pdf: Data, certificateSHA256: String) {
        self.init(configuration:configuration,pdf:pdf,certificateSHA256:certificateSHA256,
                  artworkID:UUID(),contentArtworkID:UUID(),sha256:DocumentSnapshot.digest(pdf),pageRotation:nil,uprightPDF:nil)
    }
    private init(configuration: PAdESAppearanceConfiguration, pdf: Data, certificateSHA256: String,
                 artworkID: UUID, contentArtworkID: UUID, sha256: String, pageRotation: Int?, uprightPDF: Data?) {
        self.configuration=configuration; self.pdf=pdf; self.certificateSHA256=certificateSHA256
        self.artworkID=artworkID; self.contentArtworkID=contentArtworkID; self.sha256=sha256
        self.pageRotation=pageRotation; self.uprightPDF=uprightPDF
        let c=configuration,r=c.rectangle
        let resolved=try? c.orientation.resolve(pageRotation:pageRotation ?? 0)
        self.resolvedOrientation=resolved
        approvalIdentity=DocumentSnapshot.digest(Data("\(c.visible)|\(c.pageIndex)|\(r.minX)|\(r.minY)|\(r.width)|\(r.height)|\(c.orientation.rawValue)|\(pageRotation.map(String.init) ?? "legacy")|\(resolved?.artworkCounterclockwiseDegrees ?? -1)|\(sha256)|\(certificateSHA256)".utf8))
    }
    init(rendering configuration:PAdESAppearanceConfiguration,uprightPDF:Data,certificateSHA256:String,pageRotation:Int?) throws {
        let rotation=try configuration.orientation.resolve(pageRotation:pageRotation ?? 0)
        let final=try Self.orientedPDF(uprightPDF,configuration:configuration,resolution:rotation)
        self.init(configuration:configuration,pdf:final,certificateSHA256:certificateSHA256,artworkID:UUID(),
                  contentArtworkID:UUID(),sha256:DocumentSnapshot.digest(final),pageRotation:pageRotation.map{_ in rotation.pageRotation},uprightPDF:uprightPDF)
    }
    public func placed(_ configuration:PAdESAppearanceConfiguration,cropBox:CGRect) throws -> Self {
        guard self.configuration.hasSameArtwork(as:configuration) else {
            throw SignumError.module("Il contenuto grafico è cambiato: prepara una nuova appearance.")
        }
        try configuration.validate(cropBox:cropBox,pageRotation:pageRotation ?? 0)
        return Self(configuration:configuration,pdf:pdf,certificateSHA256:certificateSHA256,artworkID:artworkID,
                    contentArtworkID:contentArtworkID,sha256:sha256,pageRotation:pageRotation,uprightPDF:uprightPDF)
    }
    public func canReorient(to next:PAdESAppearanceConfiguration,pageRotation:Int) -> Bool {
        guard uprightPDF != nil,
              let oldSize=try? configuration.contentSize(pageRotation:self.pageRotation ?? 0),
              let newSize=try? next.contentSize(pageRotation:pageRotation) else {return false}
        var a=configuration,b=next
        a.pageIndex=0;b.pageIndex=0;a.orientation = .automatic;b.orientation = .automatic
        a.rectangle=CGRect(origin:.zero,size:oldSize);b.rectangle=CGRect(origin:.zero,size:newSize)
        return a == b
    }
    public func reoriented(_ next:PAdESAppearanceConfiguration,cropBox:CGRect,pageRotation:Int,
                           isCancelled:()->Bool = {false}) throws -> Self {
        guard canReorient(to:next,pageRotation:pageRotation),let uprightPDF else {
            throw SignumError.module("Il contenuto grafico è cambiato: prepara una nuova appearance.")
        }
        try next.validate(cropBox:cropBox,pageRotation:pageRotation)
        let resolution=try next.orientation.resolve(pageRotation:pageRotation)
        if isCancelled() {throw CancellationError()}
        let old=try configuration.orientation.resolve(pageRotation:self.pageRotation ?? 0)
        let same=old.artworkCounterclockwiseDegrees == resolution.artworkCounterclockwiseDegrees
        let final=try same ? pdf : Self.orientedPDF(uprightPDF,configuration:next,resolution:resolution)
        if isCancelled() {throw CancellationError()}
        return Self(configuration:next,pdf:final,certificateSHA256:certificateSHA256,
                    artworkID:same ? artworkID:UUID(),contentArtworkID:contentArtworkID,
                    sha256:same ? sha256:DocumentSnapshot.digest(final),pageRotation:resolution.pageRotation,uprightPDF:uprightPDF)
    }
    private static func orientedPDF(_ base:Data,configuration:PAdESAppearanceConfiguration,
                                    resolution:PAdESAppearanceResolution) throws -> Data {
        guard configuration.visible,resolution.artworkCounterclockwiseDegrees != 0 else {return base}
        guard let source=CGDataProvider(data:base as CFData),let doc=CGPDFDocument(source),let page=doc.page(at:1) else {
            throw SignumError.module("Artwork non disponibile per l’orientamento.")
        }
        var box=CGRect(origin:.zero,size:configuration.rectangle.size)
        let output=NSMutableData()
        guard let consumer=CGDataConsumer(data:output),let c=CGContext(consumer:consumer,mediaBox:&box,nil) else {
            throw SignumError.module("Orientamento artwork non disponibile.")
        }
        c.beginPDFPage(nil)
        c.concatenate(resolution.transform(contentSize:page.getBoxRect(.mediaBox).size))
        c.drawPDFPage(page);c.endPDFPage();c.closePDF()
        guard output.length <= PAdESAppearanceRenderer.maximumPDFBytes else {throw SignumError.module("Appearance superiore a 8 MiB.")}
        return output as Data
    }
}

public enum PAdESAppearanceRenderer {
    public static let maximumPDFBytes = 8 * 1024 * 1024
    public static func render(_ configuration: PAdESAppearanceConfiguration, certificateDER: Data, cropBox: CGRect, pageRotation: Int? = nil, isCancelled: () -> Bool = { false }) throws -> RenderedPAdESAppearance {
        if isCancelled() { throw CancellationError() }
        try configuration.validate(cropBox: cropBox,pageRotation:pageRotation ?? 0)
        let fingerprint = SHA256.hash(data: certificateDER).map { String(format:"%02x", $0) }.joined()
        guard configuration.visible else { return try .init(rendering:configuration,uprightPDF:Data(),certificateSHA256:fingerprint,pageRotation:pageRotation) }
        var lines: [String] = []
        if configuration.showLabel { lines.append("Firmato digitalmente") }
        if configuration.showSigner { lines.append(try SignumCertificateIdentity(certificateDER: certificateDER).fullName) }
        if let date = configuration.localDate {
            let formatter = DateFormatter(); formatter.locale = Locale(identifier:"it_IT"); formatter.dateFormat = "dd/MM/yyyy HH:mm:ss ZZZZZ"
            lines.append("Data locale: " + formatter.string(from: date))
        }
        if !configuration.customText.isEmpty { lines.append(configuration.customText) }
        guard !lines.isEmpty || configuration.image != nil else { throw SignumError.module("La firma visibile richiede testo o immagine.") }
        var box = CGRect(origin:.zero, size: try configuration.contentSize(pageRotation:pageRotation ?? 0))
        let output = NSMutableData()
        guard let sink = CGDataConsumer(data: output as CFMutableData), let context = CGContext(consumer:sink, mediaBox:&box, nil) else { throw SignumError.module("Rendering appearance non disponibile.") }
        context.beginPDFPage(nil)
        context.setFillColor(CGColor(gray:1,alpha:1)); context.fill(box)
        context.setStrokeColor(CGColor(gray:0.45,alpha:1)); context.setLineWidth(0.7); context.stroke(box.insetBy(dx:0.5,dy:0.5))
        var textBox = box.insetBy(dx:7,dy:7)
        if isCancelled() { throw CancellationError() }
        if let image = configuration.image, let source = CGImageSourceCreateWithData(image.data as CFData, nil), let cg = CGImageSourceCreateImageAtIndex(source,0,nil) {
            let region = CGRect(x:7,y:7,width: lines.isEmpty ? box.width-14 : box.width*0.32,height:box.height-14)
            let scale = min(region.width/CGFloat(image.width),region.height/CGFloat(image.height))
            context.draw(cg, in:CGRect(x:region.midX-CGFloat(image.width)*scale/2,y:region.midY-CGFloat(image.height)*scale/2,width:CGFloat(image.width)*scale,height:CGFloat(image.height)*scale))
            if !lines.isEmpty { textBox.origin.x = region.maxX+7; textBox.size.width = box.maxX-textBox.minX-7 }
        }
        if isCancelled() { throw CancellationError() }
        if !lines.isEmpty {
            var alignment: CTTextAlignment = configuration.alignment == .leading ? .left : (configuration.alignment == .center ? .center : .right)
            let paragraph = withUnsafePointer(to:&alignment) { pointer in
                var setting = CTParagraphStyleSetting(spec:.alignment,valueSize:MemoryLayout<CTTextAlignment>.size,value:pointer)
                return CTParagraphStyleCreate(&setting,1)
            }
            let text = lines.joined(separator:"\n")
            let attributes: [NSAttributedString.Key:Any] = [NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName("Helvetica" as CFString,configuration.fontSize,nil),
                NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(gray:0.08,alpha:1), NSAttributedString.Key(kCTParagraphStyleAttributeName as String):paragraph]
            let attributed = NSAttributedString(string:text,attributes:attributes)
            let setter = CTFramesetterCreateWithAttributedString(attributed)
            let frame = CTFramesetterCreateFrame(setter,CFRange(location:0,length:0),CGPath(rect:textBox,transform:nil),nil)
            guard CTFrameGetVisibleStringRange(frame).length == attributed.length else { throw SignumError.module("Testo troppo lungo per il riquadro: aumenta le dimensioni o riduci il testo.") }
            CTFrameDraw(frame,context)
        }
        if isCancelled() { throw CancellationError() }
        context.endPDFPage(); context.closePDF()
        guard output.length <= maximumPDFBytes else { throw SignumError.module("Appearance superiore a 8 MiB.") }
        if isCancelled() { throw CancellationError() }
        return try .init(rendering:configuration,uprightPDF:output as Data,certificateSHA256:fingerprint,pageRotation:pageRotation)
    }
}
#endif
