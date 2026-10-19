#if os(macOS)
import Foundation
import CoreGraphics
import ImageIO
import SignumCore

/// Each invocation owns its CoreGraphics/ImageIO objects exclusively on its
/// worker. Only Data and integer values cross executors; PDFKit stays on main.
/// SwiftUI's .task owns the awaited worker and propagates cancellation to it.
enum PDFPreviewPreparation {
    struct Document: Sendable { let bytes: Data; let pageCount: Int }
    struct Page: Sendable { let png: Data; let pageCount: Int }
    static func document(_ snapshot: DocumentSnapshot,
                         preparing: @escaping @Sendable (Data, @Sendable () -> Bool) throws -> Document = { try inspect($0, isCancelled: $1) }) async throws -> Document {
        let control = SigningOperation()
        let work = Task.detached(priority: .userInitiated) {
            let bytes = try snapshot.verifiedBytes(isCancelled: { control.isCancellationRequested })
            let value = try preparing(bytes, { control.isCancellationRequested })
            guard !snapshot.isRetired else { throw CancellationError() }
            return value
        }
        let value = try await withTaskCancellationHandler(operation: { try await work.value },
            onCancel: { control.requestCancellation(); work.cancel() })
        try Task.checkCancellation(); return value
    }
    static func image(_ url: URL) async throws -> PAdESAppearanceImage {
        let work = Task.detached(priority: .userInitiated) { try Task.checkCancellation(); return try PAdESAppearanceImage.load(url) }
        let image = try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
        try Task.checkCancellation(); return image
    }
    static func page(_ bytes: Data, index: Int) async throws -> Page {
        let control = SigningOperation()
        let work = Task.detached(priority: .userInitiated) { try raster(bytes, index: index, isCancelled: { control.isCancellationRequested }) }
        let value = try await withTaskCancellationHandler(operation: { try await work.value },
            onCancel: { control.requestCancellation(); work.cancel() })
        try Task.checkCancellation(); return value
    }
    static func inspect(_ bytes: Data, isCancelled: () -> Bool = { false }) throws -> Document {
        if isCancelled() { throw CancellationError() }
        guard let source = CGDataProvider(data: bytes as CFData), let pdf = CGPDFDocument(source),
              !pdf.isEncrypted, pdf.numberOfPages > 0 else { throw SignumError.module("PDF non disponibile o protetto.") }
        for index in 1...pdf.numberOfPages {
            if isCancelled() { throw CancellationError() }
            guard let page = pdf.page(at: index), !page.getBoxRect(.mediaBox).isEmpty else { throw SignumError.module("Pagina PDF non disponibile.") }
        }
        return Document(bytes: bytes, pageCount: pdf.numberOfPages)
    }
    static func raster(_ bytes: Data, index: Int, isCancelled: () -> Bool = { false }) throws -> Page {
        if isCancelled() { throw CancellationError() }
        guard let source = CGDataProvider(data: bytes as CFData), let pdf = CGPDFDocument(source), !pdf.isEncrypted,
              index >= 0, index < min(1000, pdf.numberOfPages), let page = pdf.page(at: index + 1) else {
            throw SignumError.module("Anteprima PDF non disponibile.")
        }
        let box = page.getBoxRect(.cropBox).intersection(page.getBoxRect(.mediaBox))
        let rotated = abs(page.rotationAngle) % 180 == 90
        let size = rotated ? CGSize(width: box.height, height: box.width) : box.size
        guard size.width.isFinite, size.height.isFinite, size.width > 0, size.height > 0 else { throw SignumError.module("Dimensioni pagina non valide.") }
        let scale = min(1000 / size.width, 1000 / size.height)
        let width = max(1, Int(size.width * scale)), height = max(1, Int(size.height * scale))
        guard let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                     space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw SignumError.module("Immagine della pagina non disponibile.")
        }
        let target = CGRect(x: 0, y: 0, width: width, height: height)
        context.setFillColor(CGColor(gray: 1, alpha: 1)); context.fill(target)
        context.concatenate(page.getDrawingTransform(.cropBox, rect: target, rotate: 0, preserveAspectRatio: true))
        if isCancelled() { throw CancellationError() }
        context.drawPDFPage(page)
        if isCancelled() { throw CancellationError() }
        let output = NSMutableData()
        guard let image = context.makeImage(), let sink = CGImageDestinationCreateWithData(output, "public.png" as CFString, 1, nil) else {
            throw SignumError.module("Immagine della pagina non disponibile.")
        }
        CGImageDestinationAddImage(sink, image, nil)
        guard CGImageDestinationFinalize(sink) else { throw SignumError.module("Immagine della pagina non disponibile.") }
        if isCancelled() { throw CancellationError() }
        return Page(png: output as Data, pageCount: pdf.numberOfPages)
    }
}
#endif
