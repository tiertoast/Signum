#if os(macOS)
import Foundation
import CoreGraphics
import ImageIO
import PDFKit
import SignumCore

/// Each invocation owns its CoreGraphics/ImageIO objects exclusively on its
/// worker. Only Data and integer values cross executors. The viewer's PDFKit
/// objects stay on main; thumbnail PDFKit objects are exclusive worker locals,
/// never installed in a view, shared, cached or returned across an executor.
/// SwiftUI's .task owns the awaited worker and propagates cancellation to it.
enum PDFPreviewPreparation {
    struct Document: Sendable { let bytes: Data; let pageCount: Int }
    struct Page: Sendable { let png: Data; let pageCount: Int }
    static func document(_ snapshot: DocumentSnapshot,
                         preparing: @escaping @Sendable (Data, @Sendable () -> Bool) throws -> Document = { try inspect($0, isCancelled: $1) }) async throws -> Document {
        let control = SigningOperation()
        let cancelled: @Sendable () -> Bool = { control.isCancellationRequested || snapshot.isRetired }
        let work = Task.detached(priority: .userInitiated) {
            let bytes = try snapshot.verifiedBytes(isCancelled: cancelled)
            let value = try preparing(bytes, cancelled)
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
        // A synchronous scope on ONE worker thread, including destruction. AppKit
        // permits creating/drawing a private NSImage on a secondary thread. Keep
        // the entire PDFKit document/page/thumbnail graph private to this scope;
        // no PDFView, NSView, delegate, custom subclass or interactive action.
        // PDFKit thumbnail rendering preserves annotations/AP; drawPDFPage alone
        // omits them and would change the existing read-only preview.
        try autoreleasepool {
            if isCancelled() { throw CancellationError() }
            guard let pdf = PDFDocument(data: bytes), !pdf.isEncrypted,
                  index >= 0, index < min(1000, pdf.pageCount), let page = pdf.page(at: index) else {
                throw SignumError.module("Anteprima PDF non disponibile.")
            }
            let thumbnail = page.thumbnail(of: CGSize(width: 1000, height: 1000), for: .cropBox)
            if isCancelled() { throw CancellationError() }
            guard let tiff = thumbnail.tiffRepresentation,
                  let source = CGImageSourceCreateWithData(tiff as CFData, nil),
                  let image = CGImageSourceCreateThumbnailAtIndex(source, 0,
                    [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceThumbnailMaxPixelSize: 1000,
                     kCGImageSourceShouldCacheImmediately: true] as CFDictionary) else {
                throw SignumError.module("Immagine della pagina non disponibile.")
            }
            let output = NSMutableData()
            guard let sink = CGImageDestinationCreateWithData(output, "public.png" as CFString, 1, nil) else {
                throw SignumError.module("Immagine della pagina non disponibile.")
            }
            CGImageDestinationAddImage(sink, image, nil)
            guard CGImageDestinationFinalize(sink) else { throw SignumError.module("Immagine della pagina non disponibile.") }
            if isCancelled() { throw CancellationError() }
            return Page(png: output as Data, pageCount: pdf.pageCount)
        }
    }
}
#endif
