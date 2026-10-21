import Foundation
import SignumCore
#if os(macOS)
import PDFKit
#endif

public enum VerificationReportExporter {
    public enum Format: String, Sendable {case pdf, text
        public var pathExtension: String {self == .pdf ? "pdf":"txt"}
    }
    public static func data(_ document: VerificationReportDocument,format: Format) throws -> Data {
        switch format {
        case .text:return Data(document.plainText.utf8)
        case .pdf:
            #if os(macOS)
            return try VerificationReportPDF.data(document)
            #else
            throw SignumError.unsupportedPlatform
            #endif
        }
    }
    public static func write(_ document: VerificationReportDocument,format: Format,to destination: URL) throws {
        guard destination.isFileURL,destination.pathExtension.lowercased()==format.pathExtension else {throw VerificationReportDocument.Failure.invalidDestination}
        let bytes=try data(document,format:format)
        try SignumFileOutput.writeNew(bytes,to:destination) { staged in
            guard staged==bytes else {throw SignumError.module("Rapporto modificato durante la scrittura.")}
            #if os(macOS)
            if format == .pdf {guard let pdf=PDFDocument(data:staged),pdf.pageCount>0 else {throw SignumError.module("PDF del rapporto non leggibile.")}}
            #endif
        }
    }
}
