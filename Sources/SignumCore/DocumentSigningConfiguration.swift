#if os(macOS)
import Foundation
import CoreGraphics

/// Mutable only by replacing a pending document's configuration. Snapshot bytes
/// and identity are independent; an approved SigningJob copies the chosen value.
public struct DocumentSigningConfiguration: Equatable, Sendable {
    public let snapshotID: UUID
    public let format: SigningFormat
    public init(snapshotID: UUID, format: SigningFormat) {
        self.snapshotID = snapshotID; self.format = format
    }
    public static func canSelectPAdES(for snapshot: DocumentSnapshot) -> Bool {
        snapshot.approvedBytes.prefix(1024).range(of:Data("%PDF-".utf8)) != nil
    }
    static func requirePDF(_ snapshot: DocumentSnapshot) throws {
        guard let provider=CGDataProvider(data:snapshot.approvedBytes as CFData),
              let pdf=CGPDFDocument(provider), pdf.numberOfPages>0, !pdf.isEncrypted else {
            throw SignumError.module("PAdES richiede un PDF leggibile e non protetto. Nessuna firma autorizzata.")
        }
    }
}
#endif
