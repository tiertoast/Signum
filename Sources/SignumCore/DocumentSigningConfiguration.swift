#if os(macOS)
import Foundation
import CoreGraphics

/// Mutable only by replacing a pending document's configuration. Snapshot bytes
/// and identity are independent; an approved SigningJob copies the chosen value.
public struct DocumentSigningConfiguration: Equatable, Sendable {
    public let snapshotID: UUID
    public var counterSignatureKey: String? = nil
    public let format: SigningFormat
    public init(snapshotID: UUID, format: SigningFormat) {
        self.snapshotID = snapshotID; self.format = format
    }
    public static func canSelectPAdES(for snapshot: DocumentSnapshot) -> Bool {
        snapshot.approvedBytes.prefix(1024).range(of:Data("%PDF-".utf8)) != nil
    }
    public static func canSelectXAdES(for snapshot: DocumentSnapshot) -> Bool {
        SignatureFormatDetector.candidate(snapshot.approvedBytes) == .xml
    }
    /// Whether a batch-wide format choice may be applied to this document.
    /// Containers are chosen before adding files; co/counter-signature need a CMS.
    public static func canApply(_ format: SigningFormat, to snapshot: DocumentSnapshot) -> Bool {
        guard !format.isASiC, !snapshot.format.isASiC else { return false }
        switch format {
        case .pades: return canSelectPAdES(for: snapshot)
        case .xades: return canSelectXAdES(for: snapshot)
        case .cadesCoSign, .cadesCounterSign: return !snapshot.cmsSignatureTargets.isEmpty
        default: return true
        }
    }
    static func requirePDF(_ snapshot: DocumentSnapshot) throws {
        guard let provider=CGDataProvider(data:snapshot.approvedBytes as CFData),
              let pdf=CGPDFDocument(provider), pdf.numberOfPages>0, !pdf.isEncrypted else {
            throw SignumError.module("PAdES richiede un PDF leggibile e non protetto. Nessuna firma autorizzata.")
        }
    }
}
#endif
