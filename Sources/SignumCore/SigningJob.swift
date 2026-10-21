#if os(macOS)
import Foundation
import Darwin
import CoreGraphics

/// Internal application operation, not an inter-application protocol. No PIN or
/// mutable UI state is retained. Approval must refer to this exact value.
public struct SigningJob: Sendable {
    public let id: UUID
    public let format: SigningFormat
    public let snapshot: DocumentSnapshot
    public let snapshotIdentity: DocumentSnapshot.Identity
    public let contentSHA256: String
    public let providerPath: String
    public let slot: UInt
    public let certificate: SignumCertificate
    public let certificateDER: Data
    public let certificateSHA256: String
    public let destination: URL
    public let destinationDirectoryIdentity: OutputDirectoryIdentity?
    /// nil explicitly denotes the legacy locator/DER-only API, never the GUI.
    public let providerContext: SigningProviderContext?
    public let padesSourcePreflight: PAdESSourcePreflight?
    public let includeSigningTime: Bool
    public let padesAppearance: RenderedPAdESAppearance?

    public init(snapshot: DocumentSnapshot, format: SigningFormat? = nil, providerPath: String, slot: UInt,
                certificate: SignumCertificate, certificateDER: Data, destination: URL,
                destinationDirectoryIdentity: OutputDirectoryIdentity? = nil,
                padesSourcePreflight: PAdESSourcePreflight? = nil, padesAppearance: RenderedPAdESAppearance? = nil, providerContext: SigningProviderContext? = nil, includeSigningTime: Bool = true) throws {
        let effectiveFormat = format ?? snapshot.format
        if effectiveFormat == .pades, format != nil { try DocumentSigningConfiguration.requirePDF(snapshot) }
        guard destination.isFileURL, destination.standardizedFileURL != snapshot.originalURL.standardizedFileURL,
              destination.standardizedFileURL != snapshot.fileURL,
              destination.pathExtension.lowercased() == (effectiveFormat == .cades ? "p7m" : "pdf"),
              providerPath.hasPrefix("/"), !certificateDER.isEmpty, certificateDER.count <= 65536 else {
            throw SignumError.module("Richiesta di firma incompleta o destinazione non valida.")
        }
        if let providerContext, !providerContext.matches(provider: providerPath, slot: slot, certificate: certificate, der: certificateDER) {
            throw SignumError.module("Contesto dispositivo non coerente con il job approvato.")
        }
        if let padesSourcePreflight { try padesSourcePreflight.requireAccepted(for: snapshot) }
        self.padesSourcePreflight = padesSourcePreflight
        self.providerContext = providerContext
        if let appearance = padesAppearance {
            guard effectiveFormat == .pades,
                  appearance.certificateSHA256 == DocumentSnapshot.digest(certificateDER),
                  appearance.pdf.count <= PAdESAppearanceRenderer.maximumPDFBytes,
                  !appearance.configuration.visible || !appearance.pdf.isEmpty else {
                throw SignumError.module("Appearance non vincolata al documento e certificato approvati.")
            }
            if let rotation=appearance.pageRotation {
                guard let provider=CGDataProvider(data:snapshot.approvedBytes as CFData),
                      let doc=CGPDFDocument(provider),
                      appearance.configuration.pageIndex >= 0,appearance.configuration.pageIndex < doc.numberOfPages,
                      let page=doc.page(at:appearance.configuration.pageIndex+1),
                      try appearance.configuration.orientation.resolve(pageRotation:Int(page.rotationAngle)).pageRotation == rotation else {
                    throw SignumError.module("Orientamento non vincolato alla pagina dello snapshot approvato.")
                }
                if let unit=appearance.configuration.userUnit {
                    guard try PAdESPageGeometry(page:page).userUnit == unit else {
                        throw SignumError.module("UserUnit non vincolato alla pagina dello snapshot approvato.")
                    }
                }
                try appearance.configuration.validate(cropBox:page.getBoxRect(.cropBox).intersection(page.getBoxRect(.mediaBox)),pageRotation:rotation)
            }
        }
        self.includeSigningTime = includeSigningTime
        self.padesAppearance = padesAppearance
        self.id = UUID(); self.format = effectiveFormat; self.snapshot = snapshot
        self.snapshotIdentity = snapshot.identity; self.contentSHA256 = snapshot.identity.sha256
        self.providerPath = providerPath; self.slot = slot; self.certificate = certificate
        self.certificateDER = certificateDER; self.certificateSHA256 = DocumentSnapshot.digest(certificateDER)
        self.destination = destination.standardizedFileURL
        self.destinationDirectoryIdentity = destinationDirectoryIdentity
    }

    public func requireAvailableDestination() throws {
        if let destinationDirectoryIdentity { try destinationDirectoryIdentity.requireCurrent(at: destination.deletingLastPathComponent()) }
        var info = stat()
        guard lstat(destination.path, &info) != 0, errno == ENOENT else {
            throw SignumError.module("La destinazione approvata è occupata o non ispezionabile. Nessuna autenticazione inviata. Per un nome diverso prepara e conferma una nuova sessione.")
        }
    }

    public var formatDescription: String {
        format == .pades ? "PAdES — PDF firmato" : "CAdES — documento .p7m"
    }

    public var approvalDescription: String {
        "Documento: \(snapshot.originalURL.lastPathComponent)\nFormato: \(format.rawValue.uppercased()) · \(snapshotIdentity.byteCount) byte\nSHA-256: \(contentSHA256)\nDestinazione: \(destination.path)\n\nVerrà firmata questa copia. Le modifiche successive all'originale non saranno incluse: riseleziona il documento per aggiornarla."
    }

    public func verifiedBytes() throws -> Data {
        guard snapshot.identity == snapshotIdentity, contentSHA256 == snapshotIdentity.sha256 else {
            throw SignumError.module("Identità dello snapshot non valida.")
        }
        return try snapshot.verifiedBytes()
    }

    public func signCAdES(using module: PKCS11Module, pin: String) throws {
        try executeCAdES { bytes in
            guard module.modulePath == providerPath else { throw SignumError.module("Provider differente da quello approvato.") }
            if let providerContext { try providerContext.requireCurrentModule(); try providerContext.requireCurrentToken(module) }
            return try module.createCAdES(document: bytes, slot: slot, certificate: certificate,
                                          pin: pin, expectedCertificateDER: certificateDER, includeSigningTime: includeSigningTime)
        }
    }

    // Injection is per-job and test-only. Production always uses CMS integrity
    // verification and the existing exclusive transactional output implementation.
    func executeCAdES(io: SignumFileOutput.OutputIO = .init(), isCancelled: () -> Bool = { false }, sign: (Data) throws -> Data) throws {
        defer { snapshot.close() }
        guard format == .cades else { throw SignumError.module("Formato del job non compatibile.") }
        try requireAvailableDestination()
        let approved = try verifiedBytes()
        try CertificateEligibility.requireEligible(certificateDER: certificateDER)
        let cms = try sign(approved)
        guard cms.count <= SigningResourceLimits.maximumOutputBytes else { throw SignumError.module("La busta firmata supera la dimensione massima supportata.") }
        _ = try verifiedBytes()
        try SignumFileOutput.writeNew(cms, to: destination, expectedDirectory: destinationDirectoryIdentity, io: io) { staged in
            _ = try verifiedBytes()
            try CAdESVerifier.verifyAttached(data: staged, expectedDocument: approved, isCancelled: isCancelled)
        }
    }
}
#endif
