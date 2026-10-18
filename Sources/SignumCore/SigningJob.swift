#if os(macOS)
import Foundation
import Darwin

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
    public let padesAppearance: RenderedPAdESAppearance?

    public init(snapshot: DocumentSnapshot, providerPath: String, slot: UInt,
                certificate: SignumCertificate, certificateDER: Data, destination: URL,
                destinationDirectoryIdentity: OutputDirectoryIdentity? = nil,
                padesAppearance: RenderedPAdESAppearance? = nil) throws {
        guard destination.isFileURL, destination.standardizedFileURL != snapshot.originalURL.standardizedFileURL,
              destination.standardizedFileURL != snapshot.fileURL,
              destination.pathExtension.lowercased() == (snapshot.format == .cades ? "p7m" : "pdf"),
              providerPath.hasPrefix("/"), !certificateDER.isEmpty, certificateDER.count <= 65536 else {
            throw SignumError.module("Richiesta di firma incompleta o destinazione non valida.")
        }
        if let appearance = padesAppearance {
            guard snapshot.format == .pades,
                  appearance.certificateSHA256 == DocumentSnapshot.digest(certificateDER),
                  appearance.pdf.count <= PAdESAppearanceRenderer.maximumPDFBytes,
                  !appearance.configuration.visible || !appearance.pdf.isEmpty else {
                throw SignumError.module("Appearance non vincolata al documento e certificato approvati.")
            }
        }
        self.padesAppearance = padesAppearance
        self.id = UUID(); self.format = snapshot.format; self.snapshot = snapshot
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
            return try module.createCAdES(document: bytes, slot: slot, certificate: certificate,
                                          pin: pin, expectedCertificateDER: certificateDER)
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
        try SignumFileOutput.writeNew(cms, to: destination, io: io) { staged in
            _ = try verifiedBytes()
            try CAdESVerifier.verifyAttached(data: staged, expectedDocument: approved, isCancelled: isCancelled)
        }
    }
}
#endif
