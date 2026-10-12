import Foundation

public struct CAdESVerificationLevel: Identifiable {
    public let level: Int
    public let signers: [String]
    public var id: Int { level }
}

public struct CAdESVerificationResult {
    public let levels: [CAdESVerificationLevel] // outside -> inside
    public let originalDocument: Data
    public let suggestedFilename: String

    public var verifiedLayerCount: Int { levels.count }
    public var verifiedSignatureCount: Int { levels.reduce(0) { $0 + $1.signers.count } }
}

/// Local cryptographic verification of attached CMS/CAdES using macOS OpenSSL.
/// -noverify deliberately disables X.509 chain/trust validation.
/// NOT an eIDAS qualification, revocation, timestamp, or ETSI conformance check.
public enum CAdESVerifier {
    public static let maximumInputBytes = 64 * 1024 * 1024
    public static let maximumNestingDepth = 5

    public static func verify(file: URL) throws -> CAdESVerificationResult {
        guard file.isFileURL else { throw SignumError.module("Seleziona un file locale.") }
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        guard let n = attrs[.size] as? NSNumber, n.intValue > 0,
              n.intValue <= maximumInputBytes else {
            throw SignumError.module("Il file deve contenere tra 1 byte e 64 MiB.")
        }
        let data = try Data(contentsOf: file)
        return try verify(data: data, filename: file.lastPathComponent)
    }

    public static func verify(data: Data, filename: String = "documento.p7m") throws -> CAdESVerificationResult {
        guard !data.isEmpty, data.count <= maximumInputBytes else {
            throw SignumError.module("Dimensione busta CAdES non supportata.")
        }
        let manager = FileManager.default
        let directory = manager.temporaryDirectory
            .appendingPathComponent("signum-verify-" + UUID().uuidString, isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: directory) }

        var current = data
        var levels: [CAdESVerificationLevel] = []
        for depth in 1...maximumNestingDepth {
            let signers = try CMSDescription.signers(in: current)
            let signed = directory.appendingPathComponent("layer-\(depth).p7m")
            let extracted = directory.appendingPathComponent("payload-\(depth).dat")
            try current.write(to: signed, options: .atomic)

            try verifyCMS(input: signed, output: extracted, in: directory)
            let payload = try Data(contentsOf: extracted)
            guard !payload.isEmpty, payload.count <= maximumInputBytes else {
                throw SignumError.module("Contenuto CAdES vuoto o superiore al limite.")
            }
            levels.append(CAdESVerificationLevel(level: depth, signers: signers))
            current = payload

            if !CMSDescription.isSignedData(payload) {
                return CAdESVerificationResult(levels: levels, originalDocument: current,
                                               suggestedFilename: suggestedName(filename: filename))
            }
        }
        throw SignumError.module("Superato il limite di \(maximumNestingDepth) firme annidate.")
    }

    private static func suggestedName(filename: String) -> String {
        var result = (filename as NSString).lastPathComponent
        for _ in 0..<maximumNestingDepth {
            guard result.lowercased().hasSuffix(".p7m") else { break }
            result.removeLast(4)
        }
        return result.isEmpty || result == "." ? "documento-estratto" : result
    }

    private static func verifyCMS(input: URL, output: URL, in directory: URL) throws {
        let errorFile = directory.appendingPathComponent(UUID().uuidString + ".log")
        guard FileManager.default.createFile(atPath: errorFile.path, contents: Data(),
                                            attributes: [.posixPermissions: 0o600]) else {
            throw SignumError.module("Impossibile preparare la diagnostica temporanea.")
        }
        let log = try FileHandle(forWritingTo: errorFile)
        defer {
            try? log.close()
            try? FileManager.default.removeItem(at: errorFile)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["cms", "-verify", "-inform", "DER", "-binary", "-noverify",
                             "-in", input.path, "-out", output.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = log
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            throw SignumError.module("Impossibile avviare OpenSSL locale: \(error.localizedDescription)")
        }
        guard process.terminationStatus == 0 else {
            let message = (try? Data(contentsOf: errorFile)).flatMap {
                String(data: $0.prefix(2048), encoding: .utf8)
            } ?? "Errore crittografico"
            throw SignumError.module("Verifica crittografica fallita (OpenSSL): \(message)")
        }
    }
}

/// Restricted DER/CMS reader for attached SignedData.
/// Display information only; cryptographic validity comes from OpenSSL.
enum CMSDescription {
    private static let maximumSigners = 32
    private static let maximumCertificates = 64

    static func isSignedData(_ data: Data) -> Bool {
        // Detect the ContentInfo OID even when the nested signer set is
        // malformed. It should not silently be treated as original content.
        let bytes = [UInt8](data)
        guard bytes.count >= 16 && bytes.count <= CAdESVerifier.maximumInputBytes else {
            return false
        }
        do {
            var cursor = 0
            let outer = try DER.read(bytes, at: &cursor, limit: bytes.count)
            guard outer.tag == 0x30, cursor == bytes.count else { return false }
            cursor = outer.contents.lowerBound
            let type = try DER.read(bytes, at: &cursor, limit: outer.contents.upperBound)
            return type.tag == 0x06 &&
                   Data(bytes[type.full]) == DER.signedDataOID
        } catch {
            return false
        }
    }

    static func signers(in data: Data) throws -> [String] {
        let bytes = [UInt8](data)
        guard bytes.count >= 16, bytes.count <= CAdESVerifier.maximumInputBytes else {
            throw SignumError.module("Struttura CMS non supportata.")
        }
        var cursor = 0
        let outer = try DER.read(bytes, at: &cursor, limit: bytes.count)
        guard outer.tag == 0x30, cursor == bytes.count else { throw invalid() }
        cursor = outer.contents.lowerBound
        let contentType = try DER.read(bytes, at: &cursor, limit: outer.contents.upperBound)
        guard contentType.tag == 0x06,
              Data(bytes[contentType.full]) == DER.signedDataOID else { throw invalid() }
        let tagged = try DER.read(bytes, at: &cursor, limit: outer.contents.upperBound)
        guard tagged.tag == 0xA0, cursor == outer.contents.upperBound else { throw invalid() }
        cursor = tagged.contents.lowerBound
        let signed = try DER.read(bytes, at: &cursor, limit: tagged.contents.upperBound)
        guard signed.tag == 0x30, cursor == tagged.contents.upperBound else { throw invalid() }
        cursor = signed.contents.lowerBound

        let version = try DER.read(bytes, at: &cursor, limit: signed.contents.upperBound)
        let algorithms = try DER.read(bytes, at: &cursor, limit: signed.contents.upperBound)
        let encapsulated = try DER.read(bytes, at: &cursor, limit: signed.contents.upperBound)
        guard version.tag == 0x02, algorithms.tag == 0x31, encapsulated.tag == 0x30 else {
            throw invalid()
        }

        var embedded: [Data: String] = [:]
        var signerSet: DER.Node?
        while cursor < signed.contents.upperBound {
            let node = try DER.read(bytes, at: &cursor, limit: signed.contents.upperBound)
            if node.tag == 0xA0 {
                var certificateCursor = node.contents.lowerBound
                while certificateCursor < node.contents.upperBound {
                    guard embedded.count < maximumCertificates else { throw invalid() }
                    let certificate = try DER.read(bytes, at: &certificateCursor, limit: node.contents.upperBound)
                    guard certificate.tag == 0x30 else { continue }
                    let der = Data(bytes[certificate.full])
                    if let id = try? DER.certificateIdentity(der) {
                        let key = DER.sequence([id.issuer, id.serial])
                        embedded[key] = (try? CertificateIdentityReader.read(der))?.title
                            ?? "Firmatario (certificato non leggibile)"
                    }
                }
            } else if node.tag == 0xA1 {
                continue // Optional CRLs
            } else if node.tag == 0x31 {
                guard signerSet == nil else { throw invalid() }
                signerSet = node
            } else {
                throw invalid()
            }
        }

        guard let signerSet else { throw invalid() }
        var signers: [String] = []
        var position = signerSet.contents.lowerBound
        while position < signerSet.contents.upperBound {
            guard signers.count < maximumSigners else { throw invalid() }
            let signer = try DER.read(bytes, at: &position, limit: signerSet.contents.upperBound)
            guard signer.tag == 0x30 else { throw invalid() }
            var inside = signer.contents.lowerBound
            let signerVersion = try DER.read(bytes, at: &inside, limit: signer.contents.upperBound)
            let identifier = try DER.read(bytes, at: &inside, limit: signer.contents.upperBound)
            guard signerVersion.tag == 0x02 else { throw invalid() }
            signers.append(embedded[Data(bytes[identifier.full])]
                           ?? "Firmatario (certificato non identificato)")
        }
        guard !signers.isEmpty else {
            throw SignumError.module("La busta CMS non contiene firmatari.")
        }
        return signers
    }

    private static func invalid() -> SignumError {
        .module("Formato CMS/DER non supportato o dati ASN.1 non validi.")
    }
}
