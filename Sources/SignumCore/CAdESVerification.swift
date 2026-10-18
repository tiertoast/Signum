import Foundation
#if os(macOS)
import Darwin
#endif

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
    public static let maximumInputBytes = SigningResourceLimits.maximumOutputBytes
    public static let maximumNestingDepth = 5

    public static func verify(file: URL, isCancelled: () -> Bool = { false }) throws -> CAdESVerificationResult {
        #if os(macOS)
        return try verify(data: readInput(file: file), filename: file.lastPathComponent, isCancelled: isCancelled)
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }

    #if os(macOS)
    struct InputIO {
        var opened: (Int32) throws -> Void = { _ in }
        var read: (Int32, UnsafeMutableRawPointer, Int) -> Int = { Darwin.read($0, $1, $2) }
    }

    /// External verification input: pin the resolved parent once, reject a leaf
    /// symlink/nonregular object, and never reopen the input for content reads.
    /// Ancestor aliases (including macOS /var and /tmp) resolve only at open.
    static func readInput(file: URL, io: InputIO = InputIO()) throws -> Data {
        guard file.isFileURL else { throw SignumError.module("Seleziona un file locale.") }
        let directoryURL = file.deletingLastPathComponent()
        let parent = Darwin.open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw inputError("Cartella di origine non disponibile.") }
        defer { Darwin.close(parent) }
        var parentIdentity = stat()
        guard fstat(parent, &parentIdentity) == 0 else { throw inputError("Cartella non identificabile.") }
        let fd = openat(parent, file.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw inputError("File non disponibile o collegamento simbolico.") }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0, before.st_size <= maximumInputBytes else {
            throw inputError("Serve un file regolare tra 1 byte e \(maximumInputBytes / 1024 / 1024) MiB.")
        }
        try io.opened(fd)
        var data = Data(), chunk = [UInt8](repeating: 0, count: 65536)
        data.reserveCapacity(Int(before.st_size))
        while true {
            // At the boundary, read at most one extra byte to distinguish EOF
            // from growth. That byte is never appended to the bounded result.
            let remaining = maximumInputBytes - data.count
            let requested = min(chunk.count, remaining + 1)
            let count = chunk.withUnsafeMutableBytes { io.read(fd, $0.baseAddress!, requested) }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, count <= requested else { throw inputError("Lettura del file non riuscita.") }
            if count == 0 { break }
            guard count <= remaining else { throw inputError("Il file supera il limite di \(maximumInputBytes / 1024 / 1024) MiB durante la lettura.") }
            data.append(contentsOf: chunk.prefix(count))
        }
        var after = stat(), entry = stat(), currentParent = stat()
        guard fstat(fd, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, data.count == before.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              fstatat(parent, file.lastPathComponent, &entry, AT_SYMLINK_NOFOLLOW) == 0,
              entry.st_dev == before.st_dev, entry.st_ino == before.st_ino,
              stat(directoryURL.path, &currentParent) == 0,
              currentParent.st_dev == parentIdentity.st_dev, currentParent.st_ino == parentIdentity.st_ino else {
            throw inputError("File o percorso modificato durante la lettura. Selezionalo nuovamente.")
        }
        return data
    }
    private static func inputError(_ message: String) -> SignumError { .module(message) }
    #endif

    public static func verify(data: Data, filename: String = "documento.p7m", isCancelled: () -> Bool = { false }) throws -> CAdESVerificationResult {
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
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            let signers = try CMSDescription.signers(in: current)
            let signed = directory.appendingPathComponent("layer-\(depth).p7m")
            let extracted = directory.appendingPathComponent("payload-\(depth).dat")
            try current.write(to: signed, options: .atomic)

            try verifyCMS(input: signed, output: extracted, in: directory, isCancelled: isCancelled)
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

    /// Verify exactly the outer CMS layer against the bytes supplied to signing.
    /// Nested CMS is allowed as content and is compared without unwrapping it.
    /// This checks integrity only; certificate trust/qualification is not checked.
    public static func verifyAttached(data: Data, expectedDocument: Data, isCancelled: () -> Bool = { false }) throws {
        guard !data.isEmpty, data.count <= maximumInputBytes else {
            throw SignumError.module("Dimensione busta CAdES non supportata.")
        }
        _ = try CMSDescription.signers(in: data)
        let manager = FileManager.default
        let directory = manager.temporaryDirectory.appendingPathComponent(
            "signum-verify-" + UUID().uuidString, isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: directory) }
        let signed = directory.appendingPathComponent("signed.p7m")
        let extracted = directory.appendingPathComponent("payload")
        try data.write(to: signed)
        try verifyCMS(input: signed, output: extracted, in: directory, isCancelled: isCancelled)
        guard try Data(contentsOf: extracted) == expectedDocument else {
            throw SignumError.module("Il contenuto CMS non corrisponde al documento firmato.")
        }
    }

    private static func suggestedName(filename: String) -> String {
        var result = (filename as NSString).lastPathComponent
        for _ in 0..<maximumNestingDepth {
            guard result.lowercased().hasSuffix(".p7m") else { break }
            result.removeLast(4)
        }
        return result.isEmpty || result == "." ? "documento-estratto" : result
    }

    private static func verifyCMS(input: URL, output: URL, in directory: URL,
                                  isCancelled: () -> Bool = { false }) throws {
        var message = Data()
        do {
            _ = try SupervisedProcess.run(executable: URL(fileURLWithPath: "/usr/bin/openssl"),
                arguments: ["cms", "-verify", "-inform", "DER", "-binary", "-noverify", "-in", input.path, "-out", output.path],
                input: &message, timeout: 30, isCancelled: isCancelled)
        } catch {
            throw SignumError.module("Verifica crittografica non completata: \(error.localizedDescription)")
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
