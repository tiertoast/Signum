#if os(macOS)
import Foundation
import CryptoKit
import Darwin
import CPINManagement

/// Evidence only. No caller-supplied flag, exported function, certificate or
/// receipt can turn this model into permission to send a real credential.
public enum PINChangeQualification {
    public static let realBackendEnabled = false
    public static let digitalDNAOpenSCProfile = "digitaldna-chipdocit-opensc-12b-unqualified"
    public static let blockers = [
        "Provenienza e corrispondenza binario/sorgente non attestate.",
        "Domini IAS/CNS e procedura composta da qualificare sul modello esatto.",
        "Configurazione e dipendenze effettive da fissare e verificare.",
        "Nessuna prova hardware mutante autorizzata o eseguita."
    ]
}

/// Public evidence read through a pinned descriptor; no credential handling.
/// Digests bind bytes, not the manufacturer's authenticity or physical identity.
struct PINChangeFileEvidence: Codable, Equatable, Sendable {
    let path: String
    let device: Int32
    let inode: UInt64
    let size: Int64
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64
    let changedSeconds: Int64
    let changedNanoseconds: Int64
    let sha256: String
    static func capture(_ url: URL) throws -> Self {
        guard url.isFileURL, url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw PINManagementFailure.contextChanged }
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw PINManagementFailure.contextChanged }
        defer { Darwin.close(fd) }
        var before = stat(), after = stat()
        guard sg_pin_evidence_descriptor_is_safe(fd) == 0, fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_mode & 0o022 == 0, before.st_nlink == 1,
              before.st_size >= 0, before.st_size <= 64 * 1024 * 1024 else { throw PINManagementFailure.contextChanged }
        var digest = SHA256(), total: Int64 = 0, buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw PINManagementFailure.contextChanged }
            if n == 0 { break }
            total += Int64(n)
            guard total <= before.st_size else { throw PINManagementFailure.contextChanged }
            digest.update(data: Data(buffer.prefix(n)))
        }
        guard fstat(fd, &after) == 0, total == before.st_size,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, before.st_mode == after.st_mode,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw PINManagementFailure.contextChanged }
        return .init(path: url.path, device: after.st_dev, inode: after.st_ino, size: after.st_size,
                     modifiedSeconds: Int64(after.st_mtimespec.tv_sec), modifiedNanoseconds: Int64(after.st_mtimespec.tv_nsec),
                     changedSeconds: Int64(after.st_ctimespec.tv_sec), changedNanoseconds: Int64(after.st_ctimespec.tv_nsec),
                     sha256: digest.finalize().map { String(format: "%02x", $0) }.joined())
    }
}

/// Separate from read-status/signing routes. A future backend must independently
/// reconstruct and revalidate this exact evidence under the exclusive lease.
/// It is not accepted by the real worker: all real profiles remain disabled.
struct PINChangeBinding: Codable, Equatable, Sendable {
    let version: Int
    let profileRevision: String
    let driverID: String
    let applicationIDs: [String]
    let authenticationID: String
    let pinDomain: String
    let token: SignumToken
    let discoveryID: UUID
    let files: [String: PINChangeFileEvidence]

    init(profileRevision: String, driverID: String, applicationIDs: [String], authenticationID: String,
         pinDomain: String, token: SignumToken, discoveryID: UUID, evidenceFiles: [String: URL]) throws {
        guard !profileRevision.isEmpty, !driverID.isEmpty, !pinDomain.isEmpty,
              [profileRevision, driverID, pinDomain].allSatisfy({ $0.utf8.count <= 256 && !$0.utf8.contains(0) }),
              !token.serial.isEmpty, token.serial.utf8.count <= 32,
              !applicationIDs.isEmpty, applicationIDs.count <= 8, Set(applicationIDs).count == applicationIDs.count,
              ([authenticationID] + applicationIDs).allSatisfy({ !$0.isEmpty && $0.count <= 64 && $0.count % 2 == 0 && $0.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) } }),
              evidenceFiles["module"] != nil, evidenceFiles["configuration"] != nil,
              evidenceFiles.keys.contains(where: { $0.hasPrefix("dependency:") }), evidenceFiles.count <= 16,
              evidenceFiles.keys.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 && !$0.utf8.contains(0) }) else {
            throw PINManagementFailure.contextChanged
        }
        self.version = 1; self.profileRevision = profileRevision; self.driverID = driverID
        self.applicationIDs = applicationIDs.sorted(); self.authenticationID = authenticationID
        self.pinDomain = pinDomain; self.token = token; self.discoveryID = discoveryID
        self.files = try evidenceFiles.mapValues { try PINChangeFileEvidence.capture($0) }
        guard valid else { throw PINManagementFailure.contextChanged }
    }
    private var valid: Bool {
        version == 1 && !profileRevision.isEmpty && !driverID.isEmpty && !pinDomain.isEmpty &&
        [profileRevision,driverID,pinDomain].allSatisfy { $0.utf8.count <= 256 && !$0.utf8.contains(0) } &&
        !token.serial.trimmingCharacters(in: .whitespaces).isEmpty && [(token.serial,32),(token.label,128),(token.model,128),(token.manufacturer,128),(token.reader,256)].allSatisfy { $0.0.utf8.count <= $0.1 && !$0.0.utf8.contains(0) } &&
        !applicationIDs.isEmpty && applicationIDs.count <= 8 && applicationIDs == applicationIDs.sorted() && Set(applicationIDs).count == applicationIDs.count &&
        ([authenticationID] + applicationIDs).allSatisfy { !$0.isEmpty && $0.count <= 64 && $0.count % 2 == 0 && $0.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) } } &&
        files["module"] != nil && files["configuration"] != nil && files.keys.contains { $0.hasPrefix("dependency:") } && files.count <= 16 &&
        files.allSatisfy { role,e in
            !role.isEmpty && role.utf8.count <= 128 && !role.utf8.contains(0) && e.path.hasPrefix("/") && !e.path.utf8.contains(0) &&
            e.inode > 0 && e.size >= 0 && e.size <= 64 * 1024 * 1024 && e.sha256.count == 64 &&
            e.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
    }
    var fingerprint: String { valid ? Self.digest(self) : "" }
    /// Stable safety key deliberately excludes provider, config, binaries and
    /// discovery generation: upgrades/refresh must not bypass an uncertain result.
    /// Public serial metadata alone is NOT a qualified physical attestation.
    var journalDomain: String {
        guard valid else { return "" }
        struct Domain: Encodable { let serial: String }
        return Self.digest(Domain(serial: token.serial.trimmingCharacters(in: .whitespaces).uppercased()))
    }
    func requireCurrentEvidence() throws {
        guard valid else { throw PINManagementFailure.contextChanged }
        for evidence in files.values {
            guard try PINChangeFileEvidence.capture(URL(fileURLWithPath: evidence.path)) == evidence else {
                throw PINManagementFailure.contextChanged
            }
        }
    }
    private static func digest<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(value) else { return "" }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
#endif

#if os(macOS)
/// Stable across app bundle IDs and upgrades; never Caches/temporary storage.
/// Not called by the disabled real facade. No credential is ever stored here.
struct PINChangeJournalLocation {
    let root: URL
    static func preparePersistentRoot() throws -> Self {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw PINManagementFailure.contextChanged
        }
        return try prepare(in: support)
    }
    // Internal fixture seam: test callers use a private synthetic directory.
    static func prepare(in applicationSupport: URL) throws -> Self {
        guard applicationSupport.isFileURL else { throw PINManagementFailure.contextChanged }
        let directory = applicationSupport.appendingPathComponent("Signum-DeviceAdministration-v1", isDirectory: true)
        guard sg_pin_journal_prepare_directory(directory.path) == 0 else { throw PINManagementFailure.contextChanged }
        return .init(root: directory)
    }
    /// Observation only; never rearms or executes a previous request.
    func recover(_ request: UUID) -> Int32 {
        var bytes = request.uuid
        return withUnsafeBytes(of: &bytes) { sg_pin_journal_recover(root.path, $0.bindMemory(to: UInt8.self).baseAddress!) }
    }
}
#endif
