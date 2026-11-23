#if os(macOS)
import Foundation

struct BatchWorkerJob: Codable {
    let id: UUID, snapshotID: UUID
    let sha256: String
    let attributes: Data
    /// PAdES: the SHA-256 DigestInfo of the CMS signed attributes exists only
    /// once the helper has prepared that PDF. The first job carries it in the
    /// manifest, later ones in their signing command. Signed with CKM_RSA_PKCS.
    var lateDigest: Bool? = nil
    var isLate: Bool { lateDigest == true }
    static let sha256DigestInfoPrefix = Data([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
                                              0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20])
    static func isSHA256DigestInfo(_ data: Data) -> Bool { data.count == 51 && data.prefix(19) == sha256DigestInfoPrefix }
}
struct BatchWorkerStart: Codable {
    let version: Int
    let batchID: UUID
    let provider: String
    let slot: UInt
    let serial: String
    let certificate: WorkerCertificate
    let automatic: Bool
    let moduleIdentity: MiddlewareFileIdentity
    let jobs: [BatchWorkerJob]
    var pin: String?
    var temporaryPIN: Bool? = nil
    var pinLifetimeSeconds: Double? = nil
    var pinIdleSeconds: Double? = nil
    var lifetime: Double { pinLifetimeSeconds ?? 600 }
    var idle: Double { pinIdleSeconds ?? 60 }
    var valid: Bool {
        ((version == 2 && temporaryPIN != true && pinLifetimeSeconds == nil && pinIdleSeconds == nil &&
          pin.map { (1...64).contains($0.utf8.count) && !$0.utf8.contains(0) } == true) ||
         (version == 3 && temporaryPIN == true && pin == nil && lifetime.isFinite && idle.isFinite &&
          (0.05...600).contains(lifetime) && (0.05...60).contains(idle))) && provider.hasPrefix("/") && provider.utf8.count <= 4096 && !provider.utf8.contains(0) &&
        (1...16).contains(serial.utf8.count) && !serial.utf8.contains(0) && certificate.valid &&
        (1...32).contains(jobs.count) && Set(jobs.map(\.id)).count == jobs.count &&
        Set(jobs.map(\.snapshotID)).count == jobs.count && jobs.enumerated().allSatisfy { index, job in
            job.sha256.utf8.count == 64 && job.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
            (!job.isLate ? (1...4096).contains(job.attributes.count)
                : index == 0 ? BatchWorkerJob.isSHA256DigestInfo(job.attributes) : job.attributes.isEmpty)
        }
    }
}
struct BatchWorkerCommand: Codable {
    let version: Int
    let batchID: UUID
    let jobID: UUID?
    let index: Int
    let finish: Bool
    var skip: Bool = false
    /// Only for a lateDigest job: its SHA-256 DigestInfo.
    var digest: Data? = nil
}
struct BatchWorkerReply: Codable {
    let version: Int
    let batchID: UUID
    let jobID: UUID?
    let index: Int
    let signature: Data?
    let reusable: Bool
    let closed: Bool
    let succeeded: Bool
    var failureKind: String? = nil
}
#endif
