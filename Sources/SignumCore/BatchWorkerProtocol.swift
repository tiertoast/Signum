#if os(macOS)
import Foundation

struct BatchWorkerJob: Codable {
    let id: UUID, snapshotID: UUID
    let sha256: String
    let attributes: Data
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
        Set(jobs.map(\.snapshotID)).count == jobs.count && jobs.allSatisfy {
            $0.sha256.utf8.count == 64 && $0.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
            (1...4096).contains($0.attributes.count)
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
