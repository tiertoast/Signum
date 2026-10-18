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
    var valid: Bool {
        version == 2 && provider.hasPrefix("/") && provider.utf8.count <= 4096 && !provider.utf8.contains(0) &&
        (1...16).contains(serial.utf8.count) && !serial.utf8.contains(0) && certificate.valid &&
        (1...32).contains(jobs.count) && Set(jobs.map(\.id)).count == jobs.count &&
        Set(jobs.map(\.snapshotID)).count == jobs.count && jobs.allSatisfy {
            $0.sha256.utf8.count == 64 && $0.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
            (1...4096).contains($0.attributes.count)
        } && pin.map { (1...64).contains($0.utf8.count) && !$0.utf8.contains(0) } == true
    }
}
struct BatchWorkerCommand: Codable {
    let version: Int
    let batchID: UUID
    let jobID: UUID?
    let index: Int
    let finish: Bool
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
}
#endif
