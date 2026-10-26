#if os(macOS)
import Foundation

/// Separate, public-metadata-only contract. No secret field exists in this schema.
struct PINManagementWorkerRequest: Codable {
    static let maximumBytes = 16384
    let version: Int
    let id: UUID
    let operation: String
    let context: PINManagementContext
    var valid: Bool { version == 1 && operation == "readPublicStatus" && context.valid }
    static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "id", "operation", "context"]) else {
            throw PINManagementFailure.protocolViolation
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.valid else { throw PINManagementFailure.protocolViolation }
        // Reject unknown fields at every level, including an attempted PIN/PUK.
        let encoded = try JSONEncoder().encode(value)
        let canonical = try JSONSerialization.jsonObject(with: encoded) as? NSDictionary
        guard let canonical, canonical.isEqual(to: object) else { throw PINManagementFailure.protocolViolation }
        return value
    }
}
struct PINManagementWorkerResponse: Codable {
    let version: Int
    let id: UUID
    let contextFingerprint: String
    let snapshot: PINStatusSnapshot?
    let failure: PINManagementFailure?
}

enum PINManagementWorkerClient {
    static func read(context: PINManagementContext, isCancelled: () -> Bool) throws -> PINStatusSnapshot {
        guard context.valid else { throw PINManagementFailure.contextChanged }
        try context.requireCurrentModule()
        let request = PINManagementWorkerRequest(version: 1, id: UUID(), operation: "readPublicStatus", context: context)
        var input = try JSONEncoder().encode(request)
        let bytes = try SupervisedProcess.run(executable: IsolatedPKCS11Client.bundledExecutable,
            arguments: ["--pin-admin-v1"], input: &input, maximumInput: PINManagementWorkerRequest.maximumBytes,
            maximumOutput: PINManagementWorkerRequest.maximumBytes, timeout: 20, isCancelled: isCancelled)
        let response = try JSONDecoder().decode(PINManagementWorkerResponse.self, from: bytes)
        guard response.version == 1, response.id == request.id, response.contextFingerprint == context.fingerprint else {
            throw PINManagementFailure.protocolViolation
        }
        try context.requireCurrentModule()
        if let failure = response.failure {
            guard response.snapshot == nil else { throw PINManagementFailure.protocolViolation }
            throw failure
        }
        guard let snapshot = response.snapshot, snapshot.valid, snapshot.contextFingerprint == context.fingerprint,
              snapshot.readAt <= Date().addingTimeInterval(5), snapshot.readAt >= Date().addingTimeInterval(-60) else {
            throw PINManagementFailure.protocolViolation
        }
        return snapshot
    }
}
#endif
