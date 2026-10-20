#if os(macOS)
import Foundation

/// A read-only result bound to exact snapshot bytes. Acceptance is limited to
/// the native verifier's supported source profile; final verification is mandatory.
public struct PAdESSourcePreflight: Decodable, Sendable, Equatable {
    public enum Status: String, Decodable, Sendable { case accepted, rejected }
    public let version: Int
    public let status: Status
    public let sha256: String
    public let reason: String

    public func requireAccepted(for snapshot: DocumentSnapshot) throws {
        guard version == 1, sha256 == snapshot.identity.sha256 else { throw SupervisedProcess.Failure.protocolViolation }
        guard status == .accepted else { throw SignumError.module("PDF non compatibile con il profilo di firma supportato: \(reason)") }
    }
    public static func inspect(_ snapshot: DocumentSnapshot, helper: URL? = nil, timeout: TimeInterval = 30,
                               isCancelled: () -> Bool = { false }) throws -> Self {
        var bytes = try snapshot.verifiedBytes()
        if isCancelled() { throw SupervisedProcess.Failure.cancelled }
        let response = try SupervisedProcess.run(executable: helper ?? SignumVerificationService.bundledHelper,
            arguments: ["--source-preflight-stdin-v1"], input: &bytes,
            maximumInput: SigningResourceLimits.maximumDocumentBytes, maximumOutput: 4096,
            maximumResidentBytes: 1024*1024*1024, timeout: timeout, isCancelled: isCancelled)
        let result = try JSONDecoder().decode(Self.self, from: response)
        guard result.version == 1, result.sha256 == snapshot.identity.sha256, result.reason.utf8.count <= 1024,
              result.status != .accepted || result.reason.isEmpty else { throw SupervisedProcess.Failure.protocolViolation }
        _ = try snapshot.verifiedBytes()
        return result
    }
}
#endif
