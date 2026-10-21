import Foundation
import CCertificatePath

public enum TimestampEvidenceState: String, Sendable { case authenticatedToken, invalid, unsupported }
/// Token-level result. An authenticated token is not yet a proved signature time:
/// the caller must establish TL authorization and revocation of the TSA path.
public struct TimestampEvidenceResult: Equatable, Sendable {
    public let state: TimestampEvidenceState
    public let tokenTime: Date?
    public let reason: String
}
public enum TimestampEvidenceVerifier {
    public static func verify(token: Data, signatureValue: Data, explicitTSAIdentity: Data, observedAt: Date = Date()) -> TimestampEvidenceResult {
        var time: Int64 = 0, reason = [CChar](repeating: 0, count: 512)
        let seconds = observedAt.timeIntervalSince1970
        guard seconds.isFinite, seconds > 0, seconds < 253402300799 else {
            return .init(state: .unsupported, tokenTime: nil, reason: "Data di osservazione non supportata")
        }
        let code = token.withUnsafeBytes { t in signatureValue.withUnsafeBytes { v in explicitTSAIdentity.withUnsafeBytes { a in
            signum_timestamp_token(t.bindMemory(to: UInt8.self).baseAddress, t.count,
                v.bindMemory(to: UInt8.self).baseAddress, v.count,
                a.bindMemory(to: UInt8.self).baseAddress, a.count, Int64(seconds), &time, &reason, reason.count)
        } } }
        return .init(state: code == 1 ? .authenticatedToken : code < 0 ? .invalid : .unsupported,
            tokenTime: code == 1 ? Date(timeIntervalSince1970: Double(time)) : nil, reason: String(cString: reason))
    }
}
