#if os(macOS)
import Foundation

/// Domain of the existing PAdES line transport, independent of token policy.
public enum PAdESInputContract {
    public static func validPIN(_ value: String) -> Bool {
        (1...64).contains(value.utf8.count) && !value.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 })
    }
    public static func pinLine(_ value: String) throws -> Data {
        guard validPIN(value) else { throw SignumError.module("PIN non rappresentabile nel trasporto PAdES.") }
        var bytes = Data(value.utf8); bytes.append(10); return bytes
    }
}
#endif
