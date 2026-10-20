import Foundation

/// Candidates only: availability and permission to execute are evaluated separately.
public struct MiddlewareDefinition: Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let manufacturer: String
    public let candidatePaths: [String]
    public init(id: String, name: String, manufacturer: String, candidatePaths: [String]) {
        self.id = id; self.name = name; self.manufacturer = manufacturer; self.candidatePaths = candidatePaths
    }
}

public enum MiddlewareRegistry {
    public static let known: [MiddlewareDefinition] = [
        .init(id: "bit4id", name: "Bit4id", manufacturer: "Bit4id",
              candidatePaths: ["/Library/bit4id/pkcs11/libbit4xpki.dylib"]),
        .init(id: "opensc", name: "OpenSC", manufacturer: "OpenSC Project",
              candidatePaths: ["/Library/OpenSC/lib/opensc-pkcs11.so"])
    ]
}
