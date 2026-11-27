// Signs the update manifest published with each release.
//
//   swift scripts/update-signing.swift keygen          creates the Ed25519 key in the login Keychain
//   swift scripts/update-signing.swift public-key      prints the key for SignumUpdatePolicy.trustedPublicKeys
//   swift scripts/update-signing.swift sign --dmg PATH --build N --version V --tag T --output DIR
//         [--bundle-id ID] [--minimum-system 13.0] [--private-key-file PATH]
//   swift scripts/update-signing.swift verify --manifest PATH --signature PATH --public-key BASE64
//
// The private key never leaves the Keychain (or the given file, for tests) and
// is never printed. `sign` writes SignumUpdate.json and SignumUpdate.json.sig.
import CryptoKit
import Foundation
import Security

let service = "io.github.tiertoast.Signum.update-signing"
let account = "ed25519"

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("update-signing: \(message)\n".utf8)); exit(1)
}
func option(_ name: String, _ arguments: [String]) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}
func required(_ name: String, _ arguments: [String]) -> String {
    guard let value = option(name, arguments) else { fail("missing \(name)") }
    return value
}
func keychainKey() -> Curve25519.Signing.PrivateKey? {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
    return try? Curve25519.Signing.PrivateKey(rawRepresentation: data)
}
func privateKey(_ arguments: [String]) -> Curve25519.Signing.PrivateKey {
    if let path = option("--private-key-file", arguments) {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8),
              let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw) else { fail("unreadable private key file") }
        return key
    }
    guard let key = keychainKey() else { fail("no signing key in the Keychain; run keygen first") }
    return key
}
func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case "keygen":
    if keychainKey() != nil { fail("a signing key already exists; refusing to replace it") }
    let key = Curve25519.Signing.PrivateKey()
    let attributes: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                     kSecAttrAccount as String: account, kSecValueData as String: key.rawRepresentation,
                                     kSecAttrLabel as String: "Signum update signing key",
                                     kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else { fail("Keychain error \(status)") }
    print(key.publicKey.rawRepresentation.base64EncodedString())
case "public-key":
    print(privateKey(arguments).publicKey.rawRepresentation.base64EncodedString())
case "sign":
    let dmg = URL(fileURLWithPath: required("--dmg", arguments))
    guard let payload = try? Data(contentsOf: dmg) else { fail("unreadable DMG") }
    guard let build = Int(required("--build", arguments)), build > 0 else { fail("invalid --build") }
    let manifest: [String: Any] = [
        "schema": "signum-update-v1",
        "bundleIdentifier": option("--bundle-id", arguments) ?? "io.github.tiertoast.Signum",
        "version": required("--version", arguments), "build": build, "tag": required("--tag", arguments),
        "minimumSystemVersion": option("--minimum-system", arguments) ?? "13.0",
        "dmg": ["name": dmg.lastPathComponent, "bytes": payload.count, "sha256": sha256(payload)]
    ]
    let output = URL(fileURLWithPath: required("--output", arguments), isDirectory: true)
    guard let data = try? JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .prettyPrinted]) else {
        fail("cannot encode manifest")
    }
    let key = privateKey(arguments)
    guard let signature = try? key.signature(for: data), key.publicKey.isValidSignature(signature, for: data) else {
        fail("signing failed")
    }
    do {
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        try data.write(to: output.appendingPathComponent("SignumUpdate.json"))
        try Data((signature.base64EncodedString() + "\n").utf8).write(to: output.appendingPathComponent("SignumUpdate.json.sig"))
    } catch { fail("cannot write output: \(error)") }
    print("SignumUpdate.json \(sha256(data))")
    print("signed with \(key.publicKey.rawRepresentation.base64EncodedString())")
case "verify":
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: required("--manifest", arguments))),
          let text = try? String(contentsOfFile: required("--signature", arguments), encoding: .utf8),
          let signature = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
          let keyData = Data(base64Encoded: required("--public-key", arguments)),
          let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else { fail("unreadable input") }
    guard key.isValidSignature(signature, for: data) else { fail("INVALID signature") }
    print("valid")
default:
    fail("usage: keygen | public-key | sign … | verify …")
}
