import Foundation
import SignumCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let defaultModule = "/Library/bit4id/pkcs11/libbit4xpki.dylib"

func help() {
    print("""
    SignumCLI — experimental PKCS#11 and CAdES prototype

    swift run SignumCLI list [absolute_module_path]
    swift run SignumCLI certs <slot> [absolute_module_path]
    swift run SignumCLI sign-test <slot> <cert_ID_hex> [absolute_module_path]
    swift run SignumCLI sign-cades <slot> <cert_ID_hex> <input> <output.p7m> [absolute_module_path]

    The PIN is entered at a terminal prompt, never as a CLI argument.
    sign-cades produces an EXPERIMENTAL attached CMS/CAdES candidate.
    Independently verify its cryptographic validity before any other use.
    No certificate chain, revocation, EU trust-list or qualification checks are performed.
    """)
}

func inputPIN() throws -> String {
    guard let pointer = getpass("Token PIN (not stored): ") else {
        throw SignumError.module("Cannot read PIN")
    }
    defer { memset(pointer, 0, strlen(pointer)) }
    return String(cString: pointer)
}

func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let action = arguments.first else { help(); return }
    let modulePath: String
    switch action {
    case "list":
        modulePath = arguments.count > 1 ? arguments[1] : defaultModule
    case "certs":
        guard arguments.count >= 2 else { help(); return }
        modulePath = arguments.count > 2 ? arguments[2] : defaultModule
    case "sign-test":
        guard arguments.count >= 3 else { help(); return }
        modulePath = arguments.count > 3 ? arguments[3] : defaultModule
    case "sign-cades":
        guard arguments.count >= 5 else { help(); return }
        modulePath = arguments.count > 5 ? arguments[5] : defaultModule
    default:
        help()
        return
    }

    let module = try PKCS11Module(path: modulePath)
    if action == "list" {
        for token in try module.tokens() {
            print("Slot \(token.slot): \(token.label) [\(token.manufacturer), \(token.model)]")
        }
        return
    }

    guard let slot = UInt(arguments[1]) else {
        throw SignumError.module("Invalid slot")
    }
    let certificates = try module.certificates(slot: slot)
    if action == "certs" {
        for cert in certificates { print("\(cert.label) — ID \(cert.id)") }
        return
    }

    let requestedID = arguments[2].uppercased()
    guard let certificate = certificates.first(where: { $0.id == requestedID }) else {
        throw SignumError.module("Certificate ID not found in this slot")
    }

    if action == "sign-test" {
        let pin = try inputPIN()
        print("Starting hardware signing test (not a PDF signature)...")
        let verified = try module.signAndVerifyTest(slot: slot, certificate: certificate, pin: pin)
        print(verified ? "Verified OK — RSA/SHA-256" : "Verification failed")
        return
    }

    let input = URL(fileURLWithPath: arguments[3])
    let output = URL(fileURLWithPath: arguments[4])
    guard input.standardizedFileURL != output.standardizedFileURL else {
        throw SignumError.module("Input and output must be different files")
    }
    guard output.pathExtension.lowercased() == "p7m" else {
        throw SignumError.module("Output filename must end in .p7m")
    }
    guard !FileManager.default.fileExists(atPath: output.path) else {
        throw SignumError.module("Refusing to overwrite existing output")
    }
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: input.path)
    guard let size = fileAttributes[.size] as? NSNumber,
          size.intValue > 0, size.intValue <= CAdES.maximumDocumentBytes else {
        throw SignumError.module("Input must be 1 byte to 16 MiB")
    }
    let document = try Data(contentsOf: input)
    guard !document.isEmpty && document.count <= CAdES.maximumDocumentBytes else {
        throw SignumError.module("Input exceeds allowed size")
    }
    print("Signing test document with slot \(slot), certificate \(certificate.label).")
    print("This prototype DOES NOT validate certificate trust or legal qualification.")
    let pin = try inputPIN()
    let cms = try module.createCAdES(document: document, slot: slot,
                                     certificate: certificate, pin: pin)
    try cms.write(to: output, options: .atomic)
    print("Created: \(output.path)")
    print("NEXT: verify with: openssl cms -verify -inform DER -binary -noverify -in '\(output.path)' -out /tmp/signum-extracted.dat")
}

do {
    try run()
} catch {
    fputs("Signum error: \(error.localizedDescription)\n", stderr)
    exit(EXIT_FAILURE)
}
