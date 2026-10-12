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
    SignumCLI — PKCS#11 proof of concept (NOT PAdES/CAdES)

    swift run SignumCLI list [absolute_module_path]
    swift run SignumCLI certs <slot> [absolute_module_path]
    swift run SignumCLI sign-test <slot> <cert_ID_hex> [absolute_module_path]

    The PIN is entered in the terminal, never as a command-line argument.
    """)
}

func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let action = arguments.first else { help(); return }
    let modulePath: String
    switch action {
    case "list": modulePath = arguments.count > 1 ? arguments[1] : defaultModule
    case "certs":
        guard arguments.count >= 2 else { help(); return }
        modulePath = arguments.count > 2 ? arguments[2] : defaultModule
    case "sign-test":
        guard arguments.count >= 3 else { help(); return }
        modulePath = arguments.count > 3 ? arguments[3] : defaultModule
    default: help(); return
    }
    let module = try PKCS11Module(path: modulePath)
    if action == "list" {
        for token in try module.tokens() {
            print("Slot \(token.slot): \(token.label) [\(token.manufacturer), \(token.model)]")
        }
        return
    }
    guard let slot = UInt(arguments[1]) else { throw SignumError.module("Invalid slot") }
    let certificates = try module.certificates(slot: slot)
    if action == "certs" {
        for cert in certificates { print("\(cert.label) — ID \(cert.id)") }
        return
    }
    let requestedID = arguments[2].uppercased()
    guard let certificate = certificates.first(where: { $0.id == requestedID }) else {
        throw SignumError.module("Certificate ID not found in this slot")
    }
    guard let pointer = getpass("Token PIN (not stored): ") else {
        throw SignumError.module("Cannot read PIN")
    }
    let pin = String(cString: pointer)
    defer { memset(pointer, 0, strlen(pointer)) }
    print("Starting hardware signing test (not a PDF signature)...")
    let verified = try module.signAndVerifyTest(slot: slot, certificate: certificate, pin: pin)
    print(verified ? "Verified OK — RSA/SHA-256" : "Verification failed")
}

do {
    try run()
} catch {
    fputs("Signum error: \(error.localizedDescription)\n", stderr)
    exit(EXIT_FAILURE)
}
