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
    swift run SignumCLI verify <document>
    swift run SignumCLI verify-cades <signed.p7m> [extracted-output]

    The PIN is entered at a terminal prompt, never as a CLI argument.
    sign-cades produces an EXPERIMENTAL attached CMS/CAdES candidate.
    Independently verify its cryptographic validity before any other use.
    The verifier checks CMS integrity only: NO certificate trust/qualification/revocation.
    The extracted output is only saved if explicitly requested and must not exist.
    """)
}


func withCancellation<T>(_ operation: SigningOperation, _ body: () throws -> T) rethrows -> T {
    let previous = signal(SIGINT, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global(qos: .userInitiated))
    source.setEventHandler { operation.requestCancellation() }; source.resume()
    defer { source.cancel(); signal(SIGINT, previous) }
    return try body()
}

func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let action = arguments.first else { help(); return }

    if action == "verify" {
        guard arguments.count == 2 else { help(); return }
        let operation = SigningOperation()
        let report = try withCancellation(operation) {
            try SignumVerificationService.verify(file: URL(fileURLWithPath: arguments[1]), isCancelled: { operation.isCancellationRequested })
        }
        print("\(report.documentName) · \(report.format.rawValue) · \(report.signatures.count) firme")
        print(report.summary)
        if !report.issue.isEmpty { print(report.issue) }
        for signature in report.signatures {
            print("Firma \(signature.id+1): \(signature.integrity.description)")
            if let certificate = signature.certificate { print(certificate.subject); print("SHA-256 certificato: " + certificate.sha256) }
            print(signature.algorithm)
            if let end = signature.signedRevisionEnd { print("Revisione: \(end) byte; modifiche successive: \(signature.laterChanges)") }
            if !signature.reason.isEmpty { print(signature.reason) }
        }
        print(VerificationReport.scope)
        if report.format == .pades { print(VerificationReport.revisionScope) }
        return
    }

    if action == "verify-cades" {
        guard arguments.count == 2 || arguments.count == 3 else { help(); return }
        let input = URL(fileURLWithPath: arguments[1])
        let result = try CAdESVerifier.verify(file: input)
        print("Verified OK — CMS cryptographic integrity (trust NOT assessed)")
        print("Verified nested layers: \(result.verifiedLayerCount); signer entries: \(result.verifiedSignatureCount)")
        for layer in result.levels {
            print("Layer \(layer.level): \(layer.signers.joined(separator: ", "))")
        }
        if arguments.count == 3 {
            let output = URL(fileURLWithPath: arguments[2])
            guard input.standardizedFileURL != output.standardizedFileURL else {
                throw SignumError.module("Extraction output must differ from signed input")
            }
            try SignumFileOutput.writeNew(result.originalDocument, to: output)
            print("Extracted original document to: \(output.path)")
        }
        print("WARNING: No certificate trust, revocation, timestamps or eIDAS validation performed.")
        return
    }

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

    let worker = IsolatedPKCS11Client(), operation = SigningOperation()
    let provider = URL(fileURLWithPath: modulePath).resolvingSymlinksInPath().path
    operation.transition(to: .preparing)
    if action == "list" {
        for token in try withCancellation(operation, { try worker.scan(provider: provider, isCancelled: { operation.isCancellationRequested }).tokens }) {
            print("Slot \(token.slot): \(token.label) [\(token.manufacturer), \(token.model)]")
        }
        return
    }

    guard let slot = UInt(arguments[1]) else {
        throw SignumError.module("Invalid slot")
    }
    // Acquire and validate the whole terminal input before even a public session.
    let acquiredPIN = action == "sign-test" || action == "sign-cades" ? try TerminalPIN.read() : nil
    let rows = try withCancellation(operation) {
        try worker.certificates(provider: provider, slot: slot, isCancelled: { operation.isCancellationRequested })
    }
    let certificates = rows.map(\.certificate)
    if action == "certs" {
        for cert in certificates {
            let der = rows.first(where: { $0.certificate.id == cert.id })!.der
            let assessment = CertificateEligibility.evaluate(certificateDER: der)
            print("\(cert.label) — ID \(cert.id): \(assessment.explanation) · \(assessment.usageDescription)")
        }
        print(CertificateEligibility.scope)
        return
    }

    let requestedID = arguments[2].uppercased()
    guard let certificate = certificates.first(where: { $0.id == requestedID }) else {
        throw SignumError.module("Certificate ID not found in this slot")
    }

    let approvedCertificate = rows.first(where: { $0.certificate.id == certificate.id })!.der
    let assessment = try CertificateEligibility.requireEligible(certificateDER: approvedCertificate)
    print(assessment.explanation)
    print(CertificateEligibility.scope)

    if action == "sign-test" {
        let pin = acquiredPIN!
        print("Starting hardware signing test (not a PDF signature)...")
        try withCancellation(operation) {
            try worker.signProof(provider: provider, slot: slot, certificate: certificate, der: approvedCertificate,
                                 pin: pin, isCancelled: { operation.isCancellationRequested })
        }
        print("Verified OK — RSA/SHA-256")
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
    let snapshot = try DocumentSnapshot.capture(source: input, format: .cades)
    defer { snapshot.close() }
    let job = try SigningJob(snapshot: snapshot, providerPath: provider, slot: slot,
                             certificate: certificate, certificateDER: approvedCertificate, destination: output)
    print("Copia privata da controllare: \(snapshot.fileURL.path)")
    print(job.approvalDescription)
    print("Per approvare questa copia, scrivi FIRMA (qualsiasi altra risposta annulla):")
    fflush(stdout)
    guard readLine() == "FIRMA" else { throw SignumError.module("Firma annullata. Copia privata scartata.") }
    _ = try job.verifiedBytes()
    let pin = acquiredPIN!
    try withCancellation(operation) { try job.signCAdES(using: worker, pin: pin, operation: operation) }
    print("Created: \(output.path)")
    print("NEXT: verify with: openssl cms -verify -inform DER -binary -noverify -in '\(output.path)' -out /tmp/signum-extracted.dat")
}

do {
    try run()
} catch {
    fputs("Signum error: \(error.localizedDescription)\n", stderr)
    exit(EXIT_FAILURE)
}
