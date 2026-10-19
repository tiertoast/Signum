#if os(macOS)
import Foundation
import SignumCore

/// Launches the separately built PoDoFo proof-of-concept with a private stdin pipe.
/// No PIN is passed via argv or process environment. This is not production IPC:
/// secrets may remain in Swift and middleware memory.
enum SignumPAdESHelper {
    static var executableURL: URL {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/signum-pades-local")
    }

    static var available: Bool {
        FileManager.default.isExecutableFile(atPath: executableURL.path)
    }

    struct Field: Equatable, Sendable {
        let pageIndex: Int
        let x: Double
        let y: Double
        let width: Double
        let height: Double
    }

    static func sign(job: SigningJob, pin: String, appearanceName: String, field: Field?, operation: SigningOperation? = nil,
                     executable: URL? = nil, timeout: TimeInterval = 120, appearance: RenderedPAdESAppearance? = nil) throws {
        defer { job.snapshot.close() }
        guard job.format == .pades else { throw SignumError.module("Formato del job non compatibile con PAdES.") }
        guard PAdESInputContract.validPIN(pin) else { throw SignumError.module("PIN non rappresentabile nel trasporto PAdES.") }
        if let frozen = job.padesAppearance, let appearance, frozen.approvalIdentity != appearance.approvalIdentity {
            throw SignumError.module("Appearance differente da quella approvata nel job.")
        }
        let appearance = job.padesAppearance ?? appearance
        try job.requireAvailableDestination()
        _ = try job.verifiedBytes()
        let input = job.snapshot.fileURL, output = job.destination
        let modulePath = job.providerPath, slot = job.slot, certificateID = job.certificate.id
        let expectedCertificate = job.certificateDER
        try CertificateEligibility.requireEligible(certificateDER: expectedCertificate)
        let engine = executable ?? executableURL
        guard FileManager.default.isExecutableFile(atPath: engine.path) else {
            throw SignumError.module("Motore PAdES non installato nel bundle. Compila PoDoFo in locale.")
        }
        guard input.isFileURL, output.isFileURL,
              output.pathExtension.lowercased() == "pdf",
              input.standardizedFileURL != output.standardizedFileURL else {
            throw SignumError.module("Input e output devono essere PDF differenti.")
        }
        guard !FileManager.default.fileExists(atPath: output.path) else {
            throw SignumError.module("File PDF di destinazione già esistente.")
        }

        var args = [
            input.path,
            output.path,
            modulePath,
            String(slot),
            certificateID
        ]
        let field = appearance.map { value -> Field? in
            guard value.configuration.visible else { return nil }
            let c = value.configuration, r = c.rectangle
            return Field(pageIndex:c.pageIndex,x:r.minX,y:r.minY,width:r.width,height:r.height)
        } ?? field
        if let appearance {
            guard appearance.certificateSHA256 == job.certificateSHA256, appearance.pdf.count <= PAdESAppearanceRenderer.maximumPDFBytes else { throw SignumError.module("Appearance non vincolata al certificato approvato.") }
        }
        if let field {
            let values = [field.x, field.y, field.width, field.height]
            guard field.pageIndex >= 0,
                  values.allSatisfy({ $0.isFinite }),
                  field.width > 0, field.height > 0 else {
                throw SignumError.module("Coordinate firma grafica non valide.")
            }
            args += [
                String(field.pageIndex),
                String(field.x),
                String(field.y),
                String(field.width),
                String(field.height)
            ]
        }
        args.append("--pin-stdin")
        if field != nil { args.append(appearance == nil ? "--appearance-stdin" : "--appearance-pdf-stdin") }

        // Supply exactly one line to the helper. This avoids getpass() in GUI
        // contexts and avoids leaking credentials through command arguments.
        var secret = try PAdESInputContract.pinLine(pin)
        if field != nil, let appearance {
            guard !appearance.pdf.isEmpty else { throw SignumError.module("Appearance mancante.") }
            secret.append(contentsOf:(0..<4).reversed().map { UInt8((UInt32(appearance.pdf.count) >> ($0*8)) & 255) })
            secret.append(appearance.pdf)
        } else if field != nil {
            // Helvetica (PDF Standard 14) is used by this first text-only AP.
            // Limit to printable ASCII and avoid injecting protocol delimiters.
            let normalizedName = appearanceName.folding(
                options: .diacriticInsensitive,
                locale: Locale(identifier: "en_US_POSIX")
            )
            let cleanedName = Array(normalizedName.utf8.filter {
                $0 >= 0x20 && $0 <= 0x7E
            }.prefix(90))
            let printableName = cleanedName.isEmpty
                ? Data("Firmatario".utf8)
                : Data(cleanedName)
            secret.append(printableName)
            secret.append(0x0A)
        }
        defer { secret.resetBytes(in: 0..<secret.count) }
        if operation?.isCancellationRequested == true { throw SupervisedProcess.Failure.cancelled }
        operation?.transition(to: .waitingForAuthentication)
        operation?.transition(to: .signing)
        let fingerprint = job.certificateSHA256
        // A bound GUI job never falls back to the explicit legacy v4 helper contract.
        if let binding = job.providerContext {
            guard binding.valid, binding.padesWire.utf8.count <= 16384 else { throw SignumError.module("Contesto PAdES non valido.") }
            args += ["--provider-context-v1", binding.padesWire]
        }
        if let appearance, appearance.configuration.visible, let unit=appearance.configuration.userUnit {
            args += ["--appearance-user-unit",String(Double(unit))]
        }
        args += ["--job-id", job.id.uuidString, "--snapshot-id", job.snapshotIdentity.id.uuidString,
                 "--expected-document-sha256", job.contentSHA256,
                 "--expected-cert-sha256", fingerprint, job.providerContext == nil ? "--verified-output-v4" : "--verified-output-v5"]
        let outcome = PAdESHelperProcess.run(executable: engine, arguments: args, input: &secret,
            destination: output, timeout: timeout, expectedJobID: job.id, expectedProtocolVersion: job.providerContext == nil ? 4 : 5,
            maximumInput: appearance == nil ? 512 : PAdESAppearanceRenderer.maximumPDFBytes+69,
            isCancelled: { operation?.isCancellationRequested ?? false })
        try PAdESHelperProcess.requirePublished(outcome)
        operation?.transition(to: .verifying); operation?.recordPublished()
    }
}
#endif
