import Foundation
import CPKCS11
#if canImport(Security)
import Security
#endif

public enum SignumError: Error, LocalizedError {
    case module(String)
    case unsupportedPlatform
    case invalidCertificate
    case invalidSignature
    case outputUncertain(String)

    public var errorDescription: String? {
        switch self {
        case .module(let description): return description
        case .outputUncertain(let description): return "Esito incerto: \(description)"
        case .unsupportedPlatform: return "Independent signature verification requires macOS Security.framework"
        case .invalidCertificate: return "The token did not provide a valid X.509 certificate"
        case .invalidSignature: return "Signature verification failed"
        }
    }
}

public struct SignumToken: Identifiable, Hashable {
    public let slot: UInt
    public let label: String
    public let manufacturer: String
    public let model: String
    public let reader: String

    public init(slot: UInt, label: String, manufacturer: String,
                model: String, reader: String = "") {
        self.slot = slot
        self.label = label
        self.manufacturer = manufacturer
        self.model = model
        self.reader = reader
    }

    public var id: UInt { slot }

    /// Best-effort description from PKCS#11 metadata, not a physical USB-bus probe.
    public var deviceKind: String {
        let text = "\(label) \(model) \(reader)".lowercased()
        if text.contains("digitaldna") || text.contains("digital-dna") {
            return "Token USB"
        }
        if text.contains("cns") || text.contains("smart card") ||
            text.contains("smartcard") || text.contains("hamlet") {
            return "Smart card"
        }
        return "Dispositivo PKCS#11"
    }

    public var readerDescription: String {
        reader.isEmpty ? "Lettore non identificato" : "Lettore: \(reader)"
    }

    public var iconName: String {
        switch deviceKind {
        case "Token USB": return "externaldrive"
        case "Smart card": return "creditcard"
        default: return "key.horizontal"
        }
    }
}

public struct SignumCertificate: Identifiable, Hashable {
    public let label: String
    public let identifier: Data
    public var id: String { identifier.map { String(format: "%02X", $0) }.joined() }
}

public struct SignumTokenScan {
    public let tokens: [SignumToken]
    public let unavailableSlots: Int
}

/// Loads an installed PKCS#11 provider. Native calls share an in-process owner
/// per canonical module and serialize complete session transactions. Retain the
/// object during a call. Higher-level multi-call jobs still need their own state.
/// The driver executes in-process: use trusted modules and call off the UI thread.
public final class PKCS11Module: @unchecked Sendable {
    // Immutable Swift state; each C entry point serializes the shared provider.
    private let context: OpaquePointer
    public let modulePath: String

    public init(path: String) throws {
        // Validate locally installed middleware BEFORE dlopen executes any code.
        try Self.requireSafeModulePermissions(path: path)
        var pointer: OpaquePointer?
        var diagnostics = [CChar](repeating: 0, count: 512)
        let status = path.withCString { p in
            diagnostics.withUnsafeMutableBufferPointer { buffer in
                sg_open(p, &pointer, buffer.baseAddress, buffer.count)
            }
        }
        guard status == 0, let pointer else { throw SignumError.module(Self.diagnostic(diagnostics)) }
        context = pointer
        modulePath = sg_canonical_path(pointer).map { String(cString: $0) } ?? path
    }

    private final class RetiredContext: @unchecked Sendable {
        let pointer: OpaquePointer
        init(_ pointer: OpaquePointer) { self.pointer = pointer }
    }
    private static let releaseQueue = DispatchQueue(label: "Signum.provider.release", qos: .utility, attributes: .concurrent)

    deinit {
        // Finalization may block in vendor code. Never run it while SwiftUI
        // releases a View's last reference on the main thread.
        let retired = RetiredContext(context)
        Self.releaseQueue.async { sg_close(retired.pointer) }
    }

    public func tokens() throws -> [SignumToken] {
        try scanTokens().tokens
    }

    /// A reader may expose a slot before its card is ready. Return the other
    /// usable devices, plus a count of transiently unavailable slots.
    public func scanTokens() throws -> SignumTokenScan {
        var rows = [SGToken](repeating: SGToken(), count: 256)
        var count = 0
        var unavailable = 0
        try execute { error in
            rows.withUnsafeMutableBufferPointer { buffer in
                sg_tokens(context, buffer.baseAddress, buffer.count, &count,
                          &unavailable, error.baseAddress, error.count)
            }
        }
        let found = rows.prefix(count).map {
            SignumToken(slot: UInt($0.slot), label: Self.fixedString($0.label),
                        manufacturer: Self.fixedString($0.manufacturer),
                        model: Self.fixedString($0.model), reader: Self.fixedString($0.reader))
        }
        return SignumTokenScan(tokens: found, unavailableSlots: unavailable)
    }

    public func certificates(slot: UInt) throws -> [SignumCertificate] {
        var rows = [SGCertificate](repeating: SGCertificate(), count: 256)
        var count = 0
        try execute { error in
            rows.withUnsafeMutableBufferPointer { buffer in
                sg_certificates(context, slot, buffer.baseAddress, buffer.count,
                                &count, error.baseAddress, error.count)
            }
        }
        return rows.prefix(count).map { row in
            let id = withUnsafeBytes(of: row.id) { Data($0.prefix(Int(row.id_length))) }
            return SignumCertificate(label: Self.fixedString(row.label), identifier: id)
        }
    }

    public func certificateDER(slot: UInt, certificate: SignumCertificate) throws -> Data {
        var required = 0
        try certificate.identifier.withUnsafeBytes { id in
            try execute { error in
                sg_certificate_der(context, slot, id.bindMemory(to: UInt8.self).baseAddress,
                                   id.count, nil, 0, &required, error.baseAddress, error.count)
            }
        }
        guard required > 0, required <= 65536 else { throw SignumError.invalidCertificate }
        var der = [UInt8](repeating: 0, count: required)
        try certificate.identifier.withUnsafeBytes { id in
            try execute { error in
                der.withUnsafeMutableBufferPointer { out in
                    sg_certificate_der(context, slot, id.bindMemory(to: UInt8.self).baseAddress,
                                       id.count, out.baseAddress, out.count, &required,
                                       error.baseAddress, error.count)
                }
            }
        }
        return Data(der.prefix(required))
    }

    /// Read the subject DN and issuer CN from the public DER certificate, without PIN.
    /// Do not interpret this information as a validation or trust decision.
    public func certificateIdentity(slot: UInt, certificate: SignumCertificate) throws -> SignumCertificateIdentity {
        try CertificateIdentityReader.read(certificateDER(slot: slot, certificate: certificate))
    }

    /// Demonstration only: raw SHA256withRSA operation via the installed PKCS#11 module.
    /// Do not use this without reviewing the driver and its surrounding configuration.
    private func signRSASHA256(slot: UInt, certificate: SignumCertificate,
                               pin: String, message: Data) throws -> Data {
        guard !pin.isEmpty, !message.isEmpty, message.count <= 1024 * 1024 else {
            throw SignumError.module("Invalid PIN or message size")
        }
        try Self.requireSafeModulePermissions(path: modulePath)
        var signature = [UInt8](repeating: 0, count: 8192)
        var length = 0
        var pinBytes = Array(pin.utf8)
        defer {
            for i in pinBytes.indices { pinBytes[i] = 0 }
        }
        try certificate.identifier.withUnsafeBytes { id in
            try pinBytes.withUnsafeBytes { secret in
                try message.withUnsafeBytes { bytes in
                    try execute { error in
                        signature.withUnsafeMutableBufferPointer { output in
                            sg_sign_test(context, slot,
                                         id.bindMemory(to: UInt8.self).baseAddress, id.count,
                                         secret.bindMemory(to: UInt8.self).baseAddress, secret.count,
                                         bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count,
                                         output.baseAddress, output.count, &length,
                                         error.baseAddress, error.count)
                        }
                    }
                }
            }
        }
        guard length > 0, length <= signature.count else { throw SignumError.invalidSignature }
        return Data(signature.prefix(length))
    }

    /// Conservative pre-load filesystem permission check.
    /// Does NOT replace signature verification, driver isolation or review.
    private static func requireSafeModulePermissions(path: String) throws {
        let fileManager = FileManager.default
        guard path.hasPrefix("/") else {
            throw SignumError.module("PKCS#11 module path must be absolute")
        }
        let absolute = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        guard fileManager.fileExists(atPath: absolute) else {
            throw SignumError.module("PKCS#11 module not found: \(absolute)")
        }

        // Protect against replacing the module through writable ancestor folders.
        // Inspect the original path as well as the resolved target.
        for location in [path, absolute] {
            var parent = (location as NSString).deletingLastPathComponent
            while !parent.isEmpty {
                try verifyPermissions(parent)
                if parent == "/" { break }
                parent = (parent as NSString).deletingLastPathComponent
            }
        }

        let targets = [absolute, absolute + ".conf", absolute + ".rc"]
        for target in targets where fileManager.fileExists(atPath: target) {
            try verifyPermissions(target)
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: target, isDirectory: &isDirectory), isDirectory.boolValue {
                guard let enumerator = fileManager.enumerator(atPath: target) else {
                    throw SignumError.module("Cannot inspect middleware resources")
                }
                var inspected = 0
                while let item = enumerator.nextObject() as? String {
                    inspected += 1
                    guard inspected <= 1000 else {
                        throw SignumError.module("Too many middleware resources to verify")
                    }
                    try verifyPermissions((target as NSString).appendingPathComponent(item))
                }
            }
        }
    }

    private static func verifyPermissions(_ path: String) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let mode = attributes[.posixPermissions] as? NSNumber,
              mode.intValue & 0o022 == 0 else {
            throw SignumError.module("Untrusted writable PKCS#11 component: \(path). Remove group/other write permissions before loading this module.")
        }
    }

    /// Existing synthetic-string test; the signature is verified using Security.framework.
    public func signAndVerifyTest(slot: UInt, certificate: SignumCertificate, pin: String) throws -> Bool {
        #if canImport(Security)
        let message = Data("Signum PKCS11 proof of concept v0.1\n".utf8)
        let cert = try certificateDER(slot: slot, certificate: certificate)
        guard let x509 = SecCertificateCreateWithData(nil, cert as CFData),
              let key = SecCertificateCopyKey(x509) else { throw SignumError.invalidCertificate }
        let signature = try signRSASHA256(slot: slot, certificate: certificate, pin: pin, message: message)
        guard SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                    message as CFData, signature as CFData, nil) else {
            throw SignumError.invalidSignature
        }
        return true
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }

    /// Experimental attached CMS/CAdES candidate. Validation by an independent
    /// CMS/ETSI implementation is mandatory before treating this as a usable document.
    public func createCAdES(document: Data, slot: UInt,
                            certificate: SignumCertificate, pin: String) throws -> Data {
        #if canImport(Security)
        let cert = try certificateDER(slot: slot, certificate: certificate)
        guard let x509 = SecCertificateCreateWithData(nil, cert as CFData),
              let key = SecCertificateCopyKey(x509) else { throw SignumError.invalidCertificate }
        let prepared = try CAdES.Prepared(document: document, certificateDER: cert)
        let signature = try signRSASHA256(slot: slot, certificate: certificate,
                                          pin: pin, message: prepared.attributesToSign)
        guard SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                    prepared.attributesToSign as CFData,
                                    signature as CFData, nil) else {
            throw SignumError.invalidSignature
        }
        return try prepared.finish(signature: signature)
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }

    private func execute(_ perform: (UnsafeMutableBufferPointer<CChar>) -> Int32) throws {
        var diagnostics = [CChar](repeating: 0, count: 512)
        let result = withExtendedLifetime(self) {
            diagnostics.withUnsafeMutableBufferPointer { buffer in perform(buffer) }
        }
        guard result == 0 else { throw SignumError.module(Self.diagnostic(diagnostics)) }
    }

    private static func diagnostic(_ bytes: [CChar]) -> String {
        let message = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        return message.isEmpty ? "Unknown PKCS#11 error" : message
    }

    private static func fixedString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
}
