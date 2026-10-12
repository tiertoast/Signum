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

    public var errorDescription: String? {
        switch self {
        case .module(let description): return description
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
    public var id: UInt { slot }
}

public struct SignumCertificate: Identifiable, Hashable {
    public let label: String
    public let identifier: Data
    public var id: String { identifier.map { String(format: "%02X", $0) }.joined() }
}

/// Loads an installed PKCS#11 provider. Do not share an instance between threads.
/// The PKCS#11 driver executes inside this process: use trusted modules only.
public final class PKCS11Module {
    private let context: OpaquePointer

    public init(path: String) throws {
        var pointer: OpaquePointer?
        var diagnostics = [CChar](repeating: 0, count: 512)
        let status = path.withCString { p in
            diagnostics.withUnsafeMutableBufferPointer { buffer in
                sg_open(p, &pointer, buffer.baseAddress, buffer.count)
            }
        }
        guard status == 0, let pointer else { throw SignumError.module(Self.diagnostic(diagnostics)) }
        context = pointer
    }

    deinit { sg_close(context) }

    public func tokens() throws -> [SignumToken] {
        var rows = [SGToken](repeating: SGToken(), count: 256)
        var count = 0
        try execute { error in
            rows.withUnsafeMutableBufferPointer { buffer in
                sg_tokens(context, buffer.baseAddress, buffer.count, &count, error.baseAddress, error.count)
            }
        }
        return rows.prefix(count).map {
            SignumToken(slot: UInt($0.slot), label: Self.fixedString($0.label),
                        manufacturer: Self.fixedString($0.manufacturer), model: Self.fixedString($0.model))
        }
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

    /// Signs fixed, synthetic data and verifies RSA/SHA-256 using Security.framework.
    /// Does NOT generate a PAdES, CAdES or qualified electronic signature.
    public func signAndVerifyTest(slot: UInt, certificate: SignumCertificate, pin: String) throws -> Bool {
        #if canImport(Security)
        guard !pin.isEmpty else { throw SignumError.module("PIN is required") }
        let message = Data("Signum PKCS11 proof of concept v0.1\n".utf8)
        let certificateData = try certificateDER(slot: slot, certificate: certificate)
        guard let x509 = SecCertificateCreateWithData(nil, certificateData as CFData),
              let key = SecCertificateCopyKey(x509) else { throw SignumError.invalidCertificate }
        var signature = [UInt8](repeating: 0, count: 8192)
        var length = 0
        try certificate.identifier.withUnsafeBytes { id in
            try pin.utf8CString.withUnsafeBytes { secret in
                try message.withUnsafeBytes { bytes in
                    try execute { error in
                        signature.withUnsafeMutableBufferPointer { output in
                            sg_sign_test(context, slot,
                                         id.bindMemory(to: UInt8.self).baseAddress, id.count,
                                         secret.bindMemory(to: UInt8.self).baseAddress,
                                         max(0, secret.count - 1),
                                         bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count,
                                         output.baseAddress, output.count, &length,
                                         error.baseAddress, error.count)
                        }
                    }
                }
            }
        }
        guard length > 0, length <= signature.count else { throw SignumError.invalidSignature }
        let verified = SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                             message as CFData, Data(signature.prefix(length)) as CFData, nil)
        if !verified { throw SignumError.invalidSignature }
        return verified
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }

    private func execute(_ perform: (UnsafeMutableBufferPointer<CChar>) -> Int32) throws {
        var diagnostics = [CChar](repeating: 0, count: 512)
        let result = diagnostics.withUnsafeMutableBufferPointer { buffer in perform(buffer) }
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
