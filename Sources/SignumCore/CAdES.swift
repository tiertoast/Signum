import Foundation
import CryptoKit

/// Experimental, attached CMS/CAdES candidate.
/// Only RSA PKCS#1 v1.5 with SHA-256 and one signer's leaf certificate.
/// Independently validate any generated .p7m with a separate implementation.
public enum CAdES {
    public static let maximumDocumentBytes = SigningResourceLimits.maximumDocumentBytes

    public struct Prepared {
        public let attributesToSign: Data
        private let document: Data
        private let certificateDER: Data
        private let signerIdentifier: Data
        private let digestAlgorithm: Data

        public init(document: Data, certificateDER: Data) throws {
            guard !document.isEmpty && document.count <= CAdES.maximumDocumentBytes else {
                throw SignumError.module("Serve un documento non vuoto, fino a \(maximumDocumentBytes / 1024 / 1024) MiB.")
            }
            let identity = try DER.certificateIdentity(certificateDER)
            self.document = document
            self.certificateDER = certificateDER
            self.signerIdentifier = DER.sequence([identity.issuer, identity.serial])
            self.digestAlgorithm = DER.sequence([DER.sha256OID])

            let messageDigest = Data(SHA256.hash(data: document))
            let certificateDigest = Data(SHA256.hash(data: certificateDER))

            // ESSCertIDv2 certHash with default SHA-256; the issuerSerial
            // field is optional in RFC 5035.
            let essCertIDv2 = DER.sequence([DER.octets(certificateDigest)])
            let signingCertificateV2 = DER.sequence([DER.sequence([essCertIDv2])])

            let attributes = [
                DER.attribute(oid: DER.contentTypeAttributeOID, value: DER.dataOID),
                DER.attribute(oid: DER.messageDigestAttributeOID, value: DER.octets(messageDigest)),
                DER.attribute(oid: DER.signingCertificateV2AttributeOID, value: signingCertificateV2)
            ]
            // RFC 5652: sign DER-encoded SET OF attributes (tag 0x31).
            self.attributesToSign = DER.set(attributes)
        }

        public func finish(signature: Data) throws -> Data {
            guard (128...1024).contains(signature.count) else {
                throw SignumError.module("Unexpected RSA signature length")
            }
            // In SignerInfo, signedAttrs is [0] IMPLICIT SET OF Attribute.
            // The signature, however, is calculated over the SET tag 0x31.
            var implicitAttributes = attributesToSign
            implicitAttributes[implicitAttributes.startIndex] = 0xA0

            let signerInfo = DER.sequence([
                DER.integerOne,
                signerIdentifier,
                digestAlgorithm,
                implicitAttributes,
                DER.sequence([DER.rsaEncryptionOID, DER.null]),
                DER.octets(signature)
            ])
            // Same DER ContentInfo/SignedData layout as before. Keep only the
            // small enclosing headers/metadata, then append the attached bytes
            // once. Nested wrap/sequence calls materialized the payload at every
            // enclosing level. Prepared still owns the immutable approved Data.
            let signedPrefix = DER.integerOne + DER.set([digestAlgorithm])
            let signedSuffix = DER.contextImplicit0(certificateDER) + DER.set([signerInfo])
            let octets = DER.header(0x04, length: document.count)
            let explicitDocument = DER.header(0xA0, length: octets.count + document.count)
            let encapsulatedLength = DER.dataOID.count + explicitDocument.count + octets.count + document.count
            let encapsulated = DER.header(0x30, length: encapsulatedLength)
            let signedLength = signedPrefix.count + encapsulated.count + encapsulatedLength + signedSuffix.count
            let signed = DER.header(0x30, length: signedLength)
            let explicitSigned = DER.header(0xA0, length: signed.count + signedLength)
            let outerLength = DER.signedDataOID.count + explicitSigned.count + signed.count + signedLength
            let outer = DER.header(0x30, length: outerLength)
            var result = Data()
            result.reserveCapacity(outer.count + outerLength)
            for prefix in [outer, DER.signedDataOID, explicitSigned, signed, signedPrefix,
                           encapsulated, DER.dataOID, explicitDocument, octets] {
                result.append(prefix)
            }
            result.append(document)
            result.append(signedSuffix)
            return result
        }
    }
}

/// Minimal, bounded DER serializer and X.509 field extractor.
/// Does not parse or validate X.509 certificate semantics.
enum DER {
    static let integerOne = Data([0x02, 0x01, 0x01])
    static let null = Data([0x05, 0x00])
    static let dataOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
    static let signedDataOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
    static let sha256OID = oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
    static let rsaEncryptionOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    static let contentTypeAttributeOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03])
    static let messageDigestAttributeOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04])
    static let signingCertificateV2AttributeOID = oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F])

    private static func oid(_ bytes: [UInt8]) -> Data { wrap(0x06, Data(bytes)) }
    static func octets(_ bytes: Data) -> Data { wrap(0x04, bytes) }
    static func sequence(_ elements: [Data]) -> Data { wrap(0x30, joined(elements)) }
    static func contextExplicit0(_ content: Data) -> Data { wrap(0xA0, content) }
    static func contextImplicit0(_ content: Data) -> Data { wrap(0xA0, content) }

    static func set(_ elements: [Data]) -> Data {
        let sorted = elements.sorted { lhs, rhs in lhs.lexicographicallyPrecedes(rhs) }
        return wrap(0x31, joined(sorted))
    }

    static func attribute(oid: Data, value: Data) -> Data {
        sequence([oid, set([value])])
    }

    private static func joined(_ parts: [Data]) -> Data {
        var result = Data()
        for part in parts { result.append(part) }
        return result
    }

    static func wrap(_ tag: UInt8, _ content: Data) -> Data {
        var result = header(tag, length: content.count)
        result.append(content)
        return result
    }

    static func header(_ tag: UInt8, length: Int) -> Data {
        var result = Data([tag])
        if length < 128 {
            result.append(UInt8(length))
        } else {
            var length = length
            var bytes = [UInt8]()
            while length > 0 {
                bytes.insert(UInt8(length & 0xFF), at: 0)
                length >>= 8
            }
            result.append(UInt8(0x80 | bytes.count))
            result.append(contentsOf: bytes)
        }
        return result
    }

    struct Node {
        let tag: UInt8
        let full: Range<Int>
        let contents: Range<Int>
    }

    static func read<Bytes: RandomAccessCollection>(_ bytes: Bytes, at index: inout Int, limit: Int) throws -> Node
        where Bytes.Element == UInt8, Bytes.Index == Int {
        guard bytes.startIndex == 0, index >= 0, index < limit, limit <= bytes.count else {
            throw SignumError.invalidCertificate
        }
        let start = index
        let tag = bytes[index]
        index += 1
        guard index < limit else { throw SignumError.invalidCertificate }
        let first = bytes[index]
        index += 1

        let length: Int
        if first < 0x80 {
            length = Int(first)
        } else {
            let octetCount = Int(first & 0x7F)
            guard octetCount > 0, octetCount <= 4, index + octetCount <= limit,
                  bytes[index] != 0 else { throw SignumError.invalidCertificate }
            var value = 0
            for _ in 0..<octetCount {
                value = (value << 8) | Int(bytes[index])
                index += 1
            }
            guard value >= 128 else { throw SignumError.invalidCertificate }
            length = value
        }

        guard length <= limit - index else { throw SignumError.invalidCertificate }
        let contents = index..<(index + length)
        index += length
        return Node(tag: tag, full: start..<index, contents: contents)
    }

    static func certificateIdentity(_ certificate: Data) throws -> (issuer: Data, serial: Data) {
        let bytes = [UInt8](certificate)
        guard bytes.count <= 65536 else { throw SignumError.invalidCertificate }
        var offset = 0
        let cert = try read(bytes, at: &offset, limit: bytes.count)
        guard cert.tag == 0x30, offset == bytes.count else {
            throw SignumError.invalidCertificate
        }
        offset = cert.contents.lowerBound
        let tbs = try read(bytes, at: &offset, limit: cert.contents.upperBound)
        guard tbs.tag == 0x30 else { throw SignumError.invalidCertificate }

        var cursor = tbs.contents.lowerBound
        var serial = try read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        if serial.tag == 0xA0 { // optional [0] EXPLICIT X.509 version
            serial = try read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        }
        guard serial.tag == 0x02, !serial.contents.isEmpty else {
            throw SignumError.invalidCertificate
        }
        let signatureAlgorithm = try read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        guard signatureAlgorithm.tag == 0x30 else { throw SignumError.invalidCertificate }
        let issuer = try read(bytes, at: &cursor, limit: tbs.contents.upperBound)
        guard issuer.tag == 0x30 else { throw SignumError.invalidCertificate }

        // Keep the issuer Name and INTEGER as encoded in the original certificate.
        return (Data(bytes[issuer.full]), Data(bytes[serial.full]))
    }
}
