#if os(macOS)
import Foundation
import Security
import CXMLSecurity

/// First interoperable profile only: single enveloped RSA-SHA256, exclusive c14n,
/// root + SignedProperties, SigningCertificateV2 and application/xml DataObjectFormat.
/// Embedded certificate identifies the signer; it is never itself a trust anchor.
public enum XAdES {
    public static let maximumDocumentBytes = 8 * 1024 * 1024
    public struct Verified: Sendable {
        public let certificateDER: Data
        public let signatureValue: Data
        public let signedInfo: Data
        public let declaredTime: String
    }
    static func bytes(_ pointer: UnsafeMutablePointer<UInt8>?, _ size: Int) -> Data {
        guard let pointer, size > 0 else { return Data() }; return Data(bytes:pointer,count:size)
    }
    static func reason(_ value: signum_xades_result) -> String {
        withUnsafeBytes(of:value.error) { String(cString:$0.baseAddress!.assumingMemoryBound(to:CChar.self)) }
    }
    public static func requireUnsignedInput(_ document: Data) throws {
        var result = signum_xades_result(); defer { signum_xades_dispose(&result) }
        let ok = document.withUnsafeBytes { signum_xades_input($0.bindMemory(to:UInt8.self).baseAddress,document.count,&result) }
        guard ok == 1 else { throw SignumError.module(reason(result)) }
    }
    public struct Prepared: Sendable {
        public let attributesToSign: Data
        let template: Data
        public init(document: Data, certificateDER: Data, declaredTime: Date = Date()) throws {
            var result = signum_xades_result(); defer { signum_xades_dispose(&result) }
            let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime]
            let time = formatter.string(from:declaredTime)
            let ok = document.withUnsafeBytes { d in certificateDER.withUnsafeBytes { c in
                signum_xades_prepare(d.bindMemory(to:UInt8.self).baseAddress,document.count,
                    c.bindMemory(to:UInt8.self).baseAddress,certificateDER.count,time,&result)
            } }
            guard ok == 1 else { throw SignumError.module(XAdES.reason(result)) }
            template = XAdES.bytes(result.document,result.document_size)
            attributesToSign = XAdES.bytes(result.signed_info,result.signed_info_size)
        }
        public func finish(signature: Data) throws -> Data {
            var result = signum_xades_result(); defer { signum_xades_dispose(&result) }
            let ok = template.withUnsafeBytes { d in signature.withUnsafeBytes { s in
                signum_xades_finish(d.bindMemory(to:UInt8.self).baseAddress,template.count,
                    s.bindMemory(to:UInt8.self).baseAddress,signature.count,&result)
            } }
            guard ok == 1 else { throw SignumError.module(XAdES.reason(result)) }
            return XAdES.bytes(result.document,result.document_size)
        }
    }
    public static func verify(_ document: Data) throws -> Verified {
        var result = signum_xades_result(); defer { signum_xades_dispose(&result) }
        let ok = document.withUnsafeBytes { signum_xades_verify($0.bindMemory(to:UInt8.self).baseAddress,document.count,&result) }
        guard ok == 1 else {
            if ok == -1 { throw SignumError.invalidSignature }
            throw SignumError.module(reason(result))
        }
        return verifiedResult(result)
    }
    static func verifiedResult(_ result: signum_xades_result) -> Verified {
        let time = withUnsafeBytes(of:result.signing_time) { String(cString:$0.baseAddress!.assumingMemoryBound(to:CChar.self)) }
        return .init(certificateDER:bytes(result.certificate,result.certificate_size),signatureValue:bytes(result.signature,result.signature_size),
                     signedInfo:bytes(result.signed_info,result.signed_info_size),declaredTime:time)
    }
    static func report(_ document: Data, name: String) -> VerificationReport {
        do {
            let v = try verify(document)
            return verifiedReport(v,name:name,digest:DocumentSnapshot.digest(document),format:.xml,reason:"XMLDSig, riferimenti al documento e SignedProperties e identificazione del certificato verificati. Attendibilità separata.")
        } catch SignumError.invalidSignature {
            let signer = SignatureVerificationResult(id:0,integrity:.invalid,certificate:nil,
                algorithm:"RSA-SHA256 · XAdES Baseline-B",declaredTime:"",reason:"Firma, riferimenti XMLDSig o identificazione del certificato non validi.",
                signedRevisionEnd:nil,laterChanges:false,cmsLayer:1)
            return .init(id:UUID(),documentName:name,sha256:DocumentSnapshot.digest(document),format:.xml,signatures:[signer],
                documentState:"signed",issue:"",previewPDF:nil,originalContent:nil)
        } catch {
            return .init(id:UUID(),documentName:name,sha256:DocumentSnapshot.digest(document),format:.xml,signatures:[],
                documentState:"unsupported",issue:"XAdES non verificabile: XML alterato, malformato o fuori dal profilo Baseline-B supportato. " + error.localizedDescription,
                previewPDF:nil,originalContent:nil)
        }
    }
    static func verifiedReport(_ v: Verified,name: String,digest: String,format: VerifiedDocumentFormat,reason: String) -> VerificationReport {
            let cert = SecCertificateCreateWithData(nil,v.certificateDER as CFData)
            let fingerprint = DocumentSnapshot.digest(v.certificateDER)
            var signer = SignatureVerificationResult(id:0,integrity:.verified,
                certificate:.init(subject:cert.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "Certificato XAdES",issuer:"",sha256:fingerprint),
                algorithm:"RSA-SHA256 · XAdES Baseline-B",declaredTime:v.declaredTime,
                reason:reason,
                signedRevisionEnd:nil,laterChanges:false,cmsLayer:1)
            signer.signerDER = v.certificateDER; signer.embeddedCertificateDERs = [v.certificateDER]
            signer.evidence = .init(signatureValue:v.signatureValue,signatureKey:DocumentSnapshot.digest(v.signatureValue),signerIndex:0,
                signedAttributes:[],unsignedAttributes:[],timestampTokens:[],embedded:[],issue:"")
            return .init(id:UUID(),documentName:name,sha256:digest,format:format,signatures:[signer],
                documentState:"signed",issue:"",previewPDF:nil,originalContent:nil)
    }

}
#endif
