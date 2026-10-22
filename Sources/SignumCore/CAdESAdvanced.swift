#if os(macOS)
import Foundation

/// Bounded DER editing only. Existing content, signed attributes and SignatureValue
/// bytes are retained verbatim; cryptographic verification stays in the native helper.
public enum CAdESAdvanced {
    public struct Target: Identifiable, Equatable, Sendable {
        public var id: String { signatureKey }
        public let signatureKey, title: String
    }
    static let counterOID=Data([6,9,42,134,72,134,247,13,1,9,6])
    static func fail() -> SignumError { .module("CMS DER non supportato, ambiguo o oltre i limiti (32 firme, 4 livelli di controfirma, 64 certificati).") }
    static func fields(_ data: Data, tag: UInt8) throws -> [Data] {
        var offset=0;let outer=try DER.read(data,at:&offset,limit:data.count)
        guard outer.tag==tag,offset==data.count else { throw fail() }
        var result=[Data]();offset=outer.contents.lowerBound
        while offset<outer.contents.upperBound {
            let n=try DER.read(data,at:&offset,limit:outer.contents.upperBound)
            guard result.count<128 else { throw fail() };result.append(data.subdata(in:n.full))
        }
        return result
    }
    static func content(_ data: Data, tag: UInt8) throws -> Data {
        var o=0;let n=try DER.read(data,at:&o,limit:data.count)
        guard n.tag==tag,o==data.count else { throw fail() };return data.subdata(in:n.contents)
    }
    struct Signer {
        var parts: [Data]
        let signatureIndex: Int
        init(_ data: Data) throws {
            guard data.count<=1024*1024 else { throw fail() }
            parts=try fields(data,tag:0x30)
            guard parts.count>=5,parts[0].first==2,parts[2].first==0x30 else { throw fail() }
            signatureIndex=parts[3].first==0xa0 ? 5 : 4
            guard parts.count==signatureIndex+1 || (parts.count==signatureIndex+2 && parts.last?.first==0xa1),
                  parts[signatureIndex-1].first==0x30 else { throw fail() }
            let value=try content(parts[signatureIndex],tag:4)
            guard !value.isEmpty,value.count<=16384 else { throw fail() }
        }
        var value: Data { get throws { try content(parts[signatureIndex],tag:4) } }
        var key: String { get throws { DocumentSnapshot.digest(try value) } }
        var encoded: Data { DER.sequence(parts) }
        var unsigned: [Data] { get throws { parts.last?.first==0xa1 ? try fields(parts.last!,tag:0xa1) : [] } }
        func counters() throws -> [Data] {
            var result=[Data]()
            for attr in try unsigned {
                let a=try fields(attr,tag:0x30);guard a.count==2 else { throw fail() }
                if a[0]==counterOID { result += try fields(a[1],tag:0x31) }
            }
            return result
        }
        func appending(_ new: Data, to key: String, depth: Int=0) throws -> Data {
            guard depth<=4 else { throw fail() }
            var attrs=try unsigned,matched=false
            for i in attrs.indices {
                let a=try fields(attrs[i],tag:0x30)
                if a[0]==counterOID {
                    var children=try fields(a[1],tag:0x31)
                    children=try children.map { try Signer($0).appending(new,to:key,depth:depth+1) }
                    if try self.key==key { children.append(new);matched=true }
                    attrs[i]=DER.sequence([counterOID,DER.set(children)])
                }
            }
            if try self.key==key, !matched { attrs.append(DER.attribute(oid:counterOID,value:new)) }
            var updated=parts
            if updated.last?.first==0xa1 { updated.removeLast() }
            if !attrs.isEmpty { var set=DER.set(attrs);set[0]=0xa1;updated.append(set) }
            return DER.sequence(updated)
        }
    }
    struct Container {
        let parts: [Data]
        let certificates: [Data]
        let signers: [Data]
        let document: Data?
        init(_ data: Data) throws {
            guard !data.isEmpty,data.count<=SigningResourceLimits.maximumOutputBytes else { throw fail() }
            let outer=try fields(data,tag:0x30)
            guard outer.count==2,outer[0]==DER.signedDataOID else { throw fail() }
            let wrapped=try fields(outer[1],tag:0xa0);guard wrapped.count==1 else { throw fail() }
            parts=try fields(wrapped[0],tag:0x30)
            guard (4...6).contains(parts.count),parts[0].first==2,parts[1].first==0x31,parts[2].first==0x30,parts.last?.first==0x31 else { throw fail() }
            var position=3,certs=[Data]()
            if parts[position].first==0xa0 { certs=try fields(parts[position],tag:0xa0);position+=1 }
            if parts[position].first==0xa1 { position+=1 }
            guard position==parts.count-1,certs.count<=64,certs.allSatisfy({$0.first==0x30 && $0.count<=65536}) else { throw fail() }
            certificates=certs;signers=try fields(parts.last!,tag:0x31)
            guard !signers.isEmpty,signers.count<=32 else { throw fail() }
            let encapsulated=try fields(parts[2],tag:0x30)
            guard (1...2).contains(encapsulated.count),encapsulated[0]==DER.dataOID else { throw fail() }
            if encapsulated.count==2 {
                let explicit=try fields(encapsulated[1],tag:0xa0);guard explicit.count==1 else { throw fail() }
                document=try content(explicit[0],tag:4)
            } else { document=nil }
            _=try targets()
        }
        func targets() throws -> [Target] {
            var result=[Target]()
            func visit(_ data: Data,depth: Int,path: String) throws {
                guard depth<=4,result.count<32 else { throw fail() }
                let s=try Signer(data),key=try s.key
                guard !result.contains(where:{$0.signatureKey==key}) else { throw fail() }
                var label="Firmatario CMS"
                if let cert=certificates.first(where:{ (try? DER.certificateIdentity($0)).map { DER.sequence([$0.issuer,$0.serial])==s.parts[1] } ?? false }),
                   let identity=try? SignumCertificateIdentity(certificateDER:cert) { label=identity.title }
                result.append(.init(signatureKey:key,title:path+" · "+label+" · "+key.prefix(16)))
                for (i,child) in try s.counters().enumerated() { try visit(child,depth:depth+1,path:path+"/"+String(i+1)) }
            }
            for (i,s) in signers.enumerated() { try visit(s,depth:0,path:String(i+1)) };return result
        }
        func adding(signer: Data,certificate: Data,counterTarget: String?) throws -> Data {
            var updated=parts
            let algorithm=try Signer(signer).parts[2]
            var algorithms=try fields(parts[1],tag:0x31)
            if !algorithms.contains(algorithm) { algorithms.append(algorithm) };updated[1]=DER.set(algorithms)
            var certs=certificates;if !certs.contains(certificate){certs.append(certificate)}
            guard certs.count<=64 else { throw fail() }
            var set=DER.set(certs);set[0]=0xa0
            if updated[3].first==0xa0 { updated[3]=set } else { updated.insert(set,at:3) }
            if let counterTarget { updated[updated.count-1]=DER.set(try signers.map { try Signer($0).appending(signer,to:counterTarget) }) }
            else { updated[updated.count-1]=DER.set(signers+[signer]) }
            let output=DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence(updated))])
            guard output.count<=SigningResourceLimits.maximumOutputBytes else { throw fail() }
            _=try Container(output);return output
        }
    }
    public static func targets(in cms: Data) throws -> [Target] { try Container(cms).targets() }
    public struct Prepared {
        public let attributesToSign: Data
        private let base: CAdES.Prepared
        private let existing: Container?
        private let certificate: Data
        private let target: String?
        private let document: Data
        private let format: SigningFormat
        private let helper: URL?
        public init(document: Data,format: SigningFormat,certificateDER: Data,counterSignatureKey: String?=nil,
                    declaredSigningTime: Date?=Date(),helper: URL?=nil,isCancelled: () -> Bool={false}) throws {
            guard format.isAdvancedCAdES else { throw CAdESAdvanced.fail() }
            self.format=format;self.helper=helper;self.certificate=certificateDER;self.document=document
            if isCancelled(){throw SupervisedProcess.Failure.cancelled}
            if format == .cadesDetached {
                existing=nil;target=nil
                base=try CAdES.Prepared(document:document,certificateDER:certificateDER,declaredSigningTime:declaredSigningTime,detached:true)
            } else {
                let cms=try Container(document)
                guard try cms.targets().count<32 else { throw SignumError.module("Limite di 32 firme/controfirmatari raggiunto prima dell’autenticazione.") }
                guard let payload=cms.document,!payload.isEmpty else { throw SignumError.module("Cofirma/controfirma richiede un CMS attached DER con contenuto presente.") }
                let report=try SignumVerificationService.verify(data:document,name:"input.p7m",helper:helper,isCancelled:isCancelled)
                guard report.integrity == .verified else { throw SignumError.module("Le firme precedenti devono essere tutte verificabili prima di aggiungere una firma.") }
                let bytes: Data
                if format == .cadesCounterSign {
                    guard let key=counterSignatureKey,try cms.targets().contains(where:{$0.signatureKey==key}) else { throw SignumError.module("Seleziona esplicitamente la firma da controfirmare.") }
                    func find(_ s: Data,depth: Int=0) throws -> Data? {
                        guard depth<=4 else { throw CAdESAdvanced.fail() };let signer=try Signer(s)
                        if try signer.key==key {
                            guard depth<4 else {throw SignumError.module("Limite di quattro livelli di controfirma raggiunto prima dell’autenticazione.")}
                            return try signer.value
                        }
                        for c in try signer.counters(){if let value=try find(c,depth:depth+1){return value}};return nil
                    }
                    guard let value=try cms.signers.compactMap({try find($0)}).first else {throw CAdESAdvanced.fail()}
                    bytes=value;target=key
                } else { bytes=payload;target=nil }
                existing=cms
                base=try CAdES.Prepared(document:bytes,certificateDER:certificateDER,declaredSigningTime:declaredSigningTime,counterSignature:format == .cadesCounterSign)
            }
            attributesToSign=base.attributesToSign
        }
        public func finish(signature: Data,isCancelled: () -> Bool={false}) throws -> Data {
            if isCancelled(){throw SupervisedProcess.Failure.cancelled}
            let generated=try base.finish(signature:signature)
            let output: Data
            if let existing { output=try existing.adding(signer:Container(generated).signers[0],certificate:certificate,counterTarget:target) }
            else { output=generated }
            let report=try SignumVerificationService.verify(data:output,name:"output",detachedContent:format == .cadesDetached ? document:nil,helper:helper,isCancelled:isCancelled)
            guard report.integrity == .verified,report.signatures.contains(where:{$0.signerDER==certificate && $0.evidence?.signatureValue==signature}) else {throw SignumError.invalidSignature}
            return output
        }
    }
}
#endif
