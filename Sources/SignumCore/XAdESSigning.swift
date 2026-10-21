#if os(macOS)
import Foundation
import Darwin

extension SigningJob {
    public func signAdvancedCAdES(using worker: IsolatedPKCS11Client,pin: String,operation: SigningOperation,timeout: TimeInterval=120,helper: URL?=nil) throws {
        guard format.isAdvancedCAdES else { throw SignumError.module("Operazione CAdES avanzata non approvata.") }
        try signXAdES(using:worker,pin:pin,operation:operation,timeout:timeout,helper:helper)
    }

    /// Only canonical SignedInfo goes to the existing one-shot worker. The exact
    /// approved document and bound certificate remain in the parent process.
    public func signXAdES(using worker: IsolatedPKCS11Client, pin: String,
                          operation: SigningOperation, timeout: TimeInterval = 120, helper: URL? = nil) throws {
        defer { snapshot.close() }
        guard operation.state == .idle || operation.state == .preparing else {
            throw SignumError.module("Operazione già avviata o conclusa.")
        }
        var submitted = false, received = false
        operation.transition(to:.preparing)
        var io = SignumFileOutput.OutputIO()
        io.beforePublish = { try operation.checkCancellation() }
        io.publish = { stage,payload,parent,destination in
            guard operation.beginPublication() else { errno = ECANCELED; return -1 }
            return renameatx_np(stage,payload,parent,destination,UInt32(RENAME_EXCL))
        }
        do {
            try operation.checkCancellation()
            try executeXAdES(helper:helper,io:io,isCancelled:{ operation.isCancellationRequested }) { signedInfo in
                operation.transition(to:.waitingForAuthentication)
                try operation.checkCancellation()
                operation.transition(to:.signing); submitted = true
                let signature = try worker.sign(provider:providerPath,slot:slot,certificate:certificate,der:certificateDER,
                    attributes:signedInfo,pin:pin,id:id,timeout:timeout,providerContext:providerContext,
                    isCancelled:{ operation.isCancellationRequested })
                received = true; operation.transition(to:.verifying)
                try operation.checkCancellation()
                return signature
            }
            operation.transition(to:.completed)
        } catch {
            if case SignumError.outputUncertain = error { operation.transition(to:.outcomeUncertain); throw error }
            if submitted && !received && !(error is IsolatedPKCS11Client.Failure) &&
                (error as? SupervisedProcess.Failure) != .launch && (error as? SupervisedProcess.Failure) != .capacity {
                operation.transition(to:.outcomeUncertain)
                throw SignumError.outputUncertain("Richiesta privata interrotta o senza firma verificabile. Nessun documento pubblicato; non ripetere automaticamente il PIN.")
            }
            if operation.isCancellationRequested { operation.transition(to:.cancelled); throw SupervisedProcess.Failure.cancelled }
            operation.transition(to:.failed); throw error
        }
    }
    func executeXAdES(helper: URL?=nil,io: SignumFileOutput.OutputIO = .init(), isCancelled: () -> Bool = { false }, sign: (Data) throws -> Data) throws {
        defer { snapshot.close() }
        guard format == .xades || format.isASiC || format.isAdvancedCAdES else { throw SignumError.module("Formato del job non compatibile con XAdES.") }
        try requireAvailableDestination()
        let approved = try verifiedBytes()
        try CertificateEligibility.requireEligible(certificateDER:certificateDER)
        let output: Data
        if format.isAdvancedCAdES {
            let prepared=try CAdESAdvanced.Prepared(document:approved,format:format,certificateDER:certificateDER,
                counterSignatureKey:counterSignatureKey,declaredSigningTime:includeSigningTime ? Date():nil,helper:helper,isCancelled:isCancelled)
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            output=try prepared.finish(signature:sign(prepared.attributesToSign),isCancelled:isCancelled)
        } else if format.isASiC {
            let prepared = try ASiC.Prepared(unsignedArchive:approved,certificateDER:certificateDER)
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            output = try prepared.finish(signature:sign(prepared.attributesToSign))
        } else {
            let prepared = try XAdES.Prepared(document:approved,certificateDER:certificateDER)
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            output = try prepared.finish(signature:sign(prepared.attributesToSign))
        }
        if isCancelled() { throw SupervisedProcess.Failure.cancelled }
        _ = try verifiedBytes()
        try SignumFileOutput.writeNew(output,to:destination,expectedDirectory:destinationDirectoryIdentity,io:io) { staged in
            if isCancelled() { throw SupervisedProcess.Failure.cancelled }
            _ = try verifiedBytes()
            if format.isAdvancedCAdES {
                guard staged==output else { throw SignumError.invalidSignature }
                let report=try SignumVerificationService.verify(data:staged,name:"staged",detachedContent:format == .cadesDetached ? approved:nil,helper:helper,isCancelled:isCancelled)
                guard report.integrity == .verified,report.signatures.contains(where:{$0.signerDER==certificateDER}) else { throw SignumError.invalidSignature }
                return
            }
            let signer = try format.isASiC ? ASiC.verify(staged).signature.certificateDER : XAdES.verify(staged).certificateDER
            guard staged == output, signer == certificateDER else { throw SignumError.invalidSignature }
        }
    }
}
#endif
