import Foundation
import SignumTrustAuthentication
import SignumCertificateValidation
import SignumCore

// Diagnostic entry points reuse the production validators and authenticated cache.
let args = CommandLine.arguments
func show(_ value: AuthenticatedTL) {
    let d = value.document
    print("\(d.territory) TLv\(d.version) sequence=\(d.sequenceNumber) providers=\(d.providers.count) services=\(d.providers.reduce(0) { $0 + $1.services.count })")
    print("issue=\(d.issuedAt.ISO8601Format()) nextUpdate=\(d.nextUpdate.ISO8601Format())")
    print("signerSHA256=\(value.signerSHA256.map { String(format: "%02x", $0) }.joined())")
}
func show(_ view: TLRefreshView) {
    print("source=\(view.source.rawValue) freshness=\(view.freshness.rawValue) EU=\(view.europeSequence) IT=\(view.italySequence) expires=\(view.expiresAt.ISO8601Format())")
    if let warning = view.warning { print("refresh warning: \(warning)") }
    fflush(stdout)
}
do {
    if (args.count == 4 || args.count == 5 && args[4] == "--online"), args[1] == "evidence" {
        let cache = URL(fileURLWithPath: args[2])
        let view = try? await TLRefreshService(cacheURL: cache).cached()
        let report = try SignumVerificationService.verify(file: URL(fileURLWithPath: args[3]))
        let service = SignatureQualificationService(cache: RevocationEvidenceCache(directory: cache.deletingLastPathComponent().appendingPathComponent("Revocation")))
        let values = await service.validate(report,authenticatedLists: view?.currentItaly.map { [$0] } ?? [],mode: args.count == 5 ? .online : .offline)
        for complete in values {
            let value = complete.evidence
            print("integrity=\(report.signatures.first { $0.id == complete.signatureID }?.integrity.rawValue ?? "unknown") chain=\(complete.path.state.rawValue) chainReason=\(complete.path.reason)")
            print("qualification=\(complete.qualification.state.rawValue) qscd=\(complete.qualification.qscd.rawValue) qualificationReason=\(complete.qualification.reason)")
            print("signature=\(value.signatureID) revocation=\(value.revocation.state.rawValue) time=\(value.time.state.rawValue)")
            print("revocationReason=\(value.revocation.reason)\ntimeReason=\(value.time.reason)")
            print("signingTimeDeclared=\(value.time.declaredSigningTime) provedUpperBound=\(value.time.provenTime?.ISO8601Format() ?? "none")")
            for item in value.associations { print("evidence=\(item.sha256) source=\(item.source) binding=\(item.state.rawValue) reason=\(item.reason)") }
        }
    } else if args.count == 4, args[1] == "path" {
        let view = try? await TLRefreshService(cacheURL: URL(fileURLWithPath: args[2])).cached()
        let report = try SignumVerificationService.verify(file: URL(fileURLWithPath: args[3]))
        for signature in report.signatures {
            let result = signature.signerDER.map { CertificatePathValidator.evaluate(signer: $0, intermediates: signature.embeddedCertificateDERs, authenticatedLists: view?.currentItaly.map { [$0] } ?? []) } ?? .unavailable("Certificato DER assente")
            print("signature=\(signature.id) integrity=\(signature.integrity.rawValue) chain=\(result.state.rawValue) revocation=notChecked qualification=notChecked")
            print("reason=\(result.reason)")
            if let service = result.service { print("provider=\(service.provider) service=\(service.service) country=\(service.country) TL=\(service.listSequence)") }
            for certificate in result.path { print("certificate=\(certificate.sha256) \(certificate.subject)") }
        }
    } else if args.count == 3, ["refresh", "offline", "watch"].contains(args[1]) {
        let cache = URL(fileURLWithPath: args[2])
        try FileManager.default.createDirectory(at: cache.deletingLastPathComponent(), withIntermediateDirectories: true)
        let service = try TLRefreshService(cacheURL: cache)
        if args[1] == "offline" { show(try await service.cached()) }
        else if args[1] == "watch" {
            await service.runAutomatically { result in
                switch result {
                case .success(let view): show(view)
                case .failure(let error): print("refresh error: \(error)")
                }
            }
        } else { show(try await service.refresh(force: true)) }
    } else {
    guard args.count == 2 || args.count == 3 || (args.count == 5 && args[3] == "--snapshot") else { throw TLAuthenticationError.rejected("usage: SignumTrustProbe {refresh|offline|watch} CACHE.json, or LOTL.xml [IT.xml [--snapshot FILE]]") }
    let now = Date()
    let lotl = try LOTLPivotChain.authenticate(current: Data(contentsOf: URL(fileURLWithPath: args[1])), pivotsOldestFirst: [], now: now)
    show(lotl)
    let p = try TLAuthenticator.italyPointer(lotl: lotl, now: now)
    print("authenticated IT pointer: \(p.location) certificates=\(p.signingCertificateDERs.count)")
    if args.count >= 3 { show(try TLAuthenticator.authenticateItaly(Data(contentsOf: URL(fileURLWithPath: args[2])), lotl: lotl, now: now)) }
    if args.count == 5 {
        try TLSnapshot.save(lotl: Data(contentsOf: URL(fileURLWithPath: args[1])), italy: Data(contentsOf: URL(fileURLWithPath: args[2])), to: URL(fileURLWithPath: args[4]), now: now)
    }
    }
} catch { fputs("REJECTED: \(error)\n", stderr); exit(1) }
