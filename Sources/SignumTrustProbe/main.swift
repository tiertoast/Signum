import Foundation
import SignumTrustAuthentication

// Offline by design. Fetch LOTL first, authenticate it, then obtain the authorized IT URL.
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
    if args.count == 3, ["refresh", "offline", "watch"].contains(args[1]) {
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
