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
do {
    guard args.count == 2 || args.count == 3 || (args.count == 5 && args[3] == "--snapshot") else { throw TLAuthenticationError.rejected("usage: SignumTrustProbe LOTL.xml [IT.xml [--snapshot FILE]]") }
    let now = Date()
    let lotl = try LOTLPivotChain.authenticate(current: Data(contentsOf: URL(fileURLWithPath: args[1])), pivotsOldestFirst: [], now: now)
    show(lotl)
    let p = try TLAuthenticator.italyPointer(lotl: lotl, now: now)
    print("authenticated IT pointer: \(p.location) certificates=\(p.signingCertificateDERs.count)")
    if args.count >= 3 { show(try TLAuthenticator.authenticateItaly(Data(contentsOf: URL(fileURLWithPath: args[2])), lotl: lotl, now: now)) }
    if args.count == 5 {
        try TLSnapshot.save(lotl: Data(contentsOf: URL(fileURLWithPath: args[1])), italy: Data(contentsOf: URL(fileURLWithPath: args[2])), to: URL(fileURLWithPath: args[4]), now: now)
    }
} catch { fputs("REJECTED: \(error)\n", stderr); exit(1) }
