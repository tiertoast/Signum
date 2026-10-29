import Foundation
import Darwin
import CCertificatePath
import SignumCore

struct RevocationLocation: Equatable, Sendable {
    let kind: RevocationEvidenceKind
    let url: URL
}
enum CertificateEvidenceMaterial {
    static func issued(_ certificate: Data, by issuer: Data) -> Bool {
        certificate.withUnsafeBytes { c in issuer.withUnsafeBytes { i in
            signum_certificate_issued_by(c.bindMemory(to: UInt8.self).baseAddress,c.count,i.bindMemory(to: UInt8.self).baseAddress,i.count) == 1
        } }
    }
    static func applies(_ evidence: RevocationEvidence,to cert: Data,issuer: Data) -> Bool {
        evidence.der.withUnsafeBytes { e in cert.withUnsafeBytes { c in issuer.withUnsafeBytes { i in
            signum_revocation_targets(evidence.kind.rawValue,e.bindMemory(to: UInt8.self).baseAddress,e.count,
                c.bindMemory(to: UInt8.self).baseAddress,c.count,i.bindMemory(to: UInt8.self).baseAddress,i.count) == 1
        } } }
    }
    static func locations(_ certificate: Data) -> [RevocationLocation] {
        var text = [CChar](repeating: 0,count: 20000)
        _ = certificate.withUnsafeBytes { c in signum_revocation_locations(c.bindMemory(to: UInt8.self).baseAddress,c.count,&text,text.count) }
        return String(cString: text).split(separator: "\n").compactMap { line in
            guard line.count > 2, let url = URL(string: String(line.dropFirst(2))), EndpointPolicy.valid(url) else { return nil }
            return .init(kind: line.first == "O" ? .ocsp : .crl,url: url)
        }
    }
    static func request(_ certificate: Data, issuer: Data) -> Data? {
        var out = [UInt8](repeating: 0,count: 4096), used = 0
        let ok = certificate.withUnsafeBytes { c in issuer.withUnsafeBytes { i in
            signum_ocsp_request(c.bindMemory(to: UInt8.self).baseAddress,c.count,i.bindMemory(to: UInt8.self).baseAddress,i.count,&out,out.count,&used)
        } }
        return ok == 1 ? Data(out.prefix(used)) : nil
    }
}
enum EndpointPolicy {
    static func valid(_ url: URL) -> Bool {
        guard url.absoluteString.utf8.count <= 2048, let c = URLComponents(url: url,resolvingAgainstBaseURL: false),
              ["http","https"].contains(c.scheme), c.user == nil,c.password == nil,c.fragment == nil,
              c.port == nil || c.port == (c.scheme == "https" ? 443 : 80),
              let host = c.host, host.count <= 253, host.contains("."), !host.hasSuffix("."),
              host.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }),
              !host.split(separator: ".").contains(where: { $0.isEmpty || $0.count > 63 || $0.hasPrefix("-") || $0.hasSuffix("-") }),
              !host.hasSuffix(".local"), !host.hasSuffix(".localhost"), !host.hasSuffix(".internal"),
              !host.allSatisfy({ $0.isNumber || $0 == "." }) else { return false }
        return true
    }
    static func publicAddress(_ value: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET,value,&v4) == 1 {
            let n = UInt32(bigEndian: v4.s_addr), a = n >> 24, b = (n >> 16)&255
            return a != 0 && a != 10 && a != 127 && a < 224 && !(a == 100 && (64...127).contains(b)) &&
                !(a == 169 && b == 254) && !(a == 172 && (16...31).contains(b)) &&
                !(a == 192 && (b == 0 || b == 168 || b == 88)) && !(a == 198 && (b == 18 || b == 19 || b == 51)) &&
                !(a == 203 && b == 0 && ((n >> 8)&255) == 113)
        }
        if inet_pton(AF_INET6,value,&v6) == 1 {
            let b = withUnsafeBytes(of: &v6) { Array($0) }
            return b[0]&0xe0 == 0x20 && !(b[0] == 0x20 && b[1] == 0x02) &&
                !(b[0] == 0x20 && b[1] == 0x01 && b[2] < 2) &&
                !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        }
        return false
    }
}
// Injectable only inside this module/tests. Production URLs are never supplied
// by documents directly: they are extracted from the path-validated certificate.
protocol RevocationTransport: Sendable {
    func fetch(_ location: RevocationLocation, body: Data?, isCancelled: @escaping @Sendable () -> Bool) async throws -> Data
}
struct SystemRevocationTransport: RevocationTransport {
    func fetch(_ location: RevocationLocation, body: Data?, isCancelled: @escaping @Sendable () -> Bool) async throws -> Data {
        let task = Task.detached(priority: .utility) {
            let cancelled = { isCancelled() || Task.isCancelled }
            guard EndpointPolicy.valid(location.url), let host = location.url.host else { throw ClientError.endpoint }
            var empty = Data()
            let dns = try SupervisedProcess.run(executable: URL(fileURLWithPath: "/usr/bin/dscacheutil"),
                arguments: ["-q","host","-a","name",host],input: &empty,maximumOutput: 65536,timeout: 3,isCancelled: cancelled)
            let addresses = String(decoding: dns,as: UTF8.self).split(separator: "\n").compactMap { line -> String? in
                let parts = line.split(separator: ":",maxSplits: 1)
                guard parts.count == 2, ["ip_address","ipv6_address"].contains(String(parts[0]).trimmingCharacters(in: .whitespaces)) else { return nil }
                return String(parts[1]).trimmingCharacters(in: .whitespaces)
            }
            guard !addresses.isEmpty, addresses.count <= 32, addresses.allSatisfy(EndpointPolicy.publicAddress), let address = addresses.first else { throw ClientError.endpoint }
            let port = location.url.scheme == "https" ? 443 : 80
            let pinned = address.contains(":") ? "[\(address)]" : address
            var args = ["--disable","--globoff","--silent","--fail","--no-netrc","--noproxy","*","--proxy","",
                "--http1.1","--proto","=http,https","--proto-redir","=http,https","--max-redirs","0",
                "--connect-timeout","3","--max-time","8","--max-filesize",String(RevocationEvidenceVerifier.maximumBytes),
                "--resolve","\(host):\(port):\(pinned)","--write-out","\n%{http_code}"]
            if body != nil { args += ["--header","Content-Type: application/ocsp-request","--header","Accept: application/ocsp-response","--data-binary","@-"] }
            args += ["--url",location.url.absoluteString]
            var input = body ?? Data()
            let response = try SupervisedProcess.run(executable: URL(fileURLWithPath: "/usr/bin/curl"),arguments: args,input: &input,
                maximumInput: 4096,maximumOutput: RevocationEvidenceVerifier.maximumBytes+4,maximumResidentBytes: 256*1024*1024,timeout: 9,isCancelled: cancelled)
            guard response.count > 4, response.suffix(4) == Data("\n200".utf8) else { throw ClientError.response }
            return Data(response.dropLast(4))
        }
        return try await withTaskCancellationHandler(operation: { try await task.value },onCancel: { task.cancel() })
    }
}
enum ClientError: Error { case endpoint, response, budget }
public enum RevocationMode: Sendable { case offline, online }
struct CertificateRevocationCheck: Sendable {
    let results: [RevocationEvidenceResult]
    let reason: String
}
actor RevocationSession {
    let cache: RevocationEvidenceCache?
    let transport: any RevocationTransport
    var requests = 0
    private(set) var fetchedEvidence = [RevocationEvidence]()
    private let localEvidence: [RevocationEvidence]
    private let advancesClock: Bool
    private let startedAt = ProcessInfo.processInfo.systemUptime
    private func current(_ base: Date) -> Date { advancesClock ? base.addingTimeInterval(ProcessInfo.processInfo.systemUptime-startedAt) : base }
    let deadline = ProcessInfo.processInfo.systemUptime + 30
    init(cache: RevocationEvidenceCache?,transport: any RevocationTransport = SystemRevocationTransport(), localEvidence: [RevocationEvidence] = [], advancesClock: Bool = true) {
        self.cache = cache; self.transport = transport; self.localEvidence = Array(localEvidence.prefix(8)); self.advancesClock = advancesClock
    }
    func check(certificate: Data,issuer: Data,evidence: [RevocationEvidence],mode: RevocationMode,now: Date,
               isCancelled: @escaping @Sendable () -> Bool) async -> CertificateRevocationCheck {
        guard !isCancelled(), CertificateEvidenceMaterial.issued(certificate,by: issuer) else { return .init(results: [],reason: "Emittente non verificato o operazione annullata.") }
        var results = [RevocationEvidenceResult]()
        for value in Array(evidence.prefix(64)) + localEvidence {
            guard CertificateEvidenceMaterial.applies(value,to: certificate,issuer: issuer) else { continue }
            let result = RevocationEvidenceVerifier.verify(value,certificate: certificate,issuer: issuer,now: current(now));results.append(result)
            if result.authenticated { _ = try? await cache?.store(value,certificate: certificate,issuer: issuer,now: current(now)) }
        }
        for kind in [RevocationEvidenceKind.ocsp,.crl] {
            if let cached = try? await cache?.load(kind,certificate: certificate,issuer: issuer,now: current(now)) { results.append(cached.result) }
        }
        if results.contains(where: { $0.authenticated }) || mode == .offline || isCancelled() {
            return .init(results: results,reason: mode == .offline ? "Verifica offline: solo evidenze associate e cache riautenticata." : "Evidenze locali verificate.")
        }
        var errorReason = "Nessuna evidenza corrente disponibile."
        let locations = CertificateEvidenceMaterial.locations(certificate)
        let selected = [locations.first { $0.kind == .ocsp },locations.first { $0.kind == .crl }].compactMap { $0 }
        let until = deadline
        for location in selected {
            guard requests < 8, ProcessInfo.processInfo.systemUptime < deadline, !isCancelled(), !Task.isCancelled else { break }
            requests += 1
            let body = location.kind == .ocsp ? CertificateEvidenceMaterial.request(certificate,issuer: issuer) : nil
            if location.kind == .ocsp && body == nil { continue }
            do {
                let bytes = try await transport.fetch(location,body: body,isCancelled: { isCancelled() || ProcessInfo.processInfo.systemUptime >= until })
                guard !isCancelled(), !Task.isCancelled, bytes.count <= RevocationEvidenceVerifier.maximumBytes else { break }
                let value = RevocationEvidence(kind: location.kind,der: bytes)
                if !fetchedEvidence.contains(value) { fetchedEvidence.append(value) }
                // Advance the supplied observation with monotonic elapsed time:
                // production uses today's clock; fixed fixture dates remain reproducible.
                let result = RevocationEvidenceVerifier.verify(value,certificate: certificate,issuer: issuer,now: current(now))
                results.append(result)
                if result.authenticated { _ = try? await cache?.store(value,certificate: certificate,issuer: issuer,now: current(now)) }
                if result.state == .revoked { break }
            } catch { errorReason = "Rete assente, endpoint rifiutato o risposta non disponibile: esito indeterminato." }
        }
        return .init(results: results,reason: errorReason)
    }
}
