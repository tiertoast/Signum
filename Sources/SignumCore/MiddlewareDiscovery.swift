#if os(macOS)
import Foundation

public enum MiddlewareOrigin: String, Sendable { case known, manual }
public enum MiddlewareDetectionStatus: String, Sendable {
    case missing, unsafe, communicationError, ready, noToken, partial, cancelled, duplicate
    public var message: String {
        switch self {
        case .missing: return "Software non rilevato. Potrebbe essere necessario installare il software del produttore."
        case .unsafe: return "Caricamento automatico non consentito: percorso o autorizzazioni non sicuri."
        case .communicationError: return "Impossibile comunicare con il software del dispositivo."
        case .ready: return "Dispositivo rilevato."
        case .noToken: return "Software disponibile; nessun dispositivo di firma rilevato."
        case .partial: return "Alcuni dispositivi o certificati non sono leggibili. Cerca nuovamente."
        case .cancelled: return "Ricerca annullata."
        case .duplicate: return "Stesso modulo già rilevato tramite un altro percorso."
        }
    }
}
public struct DiscoveredToken: Sendable {
    public enum CertificateState: String, Sendable { case readable, empty, authenticationRequired, communicationError, notInspected }
    public let token: SignumToken
    public let certificates: [IsolatedPKCS11Client.Certificate]
    public let certificateState: CertificateState
    public var message: String {
        switch certificateState {
        case .readable: return "Certificati pubblici letti."
        case .empty: return "Nessun certificato pubblico visibile; il dispositivo potrebbe richiedere autenticazione."
        case .authenticationRequired: return "Il dispositivo richiede autenticazione per leggere i certificati; nessun PIN inviato."
        case .communicationError: return "Impossibile leggere i certificati del dispositivo."
        case .notInspected: return "Dispositivo rilevato, lettura non completata. Cerca nuovamente."
        }
    }
}
public struct DiscoveredMiddleware: Identifiable, Sendable {
    public let id: String
    public let definition: MiddlewareDefinition
    public let origin: MiddlewareOrigin
    public let candidatePath: String
    public let inspection: MiddlewareFileSecurity.Inspection?
    public let status: MiddlewareDetectionStatus
    public let tokens: [DiscoveredToken]
    /// Optional vendor-reported version, never a trust decision.
    public let version: String?
    public let unavailableSlots: Int
    public var diagnostic: String { status.message }
}

/// Synchronous off-main orchestrator; bounded known paths, existing supervised
/// one-shot workers, public calls only. No provider fallback or authentication.
public struct MiddlewareDiscovery: Sendable {
    let client: IsolatedPKCS11Client
    public init(client: IsolatedPKCS11Client = .init()) { self.client = client }
    public func discover(registry: [MiddlewareDefinition] = MiddlewareRegistry.known,
                         manualPaths: [String] = [], timeout: TimeInterval = 30,
                         isCancelled: () -> Bool = { false }) -> [DiscoveredMiddleware] {
        discover(registry: registry, manualPaths: manualPaths, timeout: timeout, isCancelled: isCancelled,
                 inspect: MiddlewareFileSecurity.inspect,
                 scan: { path, identity, automatic, limit in
                    try client.scan(provider: path, timeout: limit, expectedModule: identity, automatic: automatic, isCancelled: isCancelled)
                 }, certificates: { path, slot, identity, automatic, limit in
                    try client.certificates(provider: path, slot: slot, timeout: limit, expectedModule: identity, automatic: automatic, isCancelled: isCancelled)
                 })
    }
    func discover(registry: [MiddlewareDefinition], manualPaths: [String] = [], timeout: TimeInterval = 30,
                  isCancelled: () -> Bool = { false },
                  inspect: (String, Bool) throws -> MiddlewareFileSecurity.Inspection,
                  scan: (String, MiddlewareFileIdentity, Bool, TimeInterval) throws -> IsolatedPKCS11Client.Scan,
                  certificates: (String, UInt, MiddlewareFileIdentity, Bool, TimeInterval) throws -> [IsolatedPKCS11Client.Certificate]) -> [DiscoveredMiddleware] {
        let deadline = ProcessInfo.processInfo.systemUptime + min(max(timeout, 0), 60)
        var rows: [DiscoveredMiddleware] = [], seen = Set<String>()
        let candidates = registry.prefix(16).flatMap { definition in definition.candidatePaths.prefix(4).map { (definition, $0, MiddlewareOrigin.known) } } +
            manualPaths.prefix(8).map { (MiddlewareDefinition(id: "manual", name: "Software selezionato manualmente", manufacturer: "Non verificato", candidatePaths: [$0]), $0, MiddlewareOrigin.manual) }
        var totalCertificates = 0, totalDERBytes = 0
        for (definition, path, origin) in candidates {
            var inspection: MiddlewareFileSecurity.Inspection?, tokens: [DiscoveredToken] = []
            var state: MiddlewareDetectionStatus = .communicationError, unavailable = 0
            func remaining() throws -> TimeInterval {
                if isCancelled() { throw SupervisedProcess.Failure.cancelled }
                let seconds = deadline - ProcessInfo.processInfo.systemUptime
                guard seconds > 0 else { throw SupervisedProcess.Failure.timeout }; return min(seconds, 8)
            }
            do {
                _ = try remaining()
                let checked = try inspect(path, origin == .known); inspection = checked
                if !seen.insert(checked.identity.moduleKey).inserted { state = .duplicate }
                else {
                    let scan = try scan(checked.canonicalPath, checked.identity, origin == .known, remaining())
                    guard scan.provider == checked.canonicalPath else { throw SupervisedProcess.Failure.protocolViolation }
                    unavailable = scan.unavailableSlots
                    state = unavailable > 0 ? .partial : (scan.tokens.isEmpty ? .noToken : .ready)
                    for (index, token) in scan.tokens.enumerated() {
                        var found: [IsolatedPKCS11Client.Certificate] = [], certificateState = DiscoveredToken.CertificateState.notInspected
                        if index < 32 && totalCertificates < 256 && totalDERBytes < 8 * 1024 * 1024 {
                            do {
                                found = try certificates(checked.canonicalPath, token.slot, checked.identity, origin == .known, remaining())
                                let bytes = found.reduce(0) { $0 + $1.der.count }
                                guard totalCertificates + found.count <= 256, totalDERBytes + bytes <= 8 * 1024 * 1024 else { throw SupervisedProcess.Failure.capacity }
                                totalCertificates += found.count; totalDERBytes += bytes
                                certificateState = found.isEmpty ? .empty : .readable
                            } catch IsolatedPKCS11Client.Failure.authenticationRequired { certificateState = .authenticationRequired }
                            catch { found = []; certificateState = .communicationError }
                        }
                        if certificateState != .readable && certificateState != .empty { state = .partial }
                        tokens.append(.init(token: token, certificates: found, certificateState: certificateState))
                    }
                    let after = try inspect(path, origin == .known)
                    guard after.canonicalPath == checked.canonicalPath, after.identity == checked.identity else { throw MiddlewareFileSecurity.Failure.changed }
                    if isCancelled() { throw SupervisedProcess.Failure.cancelled }
                }
            } catch MiddlewareFileSecurity.Failure.missing { state = .missing; tokens = [] }
            catch MiddlewareFileSecurity.Failure.unsafe { state = .unsafe; tokens = [] }
            catch MiddlewareFileSecurity.Failure.changed { state = .unsafe; tokens = [] }
            catch SupervisedProcess.Failure.cancelled { state = .cancelled; tokens = [] }
            catch { state = .communicationError; tokens = [] }
            rows.append(.init(id: definition.id + ":" + path, definition: definition, origin: origin,
                candidatePath: path, inspection: inspection, status: state, tokens: tokens, version: nil, unavailableSlots: unavailable))
        }
        return rows
    }
}
#endif
