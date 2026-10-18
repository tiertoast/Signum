#if os(macOS)
import Foundation

/// UI-independent selection lifecycle. No automatic route selection/fallback,
/// including refresh, removal/reinsert, changed slot or provider. A signing job
/// remains a separate immutable value once approved.
public struct DeviceSelection: Sendable {
    public private(set) var requestID = UUID()
    public private(set) var providers: [DiscoveredMiddleware] = []
    public private(set) var certificates: [DeviceCertificate] = []
    public private(set) var selectedRouteID: String?
    public private(set) var isSearching = false
    private var wasCancelled = false
    public init() {}
    public var selectedRoute: DeviceCertificateRoute? {
        certificates.lazy.flatMap(\.routes).first { $0.id == selectedRouteID }
    }
    @discardableResult public mutating func beginDiscovery() -> UUID {
        self = DeviceSelection(); isSearching = true; return requestID
    }
    public mutating func cancelDiscovery() { self = DeviceSelection(); wasCancelled = true }
    @discardableResult public mutating func accept(_ results: [DiscoveredMiddleware], request: UUID, at date: Date = Date()) -> Bool {
        guard request == requestID else { return false }
        providers = results; certificates = DeviceCertificate.collect(results, at: date); selectedRouteID = nil; isSearching = false
        return true
    }
    @discardableResult public mutating func select(routeID: String?) -> Bool {
        guard let routeID else { selectedRouteID = nil; return true }
        guard certificates.contains(where: { $0.routes.contains(where: { $0.id == routeID }) }) else { selectedRouteID = nil; return false }
        selectedRouteID = routeID; return true
    }
    public var message: String {
        if wasCancelled { return "Ricerca annullata. Cerca nuovamente." }
        if isSearching { return "Ricerca dei dispositivi di firma…" }
        if providers.isEmpty { return "Nessuna ricerca completata. Cerca nuovamente." }
        if providers.contains(where: { $0.status == .cancelled }) { return "Ricerca annullata. Cerca nuovamente." }
        if providers.contains(where: { $0.status == .communicationError || $0.status == .partial }) {
            return "Impossibile comunicare con alcuni dispositivi o leggere tutti i certificati. Consulta Configura dispositivo."
        }
        if !certificates.isEmpty { return "Scegli il certificato da utilizzare. Nessuna firma viene avviata dalla ricerca." }
        if providers.contains(where: { !$0.tokens.isEmpty }) { return "Dispositivo rilevato, ma nessun certificato pubblico leggibile. Configura dispositivo per i dettagli." }
        if providers.allSatisfy({ $0.status == .missing }) { return "Software del dispositivo non rilevato. Potrebbe essere necessario installare il software del produttore." }
        if providers.contains(where: { $0.status == .unsafe }) { return "Caricamento automatico non consentito per alcuni software. Consulta Configura dispositivo." }
        return "Nessun dispositivo di firma rilevato. Collega il dispositivo e cerca nuovamente."
    }
}
#endif
