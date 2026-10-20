#if os(macOS)
import Foundation

/// Prepare off-main: local X.509 evaluation and DER identity parsing can involve
/// up to 256 certificates. Applying the immutable result requires no vendor,
/// filesystem or certificate processing on the UI thread.
public struct DeviceDiscoveryResult: Sendable {
    public let providers: [DiscoveredMiddleware]
    public let certificates: [DeviceCertificate]
    public let isComplete: Bool
    /// expectedPaths describes the whole configured scan, before it starts.
    /// Missing coverage, unreadable tokens and errors cannot prove uniqueness.
    public init(providers: [DiscoveredMiddleware], at date: Date = Date(), expectedPaths: Set<String>? = nil) {
        self.providers = providers
        certificates = DeviceCertificate.collect(providers, at: date)
        isComplete = expectedPaths.map { !$0.isEmpty && $0 == Set(providers.map(\.candidatePath)) } == true &&
            providers.allSatisfy { provider in
                [.ready,.missing,.noToken,.duplicate].contains(provider.status) && provider.unavailableSlots == 0 &&
                (provider.status != .ready || provider.inspection != nil) &&
                provider.tokens.allSatisfy { $0.certificateState == .readable && !$0.certificates.isEmpty }
            }
    }
}

/// UI-independent selection lifecycle. Exactly one locally eligible route may
/// be chosen after a complete public scan. No login, PIN, filesystem calls or
/// private-key claims are made here; signing still checks the frozen DER/key.
/// A signing job remains a separate immutable value once approved.
public struct DeviceSelection: Sendable {
    public private(set) var requestID = UUID()
    public private(set) var providers: [DiscoveredMiddleware] = []
    public private(set) var certificates: [DeviceCertificate] = []
    public private(set) var selectedRouteID: String?
    public private(set) var isSearching = false
    public enum SelectionOrigin: Sendable { case automatic, manual }
    public private(set) var selectionOrigin: SelectionOrigin?
    public private(set) var discoveryComplete = false
    private var previousManualRouteID: String?
    private var wasCancelled = false
    public init() {}
    public var selectedRoute: DeviceCertificateRoute? {
        certificates.lazy.flatMap(\.routes).first { $0.id == selectedRouteID }
    }
    @discardableResult public mutating func beginDiscovery() -> UUID {
        let previous = selectionOrigin == .manual ? selectedRouteID : previousManualRouteID
        self = DeviceSelection(); previousManualRouteID = previous
        isSearching = true; return requestID
    }
    public mutating func cancelDiscovery() { self = DeviceSelection(); wasCancelled = true }
    /// Callers must declare configured coverage to enable automatic selection.
    /// A bare array is useful for inspection/manual selection, never proof that
    /// a different configured provider was not omitted from a partial result.
    @discardableResult public mutating func accept(_ results: [DiscoveredMiddleware], request: UUID, at date: Date = Date(), expectedPaths:Set<String>? = nil) -> Bool {
        guard request == requestID, isSearching else { return false }
        return accept(DeviceDiscoveryResult(providers: results, at: date, expectedPaths:expectedPaths), request: request)
    }
    @discardableResult public mutating func accept(_ result: DeviceDiscoveryResult, request: UUID) -> Bool {
        guard request == requestID, isSearching else { return false }
        providers = result.providers; certificates = result.certificates; selectedRouteID = nil; selectionOrigin = nil; isSearching = false
        discoveryComplete = result.isComplete
        let eligible = certificates.flatMap(\.routes).filter { $0.assessment.permitsSigning }
        // Preserve an explicit, still observed complete binding. Auto selections
        // require uniqueness anew; an arriving alternative requires manual choice.
        if let prior=previousManualRouteID, eligible.contains(where: { $0.id == prior }) {
            selectedRouteID=prior; selectionOrigin = .manual
        } else if discoveryComplete, eligible.count == 1 {
            selectedRouteID=eligible[0].id; selectionOrigin = .automatic
        }
        previousManualRouteID = nil
        return true
    }
    @discardableResult public mutating func select(routeID: String?) -> Bool {
        previousManualRouteID = nil
        guard let routeID else { selectedRouteID = nil; selectionOrigin = nil; return true }
        guard !isSearching else { return false }
        guard certificates.contains(where: { $0.routes.contains(where: { $0.id == routeID }) }) else { selectedRouteID = nil; selectionOrigin = nil; return false }
        selectedRouteID = routeID; selectionOrigin = .manual; return true
    }
    public var message: String {
        if wasCancelled { return "Ricerca annullata. Cerca nuovamente." }
        if isSearching { return "Ricerca dei dispositivi di firma…" }
        if providers.isEmpty { return "Nessuna ricerca completata. Cerca nuovamente." }
        if providers.contains(where: { $0.status == .cancelled }) { return "Ricerca annullata. Cerca nuovamente." }
        if providers.contains(where: { $0.status == .communicationError || $0.status == .partial }) {
            return "Impossibile comunicare con alcuni dispositivi o leggere tutti i certificati. Consulta Configura dispositivo."
        }
        if let route=selectedRoute, selectionOrigin == .automatic {
            return "Certificato selezionato automaticamente: \(route.title). Idoneo ai controlli locali; nessun PIN richiesto."
        }
        if !discoveryComplete, !certificates.isEmpty {
            return "Ricerca non completa: l’unicità del certificato non è determinabile. Scegli manualmente o cerca nuovamente."
        }
        if selectedRoute != nil { return "Scelta manuale del certificato conservata. Nessuna firma avviata." }
        if !certificates.isEmpty { return "Scegli il certificato da utilizzare. Nessuna firma viene avviata dalla ricerca." }
        if providers.contains(where: { !$0.tokens.isEmpty }) { return "Dispositivo rilevato, ma nessun certificato pubblico leggibile. Configura dispositivo per i dettagli." }
        if providers.allSatisfy({ $0.status == .missing }) { return "Software del dispositivo non rilevato. Potrebbe essere necessario installare il software del produttore." }
        if providers.contains(where: { $0.status == .unsafe }) { return "Caricamento automatico non consentito per alcuni software. Consulta Configura dispositivo." }
        return "Nessun dispositivo di firma rilevato. Collega il dispositivo e cerca nuovamente."
    }
}
#endif
