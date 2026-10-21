import Foundation
import Combine
import SignumTrustAuthentication
import SignumTrustCore

/// Authenticated list data only. This boundary deliberately has no signature-trust verdict.
public protocol TrustedListCatalogProviding: Sendable {
    func currentCatalog() async throws -> AuthenticatedTL?
}

public protocol TrustedListsRefreshing: Sendable {
    func cached(now: Date?) async throws -> TLRefreshView
    func refresh(now: Date?, force: Bool) async throws -> TLRefreshView
    func runAutomatically(onUpdate: @Sendable (Result<TLRefreshView, Error>) async -> Void) async
    func cancelRefresh() async
}
extension TLRefreshService: TrustedListsRefreshing, TrustedListCatalogProviding {
    public func currentCatalog() throws -> AuthenticatedTL? { try cached().currentItaly }
}

/// Shares the exact coordinator used by Settings, without promoting raw TL data.
public protocol EuropeanCatalogProviding: TrustedListCatalogProviding {
    var europeanService: EuropeanTrustCatalogService { get }
    func networkAllowed() async -> Bool
    func didUpdate(_ view: EuropeanCatalogView) async
}
public struct EuropeanCatalogProvider: EuropeanCatalogProviding {
    public let europeanService: EuropeanTrustCatalogService
    private let network: @Sendable () async -> Bool
    private let update: @Sendable (EuropeanCatalogView) async -> Void
    public init(service: EuropeanTrustCatalogService,
                networkAllowed: @escaping @Sendable () async -> Bool = { false },
                onUpdate: @escaping @Sendable (EuropeanCatalogView) async -> Void = { _ in }) {
        europeanService = service; network = networkAllowed; update = onUpdate
    }
    public func currentCatalog() async throws -> AuthenticatedTL? { try await europeanService.cached().catalogs["IT"] }
    public func networkAllowed() async -> Bool { await network() }
    public func didUpdate(_ view: EuropeanCatalogView) async { await update(view) }
}

@MainActor public final class TrustedListsModel: ObservableObject {
    public enum Status: String { case current = "Aggiornati", expired = "Obsoleti", unavailable = "Non disponibili", error = "Errore" }
    @Published public private(set) var status: Status = .unavailable
    @Published public private(set) var lastVerifiedUpdate: Date?
    @Published public private(set) var expiresAt: Date?
    @Published public private(set) var providerCount = 0
    @Published public private(set) var serviceCount = 0
    @Published public private(set) var message: String?
    @Published public private(set) var isRefreshing = false
    @Published public private(set) var availableCountries: [String] = []
    @Published public private(set) var acquiredCountries: [String] = []
    @Published public private(set) var countryExpiries: [String: Date] = [:]
    @Published public private(set) var countryWarnings: [String: String] = [:]
    @Published public private(set) var offline = false
    @Published public var selectedCountry = "IT"
    public var isEuropean: Bool { europeanService != nil }
    private let service: (any TrustedListsRefreshing)?
    private let europeanService: EuropeanTrustCatalogService?
    private let clock: @Sendable () -> Date
    private let directory: URL?
    private var lifecycle: Task<Void, Never>?
    private var manual: Task<Void, Never>?
    private var generation = UUID()
    public init(service: any TrustedListsRefreshing, directory: URL? = nil) {
        self.service = service; self.directory = directory; europeanService = nil; clock = { Date() }
    }
    public init(europeanService: EuropeanTrustCatalogService, directory: URL? = nil,
                offline: Bool = false, clock: @escaping @Sendable () -> Date = { Date() }) {
        service = nil; self.europeanService = europeanService; self.directory = directory
        self.offline = offline; self.clock = clock
    }
    public static func developmentPreview() throws -> TrustedListsModel {
        let identity = Bundle.main.bundleIdentifier.flatMap { $0.hasPrefix("io.github.tiertoast.Signum.DevelopmentPreview") ? $0 : nil } ?? "io.github.tiertoast.Signum.DevelopmentPreview.B6"
        let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
            .appendingPathComponent(identity + "/TrustedLists", isDirectory: true)
        return TrustedListsModel(europeanService: try EuropeanTrustCatalogService(directory: directory), directory: directory)
    }
    /// Construction does no disk/network work. Lifecycle work is cancellable and never awaited by signing.
    public var catalogProvider: (any TrustedListCatalogProviding)? {
        guard let europeanService else { return service as? any TrustedListCatalogProviding }
        return EuropeanCatalogProvider(service: europeanService, networkAllowed: { [weak self] in
            await self?.allowsNetwork() ?? false
        }, onUpdate: { [weak self] view in await self?.acceptValidation(view) })
    }
    private func allowsNetwork() -> Bool { !offline }
    public func setOffline(_ value: Bool) {
        guard offline != value else { return }
        stop(); offline = value; start()
    }
    public func start() {
        guard lifecycle == nil else { return }
        if let europeanService { startEuropean(europeanService); return }
        guard let service else { return }
        let token = generation, directory = directory
        lifecycle = Task(priority: .utility) { [weak self] in
            do {
                if let directory {
                    try await Task.detached(priority: .utility) {
                        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                    }.value
                }
                if let cached = try? await service.cached(now: nil), !Task.isCancelled, self?.generation == token { self?.apply(cached) }
                guard !Task.isCancelled, self?.generation == token else { return }
                self?.isRefreshing = true
                await service.runAutomatically { [weak self] result in
                    await self?.receive(result, token: token)
                }
            } catch { self?.receive(.failure(error), token: token) }
        }
    }
    public func checkForUpdates() {
        guard manual == nil else { return }
        if let europeanService { refreshEuropean(europeanService); return }
        guard let service else { return }
        isRefreshing = true
        let token = generation
        manual = Task(priority: .utility) { [weak self] in
            do { self?.receive(.success(try await service.refresh(now: nil, force: true)), token: token) }
            catch { self?.receive(.failure(error), token: token) }
            if self?.generation == token { self?.manual = nil }
        }
    }
    public func stop() {
        generation = UUID()
        lifecycle?.cancel(); lifecycle = nil
        manual?.cancel(); manual = nil; isRefreshing = false
        let service = service
        let european = europeanService
        Task { await service?.cancelRefresh(); await european?.cancelRefresh() }
    }
    private func receive(_ result: Result<TLRefreshView, Error>, token: UUID) {
        guard generation == token else { return }
        isRefreshing = false
        switch result {
        case .success(let view): apply(view)
        case .failure(let error):
            if error is CancellationError { return }
            status = expiresAt.map { $0 <= Date() } == true ? .expired : .error
            message = Self.explanation(error)
        }
    }
    private func apply(_ view: TLRefreshView) {
        lastVerifiedUpdate = view.lastVerifiedUpdate; expiresAt = view.expiresAt
        providerCount = view.providerCount; serviceCount = view.serviceCount
        status = view.freshness == .expired ? .expired : .current
        message = view.warning == nil ? nil : "Aggiornamento non riuscito. È conservato l’ultimo elenco verificato. Riprova quando la rete è disponibile."
    }
    private func acceptValidation(_ view: EuropeanCatalogView) async { await accept(view, token: generation) }
    private func startEuropean(_ european: EuropeanTrustCatalogService) {
        let token = generation, now = clock(), offline = offline
        lifecycle = Task(priority: .utility) { [weak self] in
            do { await self?.accept(try await european.cached(now: now), token: token) }
            catch { if offline { self?.receive(.failure(error), token: token) } }
            guard !Task.isCancelled, self?.generation == token, !offline else { return }
            self?.isRefreshing = true
            await european.runAutomatically { [weak self] result in
                switch result {
                case .success(let view): await self?.accept(view, token: token)
                case .failure(let error): await self?.receive(.failure(error), token: token)
                }
            }
        }
    }
    private func refreshEuropean(_ european: EuropeanTrustCatalogService) {
        isRefreshing = true
        let token = generation, selected = selectedCountry, now = clock(), offline = offline
        manual = Task(priority: .utility) { [weak self] in
            do {
                let view: EuropeanCatalogView
                if offline { view = try await european.cached(now: now) }
                else { view = try await european.refresh(countries: [selected], now: now, force: true) }
                await self?.accept(view, token: token)
            } catch { self?.receive(.failure(error), token: token) }
            if self?.generation == token { self?.manual = nil; self?.isRefreshing = false }
        }
    }
    private func accept(_ incoming: EuropeanCatalogView, token: UUID) async {
        // A selective refresh returns a subset. Reauthenticate all installed caches
        // for Settings; this never acquires additional countries.
        let view = (try? await europeanService?.cached(now: clock())) ?? incoming
        let warnings = view.warnings.merging(incoming.warnings, uniquingKeysWith: { _, new in new })
        let directory = directory
        let present = await Task.detached(priority: .utility) {
            guard let directory else { return view.selectedCountries.sorted() }
            return EUTrustPolicy.countries.filter {
                FileManager.default.fileExists(atPath: directory.appendingPathComponent($0 + ".json").path)
            }.sorted()
        }.value
        guard generation == token, !Task.isCancelled else { return }
        availableCountries = view.availableCountries.sorted(); acquiredCountries = present
        countryExpiries = view.catalogs.mapValues { $0.document.nextUpdate }
        countryWarnings = warnings
        lastVerifiedUpdate = view.refreshedAt
        let dates = Array(countryExpiries.values) + (view.europe.map { [$0.document.nextUpdate] } ?? [])
        expiresAt = dates.min()
        providerCount = view.catalogs.values.reduce(0) { $0 + $1.usableProviders.count }
        serviceCount = view.catalogs.values.reduce(0) { $0 + $1.usableServiceCount }
        status = warnings.values.contains(where: { $0.contains("expired") }) ? .expired : view.europe == nil ? .unavailable : .current
        message = warnings.isEmpty ? nil : "Alcuni elenchi non sono disponibili o aggiornabili. Le cache precedenti sono conservate, ma vengono usate solo se ancora autentiche e valide."
        isRefreshing = false
    }
    public static func explanation(_ error: Error) -> String {
        if error is URLError { return "Impossibile raggiungere gli elenchi fiduciari. Controlla la connessione e riprova." }
        if error is TLAuthenticationError { return "Gli elenchi ricevuti o la cache non superano i controlli di autenticità e validità. Nessun nuovo elenco è stato accettato." }
        return "Elenchi fiduciari non disponibili. Verifica la connessione e l’accesso ai dati dell’app, poi riprova."
    }
}
