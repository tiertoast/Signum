import Foundation
import Combine
import SignumTrustAuthentication

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

@MainActor public final class TrustedListsModel: ObservableObject {
    public enum Status: String { case current = "Aggiornati", expired = "Obsoleti", unavailable = "Non disponibili", error = "Errore" }
    @Published public private(set) var status: Status = .unavailable
    @Published public private(set) var lastVerifiedUpdate: Date?
    @Published public private(set) var expiresAt: Date?
    @Published public private(set) var providerCount = 0
    @Published public private(set) var serviceCount = 0
    @Published public private(set) var message: String?
    @Published public private(set) var isRefreshing = false
    private let service: any TrustedListsRefreshing
    private let directory: URL?
    private var lifecycle: Task<Void, Never>?
    private var manual: Task<Void, Never>?
    private var generation = UUID()
    public init(service: any TrustedListsRefreshing, directory: URL? = nil) {
        self.service = service; self.directory = directory
    }
    public static func developmentPreview() throws -> TrustedListsModel {
        let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
            .appendingPathComponent("io.github.tiertoast.Signum.DevelopmentPreview/TrustedLists", isDirectory: true)
        return TrustedListsModel(service: try TLRefreshService(cacheURL: directory.appendingPathComponent("verified.json")), directory: directory)
    }
    /// Construction does no disk/network work. Lifecycle work is cancellable and never awaited by signing.
    public func start() {
        guard lifecycle == nil else { return }
        let token = generation, service = service, directory = directory
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
        isRefreshing = true
        let token = generation, service = service
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
        Task { await service.cancelRefresh() }
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
    public static func explanation(_ error: Error) -> String {
        if error is URLError { return "Impossibile raggiungere gli elenchi fiduciari. Controlla la connessione e riprova." }
        if error is TLAuthenticationError { return "Gli elenchi ricevuti o la cache non superano i controlli di autenticità e validità. Nessun nuovo elenco è stato accettato." }
        return "Elenchi fiduciari non disponibili. Verifica la connessione e l’accesso ai dati dell’app, poi riprova."
    }
}
