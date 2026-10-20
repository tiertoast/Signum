import Foundation

public enum TLCacheFreshness: String, Sendable { case current, expired }
public enum TLRefreshSource: String, Sendable { case network, cache }

/// Stale metadata is explicitly labeled. Only a current view exposes authenticated records.
public struct TLRefreshView: Sendable {
    public let source: TLRefreshSource
    public let freshness: TLCacheFreshness
    public let europeSequence: Int
    public let italySequence: Int
    public let expiresAt: Date
    public let lastVerifiedUpdate: Date?
    public let providerCount: Int
    public let serviceCount: Int
    public let warning: String?
    public let currentEurope: AuthenticatedTL?
    public let currentItaly: AuthenticatedTL?
    init(_ snapshot: VerifiedSnapshot, source: TLRefreshSource, warning: String? = nil, now: Date? = nil) {
        self.source = source; self.warning = warning
        lastVerifiedUpdate = snapshot.bundle.refreshedAt
        providerCount = snapshot.italy.document.providers.count
        serviceCount = snapshot.italy.document.providers.reduce(0) { $0 + $1.services.count }
        let expired = snapshot.expired || (now.map { min(snapshot.europe.document.nextUpdate, snapshot.italy.document.nextUpdate) <= $0 } ?? false)
        freshness = expired ? .expired : .current
        europeSequence = snapshot.europe.document.sequenceNumber; italySequence = snapshot.italy.document.sequenceNumber
        expiresAt = min(snapshot.europe.document.nextUpdate, snapshot.italy.document.nextUpdate)
        currentEurope = expired ? nil : snapshot.europe; currentItaly = expired ? nil : snapshot.italy
    }
}

/// One refresh owner; cross-process commits additionally use TLSnapshot's stable lock.
/// Network work is coalesced even across actor suspension. No failed refresh replaces disk state.
public actor TLRefreshService {
    private let cacheURL: URL
    private let transport: any TLTransport
    private let interval: TimeInterval
    private let anchors: Set<Data>
    private let clock: @Sendable () -> Date
    private var inFlight: Task<TLRefreshView, Error>?
    public init(cacheURL: URL, transport: any TLTransport = TLHTTPSClient(), refreshInterval: TimeInterval = 6 * 3600) throws {
        guard refreshInterval.isFinite, refreshInterval >= 60, refreshInterval <= 24 * 3600 else { throw TLRefreshFailure.invalidInterval }
        self.cacheURL = cacheURL; self.transport = transport; interval = refreshInterval; anchors = EUTrustPolicy.journalAnchors; clock = { Date() }
    }
    // Synthetic test anchors cannot be selected through the production public initializer.
    init(cacheURL: URL, transport: any TLTransport, interval: TimeInterval = 6 * 3600, anchors: Set<Data>, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.cacheURL = cacheURL; self.transport = transport; self.interval = interval; self.anchors = anchors; self.clock = clock
    }
    public func cached(now: Date? = nil) throws -> TLRefreshView {
        TLRefreshView(try TLSnapshot.readVerified(cacheURL, now: now ?? clock(), anchors: anchors), source: .cache, now: now ?? clock())
    }
    public func refresh(now: Date? = nil, force: Bool = false) async throws -> TLRefreshView {
        if let inFlight { return try await withTaskCancellationHandler(operation: { try await inFlight.value }, onCancel: { inFlight.cancel() }) }
        let task = Task { try await self.perform(now: now, force: force) }
        inFlight = task
        defer { inFlight = nil }
        return try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
    }
    public func cancelRefresh() { inFlight?.cancel() }

    private func perform(now reference: Date?, force: Bool) async throws -> TLRefreshView {
        let currentTime: @Sendable () -> Date = { reference ?? self.clock() }
        let now = currentTime()
        let exists = FileManager.default.fileExists(atPath: cacheURL.path)
        // Corrupt local state must not silently reset the rollback high-water mark.
        let previous = exists ? try TLSnapshot.readVerified(cacheURL, now: now, anchors: anchors) : nil
        if !force, let previous, !previous.expired, let refreshed = previous.bundle.refreshedAt,
           refreshed <= now, now.timeIntervalSince(refreshed) < interval,
           min(previous.europe.document.nextUpdate, previous.italy.document.nextUpdate).timeIntervalSince(now) > interval {
            return TLRefreshView(previous, source: .cache, now: currentTime())
        }
        do {
            try Task.checkCancellation()
            let lotl = try await transport.fetch(URL(string: EUTrustPolicy.location)!)
            let urls = try LOTLPivotChain.discoveryURLs(in: lotl)
            guard urls.count <= 16 else { throw TLAuthenticationError.rejected("pivot chain too long") }
            var pivots: [LOTLPivotChain.Pivot] = []
            var total = lotl.count
            for url in urls {
                try Task.checkCancellation()
                guard LOTLPivotChain.allowedPivotURL(url) else { throw TLRefreshFailure.unauthorizedURL }
                let bytes: Data
                if let cached = previous?.bundle.pivots.first(where: { $0.location == url }) {
                    bytes = cached.xml // Reauthenticated as part of the complete chain below.
                } else { bytes = try await transport.fetch(URL(string: url)!) }
                total += bytes.count
                guard total <= 64 * 1024 * 1024 else { throw TLRefreshFailure.downloadTooLarge }
                pivots.append(.init(location: url, xml: bytes))
            }
            let eu = try LOTLPivotChain.validate(current: lotl, pivotsOldestFirst: pivots, now: currentTime(),
                                                previous: previous?.europe, initialAnchors: anchors)
            let pointer = try TLAuthenticator.italyPointer(lotl: eu, now: currentTime())
            try Task.checkCancellation()
            let italy = try await transport.fetch(URL(string: pointer.location)!)
            _ = try TLAuthenticator.authenticateItaly(italy, lotl: eu, now: currentTime(), previous: previous?.italy)
            try Task.checkCancellation()
            let bundle = TLBundle(lotl: lotl, italy: italy, pivots: pivots, refreshedAt: currentTime())
            try TLSnapshot.save(bundle, to: cacheURL, now: currentTime(), anchors: anchors, currentTime: currentTime)
            return TLRefreshView(try TLSnapshot.readVerified(cacheURL, now: currentTime(), anchors: anchors), source: .network, now: currentTime())
        } catch is CancellationError { throw CancellationError() }
        catch {
            try Task.checkCancellation()
            // Re-read disk so another writer's newer accepted snapshot is not hidden.
            if FileManager.default.fileExists(atPath: cacheURL.path) {
                return TLRefreshView(try TLSnapshot.readVerified(cacheURL, now: currentTime(), anchors: anchors), source: .cache, warning: String(describing: error), now: currentTime())
            }
            throw error
        }
    }

    /// Lifecycle owned by the caller; cancellation stops sleeping and active downloads.
    /// No detached task or persistent scheduler is installed. An update is attempted
    /// immediately, then periodically, including retry after network failure.
    static func automaticDelay(view: TLRefreshView?, now: Date, interval: TimeInterval) -> TimeInterval {
        guard let view, view.warning == nil, view.freshness == .current else { return min(interval, 300) }
        return max(60, min(interval, view.expiresAt.timeIntervalSince(now) - 300))
    }
    public func runAutomatically(onUpdate: @Sendable (Result<TLRefreshView, Error>) async -> Void) async {
        while !Task.isCancelled {
            var view: TLRefreshView?
            do { view = try await refresh(); await onUpdate(.success(view!)) }
            catch is CancellationError { return }
            catch { await onUpdate(.failure(error)) }
            let delay = Self.automaticDelay(view: view, now: Date(), interval: interval)
            do { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            catch { cancelRefresh(); return }
        }
    }
}
