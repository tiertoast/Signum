import Foundation
import SignumTrustCore

public struct EuropeanCatalogView: Sendable {
    public let europe: InterpretedTrustCatalog?
    public let availableCountries: Set<String>
    public let catalogs: [String: InterpretedTrustCatalog]
    public let warnings: [String: String]
    public let refreshedAt: Date?
    public var selectedCountries: Set<String> { Set(catalogs.keys) }
}
private struct EuropeanJournal: Codable, Sendable {
    let lotl: Data
    let pivots: [LOTLPivotChain.Pivot]
    let refreshedAt: Date
}
private struct VerifiedEuropeanJournal: Sendable {
    let raw: EuropeanJournal
    let catalog: InterpretedTrustCatalog
}

/// One caller-owned coordinator; no daemon, no country fetch without selection.
/// National envelopes retain A/E1's authentication, stable flock and atomic rename.
public actor EuropeanTrustCatalogService {
    private let directory: URL
    private let transport: any TLTransport
    private let anchors: Set<Data>
    private let interval: TimeInterval
    private var inFlight: (UUID, Set<String>, Task<EuropeanCatalogView, Error>)?
    private let maximumDiskBytes = 512 * 1024 * 1024
    public init(directory: URL, transport: any TLTransport = TLHTTPSClient(), refreshInterval: TimeInterval = 6*3600) throws {
        guard refreshInterval >= 60, refreshInterval <= 24*3600, refreshInterval.isFinite else { throw TLRefreshFailure.invalidInterval }
        self.directory = directory; self.transport = transport; interval = refreshInterval; anchors = EUTrustPolicy.journalAnchors
    }
    init(directory: URL, transport: any TLTransport, anchors: Set<Data>, interval: TimeInterval = 6*3600) {
        self.directory = directory; self.transport = transport; self.anchors = anchors; self.interval = interval
    }
    private var journalURL: URL { directory.appendingPathComponent("europe.json") }
    private var lockURL: URL { directory.appendingPathComponent("catalog") }
    private func nationalURL(_ country: String) -> URL { directory.appendingPathComponent(country+".json") }
    private func cachedCountries() -> Set<String> {
        Set(EUTrustPolicy.countries.filter { FileManager.default.fileExists(atPath:nationalURL($0).path) })
    }
    private func readJournal(now: Date) throws -> VerifiedEuropeanJournal? {
        guard FileManager.default.fileExists(atPath:journalURL.path) else {
            guard cachedCountries().isEmpty else { throw TLAuthenticationError.rejected("shared LOTL continuity state missing") }
            return nil
        }
        let handle = try FileHandle(forReadingFrom:journalURL); defer { try? handle.close() }
        let bytes = try handle.read(upToCount:TLSnapshot.maximumEnvelopeBytes+1) ?? Data()
        guard bytes.count <= TLSnapshot.maximumEnvelopeBytes else { throw TLAuthenticationError.rejected("shared LOTL cache bounds") }
        let raw = try JSONDecoder().decode(EuropeanJournal.self,from:bytes)
        guard raw.pivots.count <= 16, raw.lotl.count + raw.pivots.reduce(0,{ $0+$1.xml.count }) <= 64*1024*1024 else { throw TLRefreshFailure.downloadTooLarge }
        let metadata = try UntrustedTLParser.parse(raw.lotl)
        guard metadata.issuedAt <= now.addingTimeInterval(300) else { throw TLAuthenticationError.rejected("future shared LOTL") }
        let at = metadata.nextUpdate <= now ? metadata.issuedAt : now
        let catalog = try LOTLPivotChain.validate(current:raw.lotl,pivotsOldestFirst:raw.pivots,now:at,initialAnchors:anchors)
        return .init(raw:raw,catalog:catalog)
    }
    private func quota(replacing url: URL, bytes: Int) throws {
        let urls = [journalURL] + EUTrustPolicy.countries.map(nationalURL)
        var total = bytes
        for file in urls where file != url && FileManager.default.fileExists(atPath:file.path) {
            let size = try FileManager.default.attributesOfItem(atPath:file.path)[.size] as? NSNumber
            guard let size else { throw TLAuthenticationError.rejected("cache quota metadata unavailable") }
            total += size.intValue
            guard total <= maximumDiskBytes else { throw TLAuthenticationError.rejected("European cache quota reached; continuity retained") }
        }
        guard total <= maximumDiskBytes else { throw TLRefreshFailure.downloadTooLarge }
    }
    private func current(_ value: VerifiedEuropeanJournal, now: Date) -> Bool {
        value.catalog.interpretationState != .blocked && value.catalog.document.issuedAt <= now && value.catalog.document.nextUpdate > now
    }
    public func cached(countries: Set<String> = [], now: Date = Date()) throws -> EuropeanCatalogView {
        guard countries.isSubset(of:EUTrustPolicy.countries) else { throw TLAuthenticationError.rejected("unsupported territory selection") }
        guard let journal = try readJournal(now:now) else { throw TLRefreshFailure.noAuthenticatedCache }
        let wanted = countries.isEmpty ? cachedCountries() : countries
        let live = current(journal,now:now)
        let available = live ? Set(EUTrustPolicy.countries.filter { (try? TLAuthenticator.nationalPointer(country:$0,lotl:journal.catalog,now:now)) != nil }) : []
        var catalogs = [String:InterpretedTrustCatalog](), warnings = [String:String]()
        for country in wanted.sorted() {
            do {
                guard live, available.contains(country) else { throw TLAuthenticationError.rejected("LOTL expired, blocked or national pointer unavailable") }
                let old = try TLSnapshot.readVerified(nationalURL(country),now:now,anchors:anchors)
                guard old.bundle.country == country else { throw TLAuthenticationError.rejected("national cache territory mismatch") }
                if case .rejected(let reason) = TLContinuityPolicy.assess(previous:old.europe.revision,candidate:journal.catalog.revision,now:now) { throw TLAuthenticationError.rejected(String(describing:reason)) }
                let national = old.europe.revision.xmlSHA256 == journal.catalog.revision.xmlSHA256 ? old.italy :
                    try TLAuthenticator.authenticateNational(old.bundle.italy,country:country,lotl:journal.catalog,now:now)
                guard national.document.issuedAt <= now, national.document.nextUpdate > now,
                      national.interpretationState != .blocked else { throw TLAuthenticationError.rejected("national list expired or interpretation blocked") }
                catalogs[country] = national
            } catch { warnings[country] = String(describing:error) }
        }
        if !live { warnings["EU"] = "Shared authenticated LOTL is expired or blocked; no current catalogs" }
        return .init(europe:live ? journal.catalog : nil,availableCountries:available,catalogs:catalogs,warnings:warnings,refreshedAt:journal.raw.refreshedAt)
    }
    public func refresh(countries: Set<String> = [], now: Date = Date(), force: Bool = false) async throws -> EuropeanCatalogView {
        guard countries.isSubset(of:EUTrustPolicy.countries) else { throw TLAuthenticationError.rejected("unsupported territory selection") }
        let wanted = countries.isEmpty ? cachedCountries() : countries
        if let (id,selection,task) = inFlight {
            let completed = try await withTaskCancellationHandler(operation:{ try await task.value },onCancel:{ task.cancel() })
            if wanted.isSubset(of:selection) { return completed }
            if inFlight?.0 == id { inFlight = nil }
            return try await refresh(countries:countries,now:now,force:false)
        }
        let id = UUID(), task = Task { try await self.perform(countries:countries,now:now,force:force) }
        inFlight = (id,wanted,task); defer { if inFlight?.0 == id { inFlight = nil } }
        return try await withTaskCancellationHandler(operation:{ try await task.value },onCancel:{ task.cancel() })
    }
    public func cancelRefresh() { inFlight?.2.cancel() }
    private func perform(countries: Set<String>, now: Date, force: Bool) async throws -> EuropeanCatalogView {
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let started = ProcessInfo.processInfo.systemUptime
        let clock: @Sendable () -> Date = { now.addingTimeInterval(ProcessInfo.processInfo.systemUptime-started) }
        let previous = try readJournal(now:clock()) // Corruption must never reset continuity.
        let wanted = countries.isEmpty ? cachedCountries() : countries
        var failures = [String:String]()
        var usable = previous
        let due = previous.map { !current($0,now:clock()) || clock().timeIntervalSince($0.raw.refreshedAt) >= interval || $0.catalog.document.nextUpdate.timeIntervalSince(clock()) < interval } ?? true
        if force || due {
            do {
                try Task.checkCancellation()
                let lotl = try await transport.fetch(URL(string:EUTrustPolicy.location)!)
                let urls = try LOTLPivotChain.discoveryURLs(in:lotl)
                guard urls.count <= 16 else { throw TLRefreshFailure.downloadTooLarge }
                var pivots = [LOTLPivotChain.Pivot](), size = lotl.count
                for url in urls {
                    try Task.checkCancellation()
                    guard LOTLPivotChain.allowedPivotURL(url) else { throw TLRefreshFailure.unauthorizedURL }
                    let bytes: Data
                    if let cached = previous?.raw.pivots.first(where:{ $0.location == url }) { bytes = cached.xml }
                    else { bytes = try await transport.fetch(URL(string:url)!) }
                    size += bytes.count; guard size <= 64*1024*1024 else { throw TLRefreshFailure.downloadTooLarge }
                    pivots.append(.init(location:url,xml:bytes))
                }
                let candidate = try LOTLPivotChain.validate(current:lotl,pivotsOldestFirst:pivots,now:clock(),previous:previous?.catalog,initialAnchors:anchors)
                guard candidate.interpretationState != .blocked else { throw TLAuthenticationError.rejected("LOTL interpretation blocked") }
                let raw = EuropeanJournal(lotl:lotl,pivots:pivots,refreshedAt:clock())
                try TLSnapshot.withExclusiveLock(lockURL) {
                    if let latest = try readJournal(now:clock()) {
                        if case .rejected(let reason) = TLContinuityPolicy.assess(previous:latest.catalog.revision,candidate:candidate.revision,now:clock()) { throw TLAuthenticationError.rejected(String(describing:reason)) }
                        guard Array(pivots.prefix(latest.raw.pivots.count).map(\.location)) == latest.raw.pivots.map(\.location) else { throw TLAuthenticationError.rejected("shared pivot history rollback") }
                    }
                    try Task.checkCancellation()
                    guard candidate.document.nextUpdate > clock() else { throw TLAuthenticationError.rejected("LOTL expired at commit") }
                    let bytes = try JSONEncoder().encode(raw);try quota(replacing:journalURL,bytes:bytes.count)
                    try bytes.write(to:journalURL,options:.atomic)
                }
                usable = try readJournal(now:clock())
            } catch is CancellationError { throw CancellationError() }
            catch { failures["EU"] = String(describing:error); usable = try readJournal(now:clock()) }
        }
        guard let shared = usable, current(shared,now:clock()) else {
            if previous != nil { return try cached(countries:wanted,now:clock()) }
            throw TLRefreshFailure.noAuthenticatedCache
        }
        var downloads = 0, bytesDownloaded = 0
        for country in wanted.sorted() {
            do {
                try Task.checkCancellation()
                let file = nationalURL(country)
                let old = FileManager.default.fileExists(atPath:file.path) ? try TLSnapshot.readVerified(file,now:clock(),anchors:anchors) : nil
                guard old == nil || old?.bundle.country == country else { throw TLAuthenticationError.rejected("national cache territory mismatch") }
                if !force, let old, !old.expired, let date = old.bundle.refreshedAt, date <= clock(), clock().timeIntervalSince(date) < interval,
                   old.europe.revision.xmlSHA256 == shared.catalog.revision.xmlSHA256,
                   old.italy.document.nextUpdate.timeIntervalSince(clock()) > interval { continue }
                guard downloads < 4 else { throw TLAuthenticationError.rejected("selective refresh budget (4 national downloads)") }
                downloads += 1
                let xml = try await transport.fetchNational(country:country,lotl:shared.catalog,now:clock())
                bytesDownloaded += xml.count;guard bytesDownloaded <= 128*1024*1024 else { throw TLRefreshFailure.downloadTooLarge }
                try TLSnapshot.withExclusiveLock(lockURL) {
                    guard let latest = try readJournal(now:clock()), current(latest,now:clock()) else { throw TLRefreshFailure.noAuthenticatedCache }
                    _ = try TLAuthenticator.authenticateNational(xml,country:country,lotl:latest.catalog,now:clock(),previous:old?.italy)
                    let bundle = TLBundle(lotl:latest.raw.lotl,italy:xml,pivots:latest.raw.pivots,refreshedAt:clock(),country:country)
                    try quota(replacing:file,bytes:JSONEncoder().encode(bundle).count)
                    try Task.checkCancellation()
                    try TLSnapshot.save(bundle,to:file,now:clock(),anchors:anchors,currentTime:clock)
                }
            } catch is CancellationError { throw CancellationError() }
            catch { failures[country] = String(describing:error) }
        }
        let view = try cached(countries:wanted,now:clock())
        return .init(europe:view.europe,availableCountries:view.availableCountries,catalogs:view.catalogs,
            warnings:view.warnings.merging(failures,uniquingKeysWith:{ _,new in new }),refreshedAt:view.refreshedAt)
    }
    public func runAutomatically(onUpdate: @Sendable (Result<EuropeanCatalogView,Error>) async -> Void) async {
        while !Task.isCancelled {
            var delay = min(interval,300)
            do {
                let view = try await refresh()
                await onUpdate(.success(view))
                if view.warnings.isEmpty {
                    let expiries = view.catalogs.values.map { $0.document.nextUpdate } + (view.europe.map { [$0.document.nextUpdate] } ?? [])
                    delay = max(60,min(interval,(expiries.min() ?? Date().addingTimeInterval(interval)).timeIntervalSinceNow-300))
                }
            } catch is CancellationError { return }
            catch { await onUpdate(.failure(error)) }
            do { try await Task.sleep(nanoseconds:UInt64(delay*1_000_000_000)) } catch { return }
        }
    }
}
