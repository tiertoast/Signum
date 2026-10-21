import XCTest
import Darwin
@testable import SignumTrustAuthentication

private actor FixtureTransport: TLTransport {
    var documents: [String: Data]
    var requests: [String] = []
    var fail = false
    var delay: UInt64 = 0
    var onItaly: (@Sendable () -> Void)?
    func whenItaly(_ action: @escaping @Sendable () -> Void) { onItaly = action }
    init(_ documents: [String: Data]) { self.documents = documents }
    func configure(fail: Bool = false, delay: UInt64 = 0) { self.fail = fail; self.delay = delay }
    func set(_ url: String, _ data: Data) { documents[url] = data }
    func fetch(_ url: URL) async throws -> Data {
        requests.append(url.absoluteString)
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        if fail { throw URLError(.notConnectedToInternet) }
        guard let data = documents[url.absoluteString] else { throw URLError(.resourceUnavailable) }
        if url.absoluteString == EUTrustPolicy.italyLocation { onItaly?() }
        return data
    }
}

private final class RefreshClock: @unchecked Sendable {
    private let lock = NSLock()
    private var time: Date
    init(_ time: Date) { self.time = time }
    func read() -> Date { lock.lock(); defer { lock.unlock() }; return time }
    func advance() { lock.lock(); time = time.addingTimeInterval(10); lock.unlock() }
}

final class RefreshTests: XCTestCase {
    let now = ISO8601DateFormatter().date(from: "2026-10-20T12:00:00Z")!
    let pivot1 = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-401.xml"
    let pivot2 = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-403.xml"
    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")))
    }
    func cache() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: dir) }
        return dir.appendingPathComponent("verified.json")
    }
    private func transport() throws -> FixtureTransport {
        FixtureTransport([EUTrustPolicy.location: try fixture("eu-lotl.xml"), EUTrustPolicy.italyLocation: try fixture("it.xml")])
    }
    func testAutomaticDuePolicyAndForcedRefresh() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        let first = try await service.refresh(now: now)
        XCTAssertEqual(first.source, .network); XCTAssertEqual(first.freshness, .current)
        XCTAssertEqual(TLRefreshService.automaticDelay(view: first, now: first.expiresAt.addingTimeInterval(-360), interval: 21600), 60)
        XCTAssertEqual(TLRefreshService.automaticDelay(view: nil, now: now, interval: 21600), 300)
        let second = try await service.refresh(now: now.addingTimeInterval(60))
        XCTAssertEqual(second.source, .cache)
        let afterCache = await network.requests; XCTAssertEqual(afterCache.count, 2)
        _ = try await service.refresh(now: now.addingTimeInterval(6 * 3600))
        let afterDue = await network.requests; XCTAssertEqual(afterDue.count, 4)
        _ = try await service.refresh(now: now.addingTimeInterval(6 * 3600 + 1), force: true)
        let afterForce = await network.requests; XCTAssertEqual(afterForce.count, 6)
    }
    func testOfflineCurrentAndExpiredNeverExposeCurrentRecords() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        _ = try await service.refresh(now: now)
        let bytes = try Data(contentsOf: url)
        await network.configure(fail: true)
        let offline = try await service.refresh(now: now, force: true)
        XCTAssertEqual(offline.source, .cache); XCTAssertEqual(offline.freshness, .current)
        XCTAssertNotNil(offline.warning); XCTAssertNotNil(offline.currentItaly)
        let stale = try await service.refresh(now: now.addingTimeInterval(365 * 86400), force: true)
        XCTAssertEqual(stale.freshness, .expired); XCTAssertNil(stale.currentItaly); XCTAssertNil(stale.currentEurope)
        XCTAssertEqual(try Data(contentsOf: url), bytes)
        XCTAssertThrowsError(try TLSnapshot.load(from: url, now: now.addingTimeInterval(365 * 86400)))
    }
    func testNoCacheOfflineFailsAndUnauthenticatedLOTLNeverFetchesItaly() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        await network.configure(fail: true)
        do { _ = try await service.refresh(now: now); XCTFail("offline bootstrap accepted") } catch {}
        await network.configure()
        await network.set(EUTrustPolicy.location, Data("invalid".utf8))
        do { _ = try await service.refresh(now: now); XCTFail("invalid bootstrap accepted") } catch {}
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        let requests = await network.requests
        XCTAssertTrue(requests.allSatisfy { $0 == EUTrustPolicy.location })
    }
    func testInvalidItalyPreservesLastGoodSnapshotAndReportsFailure() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        _ = try await service.refresh(now: now)
        let bytes = try Data(contentsOf: url)
        await network.set(EUTrustPolicy.italyLocation, Data("tampered".utf8))
        let result = try await service.refresh(now: now, force: true)
        XCTAssertEqual(result.italySequence, 224); XCTAssertNotNil(result.warning)
        XCTAssertEqual(try Data(contentsOf: url), bytes)
    }
    func testTwoOfficialStyleSelfReferencingPivotsPersistAndReloadOffline() async throws {
        let url = try cache()
        let network = FixtureTransport([
            EUTrustPolicy.location: try fixture("synthetic-c.xml"), EUTrustPolicy.italyLocation: try fixture("synthetic-it.xml"),
            pivot1: try fixture("synthetic-pivot.xml"), pivot2: try fixture("synthetic-pivot2.xml")])
        let anchors: Set<Data> = [TLAuthenticator.sha256(try fixture("test-a.der"))]
        let service = TLRefreshService(cacheURL: url, transport: network, anchors: anchors)
        let result = try await service.refresh(now: now)
        XCTAssertEqual(result.europeSequence, 404); XCTAssertEqual(result.freshness, .current)
        let requests = await network.requests
        XCTAssertEqual(requests, [EUTrustPolicy.location, pivot1, pivot2, EUTrustPolicy.italyLocation])
        let restarted = TLRefreshService(cacheURL: url, transport: network, anchors: anchors)
        let loaded = try await restarted.cached(now: now)
        XCTAssertEqual(loaded.europeSequence, 404)
        await network.configure(fail: true)
        let offline = try await restarted.refresh(now: now, force: true)
        XCTAssertEqual(offline.europeSequence, 404); XCTAssertNotNil(offline.warning)
        let envelope = try JSONDecoder().decode(TLBundle.self, from: Data(contentsOf: url))
        XCTAssertEqual(envelope.pivots.map(\.location), [pivot1, pivot2])
    }
    func testAuthenticatedRollbackAndMissingPivotPreserveBytes() async throws {
        let url = try cache()
        let network = FixtureTransport([EUTrustPolicy.location: try fixture("synthetic-b.xml"), EUTrustPolicy.italyLocation: try fixture("synthetic-it-new.xml"), pivot1: try fixture("synthetic-pivot.xml")])
        let anchors: Set<Data> = [TLAuthenticator.sha256(try fixture("test-a.der"))]
        let service = TLRefreshService(cacheURL: url, transport: network, anchors: anchors)
        _ = try await service.refresh(now: now)
        let bytes = try Data(contentsOf: url)
        await network.set(EUTrustPolicy.location, try fixture("synthetic-a.xml"))
        let rollback = try await service.refresh(now: now, force: true)
        XCTAssertEqual(rollback.europeSequence, 402); XCTAssertNotNil(rollback.warning)
        XCTAssertEqual(try Data(contentsOf: url), bytes)
        await network.set(EUTrustPolicy.location, try fixture("synthetic-b.xml"))
        await network.set(EUTrustPolicy.italyLocation, try fixture("synthetic-it.xml"))
        let nationalRollback = try await service.refresh(now: now, force: true)
        XCTAssertNotNil(nationalRollback.warning); XCTAssertEqual(try Data(contentsOf: url), bytes)
        let empty = try cache()
        let missing = FixtureTransport([EUTrustPolicy.location: try fixture("synthetic-b.xml")])
        let noPivot = TLRefreshService(cacheURL: empty, transport: missing, anchors: anchors)
        do { _ = try await noPivot.refresh(now: now); XCTFail("missing pivot accepted") } catch {}
        let requests = await missing.requests; XCTAssertFalse(requests.contains(EUTrustPolicy.italyLocation))
    }
    func testConcurrentRequestsCoalesceAndCancellationDoesNotCommit() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        await network.configure(delay: 30_000_000)
        async let first = service.refresh(now: now, force: true)
        async let second = service.refresh(now: now, force: true)
        _ = try await (first, second)
        let requests = await network.requests; XCTAssertEqual(requests.count, 2)
        let bytes = try Data(contentsOf: url)
        await network.configure(delay: 5_000_000_000)
        let work = Task { try await service.refresh(now: now, force: true) }
        try await Task.sleep(nanoseconds: 30_000_000)
        work.cancel()
        do { _ = try await work.value; XCTFail("cancellation ignored") } catch is CancellationError {} catch { XCTFail("unexpected error: \(error)") }
        XCTAssertEqual(try Data(contentsOf: url), bytes)
    }
    func testCorruptCacheCannotResetContinuityAndLegacySnapshotLoads() async throws {
        let url = try cache(), network = try transport()
        let legacy = try JSONSerialization.data(withJSONObject: ["lotl": fixture("eu-lotl.xml").base64EncodedString(), "italy": fixture("it.xml").base64EncodedString()])
        try legacy.write(to: url)
        let service = try TLRefreshService(cacheURL: url, transport: network)
        let result = try await service.cached(now: now); XCTAssertEqual(result.italySequence, 224)
        try Data("corrupt".utf8).write(to: url)
        do { _ = try await service.refresh(now: now); XCTFail("corrupt state silently reset") } catch {}
        let requests = await network.requests; XCTAssertTrue(requests.isEmpty)
    }
    func testCompetingWriterPreservesSnapshot() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        _ = try await service.refresh(now: now)
        let before = try Data(contentsOf: url)
        let fd = open(url.path + ".lock", O_RDWR)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = flock(fd, LOCK_UN); close(fd) }
        XCTAssertEqual(flock(fd, LOCK_EX | LOCK_NB), 0)
        let result = try await service.refresh(now: now, force: true)
        XCTAssertTrue(result.warning?.contains("writer busy") == true)
        XCTAssertEqual(try Data(contentsOf: url), before)
    }
    func testAutomaticLoopPublishesThenStopsOnCancellation() async throws {
        let url = try cache(), network = try transport()
        let service = try TLRefreshService(cacheURL: url, transport: network)
        let delivered = expectation(description: "automatic refresh result")
        let monitor = Task {
            await service.runAutomatically { result in
                if case .failure(let error) = result { XCTFail("automatic refresh failed: \(error)") }
                delivered.fulfill()
            }
        }
        await fulfillment(of: [delivered], timeout: 120)
        monitor.cancel()
        await monitor.value
        let requests = await network.requests; XCTAssertEqual(requests.count, 2)
    }
    func testExpiryDuringDownloadCannotCommitOrReturnCurrentData() async throws {
        let url = try cache(), network = try transport()
        try TLSnapshot.save(lotl: fixture("eu-lotl.xml"), italy: fixture("it.xml"), to: url, now: now)
        let before = try Data(contentsOf: url)
        let clock = RefreshClock(ISO8601DateFormatter().date(from: "2027-03-24T08:16:55Z")!)
        await network.whenItaly { clock.advance() }
        let service = TLRefreshService(cacheURL: url, transport: network, anchors: EUTrustPolicy.journalAnchors, clock: { clock.read() })
        let result = try await service.refresh(force: true)
        XCTAssertEqual(result.freshness, .expired)
        XCTAssertNil(result.currentItaly); XCTAssertNil(result.currentEurope); XCTAssertNotNil(result.warning)
        XCTAssertEqual(try Data(contentsOf: url), before)
    }
    func testExpiryAtAtomicCommitDoesNotPublish() throws {
        let url = try cache()
        let before = ISO8601DateFormatter().date(from: "2027-03-24T08:16:55Z")!
        let after = before.addingTimeInterval(10)
        let bundle = TLBundle(lotl: try fixture("eu-lotl.xml"), italy: try fixture("it.xml"))
        XCTAssertThrowsError(try TLSnapshot.save(bundle, to: url, now: before, anchors: EUTrustPolicy.journalAnchors, currentTime: { after })) { error in
            XCTAssertTrue(String(describing: error).contains("no longer current at commit"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }
    func testURLPolicyAndIntervalLimits() throws {
        for url in ["http://ec.europa.eu/tools/lotl/eu-lotl.xml", "https://evil.invalid/tl.xml", "file:///etc/passwd", "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-401.xml?url=evil", "https://ec.europa.eu@evil.invalid/tools/lotl/eu-lotl.xml"] {
            XCTAssertFalse(TLDownloadPolicy.allows(URL(string: url)!))
        }
        XCTAssertThrowsError(try TLRefreshService(cacheURL: cache(), refreshInterval: 0))
        XCTAssertThrowsError(try TLRefreshService(cacheURL: cache(), refreshInterval: .infinity))
    }
}
