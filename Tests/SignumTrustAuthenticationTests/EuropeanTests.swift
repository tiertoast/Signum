import XCTest
@testable import SignumTrustAuthentication

private actor EuropeanTransport: TLTransport {
    let documents: [String: Data]
    var requests: [String] = []
    var offline = false
    init(_ documents: [String: Data]) { self.documents = documents }
    func disconnect() { offline = true }
    func fetch(_ url: URL) async throws -> Data {
        requests.append(url.absoluteString)
        if offline { throw URLError(.notConnectedToInternet) }
        guard let bytes = documents[url.absoluteString] else { throw URLError(.resourceUnavailable) }
        return bytes
    }
}

final class EuropeanTests: XCTestCase {
    let now = ISO8601DateFormatter().date(from: "2026-10-21T06:00:00Z")!
    func bytes(_ name: String, folder: String = "Fixtures") throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: folder)))
    }
    func cache() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        return directory.appendingPathComponent("AT.json")
    }
    func europe() throws -> AuthenticatedTL {
        try LOTLPivotChain.authenticate(current: bytes("eu-lotl.xml"), pivotsOldestFirst: [], now: now)
    }
    func testSignedMachinePointersCoverEUAndEEAWithoutPDFOrUK() throws {
        let eu = try europe()
        XCTAssertEqual(EUTrustPolicy.countries.count, 30)
        for country in EUTrustPolicy.countries {
            let pointer = try TLAuthenticator.nationalPointer(country: country, lotl: eu, now: now)
            XCTAssertEqual(pointer.territory, country)
            XCTAssertEqual(pointer.mimeType, "application/vnd.etsi.tsl+xml")
            XCTAssertFalse(pointer.signingCertificateDERs.isEmpty)
        }
        XCTAssertThrowsError(try TLAuthenticator.nationalPointer(country: "UK", lotl: eu, now: now))
        XCTAssertThrowsError(try TLAuthenticator.nationalPointer(country: "EU", lotl: eu, now: now))
        XCTAssertThrowsError(try TLAuthenticator.nationalPointer(country: "AT", lotl: eu, now: eu.document.nextUpdate))
        XCTAssertFalse(TLDownloadPolicy.allows(URL(string: "https://www.signatur.rtr.at/vertrauensliste.xml")!)) // requires signed-pointer capability
    }
    func testOfficialAustriaAuthenticationAndTampering() throws {
        let eu = try europe(), xml = try bytes("at.xml", folder: "Fixtures/European")
        let at = try TLAuthenticator.authenticateNational(xml, country: "AT", lotl: eu, now: now)
        XCTAssertEqual(at.document.sequenceNumber, 75)
        XCTAssertEqual(at.document.providers.count, 8)
        XCTAssertEqual(at.document.providers.reduce(0) { $0 + $1.services.count }, 100)
        XCTAssertThrowsError(try TLAuthenticator.authenticateNational(xml, country: "IT", lotl: eu, now: now))
        let altered = Data(String(decoding: xml, as: UTF8.self).replacingOccurrences(of: "<TSLSequenceNumber>75</TSLSequenceNumber>", with: "<TSLSequenceNumber>76</TSLSequenceNumber>").utf8)
        XCTAssertNotEqual(altered, xml)
        XCTAssertThrowsError(try TLAuthenticator.authenticateNational(altered, country: "AT", lotl: eu, now: now))
    }
    func testPerCountryAtomicCacheOfflineExpiryAndTerritoryIsolation() async throws {
        let url = try cache(), eu = try europe()
        let pointer = try TLAuthenticator.nationalPointer(country: "AT", lotl: eu, now: now)
        let network = EuropeanTransport([EUTrustPolicy.location: try bytes("eu-lotl.xml"), pointer.location: try bytes("at.xml", folder: "Fixtures/European")])
        let service = try TLRefreshService(cacheURL: url, transport: network, country: "AT")
        let first = try await service.refresh(now: now)
        XCTAssertEqual(first.country, "AT"); XCTAssertEqual(first.nationalSequence, 75)
        XCTAssertEqual(first.currentNational?.document.territory, "AT"); XCTAssertNil(first.currentItaly)
        let requests = await network.requests
        XCTAssertEqual(requests, [EUTrustPolicy.location, pointer.location]) // no other national download
        let saved = try Data(contentsOf: url)
        await network.disconnect()
        let offline = try await service.refresh(now: now, force: true)
        XCTAssertEqual(offline.source, .cache); XCTAssertEqual(offline.freshness, .current)
        XCTAssertNotNil(offline.warning); XCTAssertNotNil(offline.currentNational)
        let expired = try await service.cached(now: first.expiresAt)
        XCTAssertEqual(expired.freshness, .expired); XCTAssertNil(expired.currentNational)
        let wrongCountry = try TLRefreshService(cacheURL: url, transport: network, country: "IT")
        do { _ = try await wrongCountry.cached(now: now); XCTFail("country substitution accepted") } catch {}
        do { _ = try await wrongCountry.refresh(now: now); XCTFail("country substitution committed") } catch {}
        XCTAssertEqual(try Data(contentsOf: url), saved)
    }
}
