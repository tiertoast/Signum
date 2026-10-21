import XCTest
import SignumCore
import SignumTrustCore
@testable import SignumTrustAuthentication
@testable import SignumCertificateValidation

actor E2Transport: TLTransport {
    var documents: [String:Data]
    var requests = [String]()
    var delay: UInt64 = 0
    var offline = false
    init(_ documents: [String:Data]) { self.documents = documents }
    func set(_ url: String,_ bytes: Data) { documents[url] = bytes }
    func configure(offline: Bool = false, delay: UInt64 = 0) { self.offline = offline;self.delay = delay }
    func fetch(_ url: URL) async throws -> Data {
        requests.append(url.absoluteString)
        if delay > 0 { try await Task.sleep(nanoseconds:delay) }
        guard !offline, let bytes = documents[url.absoluteString] else { throw URLError(.notConnectedToInternet) }
        return bytes
    }
}
final class EuropeanCatalogTests: XCTestCase {
    func data(_ name: String,_ ext: String = "xml",folder: String = "E2") throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:ext,subdirectory:"Fixtures/"+folder)))
    }
    func now() throws -> Date {
        let clock = try JSONSerialization.jsonObject(with:data("clock","json",folder:"E1R")) as! [String:String]
        return try XCTUnwrap(ISO8601DateFormatter().date(from:clock["evaluatedAt"]!))
    }
    func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("signum-e2-"+UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at:url) };return url
    }
    func location(_ country: String) -> String { country == "IT" ? EUTrustPolicy.italyLocation : "https://tl.example.test/\(country).xml" }
    func network() throws -> E2Transport {
        var documents = [EUTrustPolicy.location:try data("europe")]
        for c in ["IT","AT","DE","BE","FR","ES","BG"] { documents[location(c)] = try data(c) }
        return E2Transport(documents)
    }
    func coordinator(_ dir: URL,_ network: E2Transport) throws -> EuropeanTrustCatalogService {
        EuropeanTrustCatalogService(directory:dir,transport:network,anchors:[TLAuthenticator.sha256(try data("signer0","der"))])
    }
    func list(_ country: String = "IT",variant: String? = nil) throws -> InterpretedTrustCatalog {
        let eu = try LOTLPivotChain.validate(current:data("europe"),pivotsOldestFirst:[],now:now(),initialAnchors:[TLAuthenticator.sha256(data("signer0","der"))])
        return try TLAuthenticator.authenticateNational(data(variant ?? country),country:country,lotl:eu,now:now())
    }
    func report() throws -> VerificationReport {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        return try SignumVerificationService.verify(data:data("multi","cms",folder:"E1R"),name:"multi.cms",helper:URL(fileURLWithPath:helper))
    }
    func testSharedSelectiveRefreshCoalescingRestartAndOffline() async throws {
        let dir = try directory(), network = try network(), service = try coordinator(dir,network), at = try now()
        await network.configure(delay:10_000_000)
        async let first = service.refresh(countries:["IT"],now:at)
        async let concurrent = service.refresh(countries:["IT"],now:at)
        let pair = try await (first,concurrent)
        XCTAssertEqual(pair.0.selectedCountries,["IT"]);XCTAssertEqual(pair.1.selectedCountries,["IT"])
        let initialRequests = await network.requests;XCTAssertEqual(initialRequests.count,2)
        let second = try await service.refresh(countries:["AT"],now:at.addingTimeInterval(20))
        XCTAssertEqual(second.selectedCountries,["AT"]);XCTAssertTrue(second.availableCountries.contains("BG"))
        let requests = await network.requests;XCTAssertEqual(requests.count,3)
        XCTAssertEqual(requests.filter { $0 == EUTrustPolicy.location }.count,1)
        await network.configure(offline:true)
        let restarted = try coordinator(dir,network)
        let cached = try await restarted.cached(now:at.addingTimeInterval(30))
        XCTAssertEqual(cached.selectedCountries,["IT","AT"])
        let after = await network.requests;XCTAssertEqual(after,requests)
        let expired = try await restarted.cached(now:at.addingTimeInterval(400*86400))
        XCTAssertNil(expired.europe);XCTAssertTrue(expired.catalogs.isEmpty)
    }
    func testPartialFailureNationalKeyRotationAndSharedRollback() async throws {
        let dir = try directory(), network = try network(), service = try coordinator(dir,network), at = try now()
        _ = try await service.refresh(countries:["IT","AT"],now:at)
        let oldAT = try Data(contentsOf:dir.appendingPathComponent("AT.json"))
        await network.set(EUTrustPolicy.location,try data("europe-rotated-national"))
        let partial = try await service.refresh(countries:["IT","AT"],now:at.addingTimeInterval(20),force:true)
        XCTAssertEqual(partial.europe?.document.sequenceNumber,501);XCTAssertNotNil(partial.catalogs["IT"])
        XCTAssertNil(partial.catalogs["AT"]);XCTAssertNotNil(partial.warnings["AT"])
        XCTAssertEqual(try Data(contentsOf:dir.appendingPathComponent("AT.json")),oldAT)
        await network.set(location("AT"),try data("AT-rotated"))
        let rotated = try await service.refresh(countries:["AT"],now:at.addingTimeInterval(40))
        XCTAssertNotNil(rotated.catalogs["AT"])
        let latestAT = try Data(contentsOf:dir.appendingPathComponent("AT.json")), latestEU = try Data(contentsOf:dir.appendingPathComponent("europe.json"))
        await network.set(location("AT"),try data("AT-rotated-old"))
        let rollback = try await service.refresh(countries:["AT"],now:at.addingTimeInterval(60),force:true)
        XCTAssertNotNil(rollback.warnings["AT"]);XCTAssertEqual(try Data(contentsOf:dir.appendingPathComponent("AT.json")),latestAT)
        // Same sequence/digest LOTL refresh may update only its metadata; capture after that refresh.
        let beforeRollbackEU = try Data(contentsOf:dir.appendingPathComponent("europe.json"))
        await network.set(EUTrustPolicy.location,try data("europe"))
        let euRollback = try await service.refresh(countries:["AT"],now:at.addingTimeInterval(80),force:true)
        XCTAssertEqual(euRollback.europe?.document.sequenceNumber,501);XCTAssertNotNil(euRollback.warnings["EU"])
        XCTAssertEqual(try Data(contentsOf:dir.appendingPathComponent("europe.json")),beforeRollbackEU)
        XCTAssertFalse(latestEU.isEmpty)
    }
    func testSharedOfficialStylePivotRotationAndMissingPivotFailClosed() async throws {
        let fixture = URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("SignumTrustAuthenticationTests/Fixtures")
        func bytes(_ name: String) throws -> Data { try Data(contentsOf:fixture.appendingPathComponent(name)) }
        let p1 = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-401.xml", p2 = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-403.xml"
        let anchors: Set<Data> = [TLAuthenticator.sha256(try bytes("test-a.der"))]
        let net = E2Transport([EUTrustPolicy.location:try bytes("synthetic-c.xml"),EUTrustPolicy.italyLocation:try bytes("synthetic-it.xml"),p1:try bytes("synthetic-pivot.xml"),p2:try bytes("synthetic-pivot2.xml")])
        let dir = try directory(), at = ISO8601DateFormatter().date(from:"2026-10-20T12:00:00Z")!
        let service = EuropeanTrustCatalogService(directory:dir,transport:net,anchors:anchors)
        let value = try await service.refresh(countries:["IT"],now:at)
        XCTAssertEqual(value.europe?.document.sequenceNumber,404);XCTAssertNotNil(value.catalogs["IT"])
        let restarted = EuropeanTrustCatalogService(directory:dir,transport:net,anchors:anchors)
        let cached = try await restarted.cached(now:at);XCTAssertEqual(cached.europe?.source.pivotReferences.count,2)
        let bad = E2Transport([EUTrustPolicy.location:try bytes("synthetic-c.xml")])
        let unavailable = EuropeanTrustCatalogService(directory:try directory(),transport:bad,anchors:anchors)
        do { _ = try await unavailable.refresh(countries:["IT"],now:at);XCTFail("missing pivot accepted") } catch {}
        let requests = await bad.requests;XCTAssertFalse(requests.contains(EUTrustPolicy.italyLocation))
    }
    func testSelectiveBudgetCancellationAndCorruptContinuityNeverReset() async throws {
        let dir = try directory(), net = try network(), service = try coordinator(dir,net), at = try now()
        let view = try await service.refresh(countries:["IT","AT","DE","BE","FR","ES","BG"],now:at)
        let requests = await net.requests;XCTAssertEqual(requests.count,5);XCTAssertEqual(view.catalogs.count,4)
        XCTAssertTrue(view.warnings.values.contains { $0.contains("budget") })
        try Data("corrupt".utf8).write(to:dir.appendingPathComponent("europe.json"))
        do { _ = try await service.refresh(countries:["IT"],now:at,force:true);XCTFail("corrupt journal reset") } catch {}
        let after = await net.requests;XCTAssertEqual(requests,after)
        let cancelledDir = try directory(), delayed = try network(), cancelService = try coordinator(cancelledDir,delayed)
        await delayed.configure(delay:500_000_000)
        let task = Task { try await cancelService.refresh(countries:["IT"],now:at) }
        try await Task.sleep(nanoseconds:20_000_000);task.cancel()
        do { _ = try await task.value;XCTFail("cancelled refresh succeeded") } catch {}
        XCTAssertFalse(FileManager.default.fileExists(atPath:cancelledDir.appendingPathComponent("IT.json").path))
    }
    func testSixCountryDirectCAQCProfilesOfflineAndUncoveredCountry() async throws {
        let report = try report()
        for country in ["IT","AT","DE","BE","FR","ES","BG"] {
            let catalog = try list(country)
            let results = await SignatureQualificationService().validate(report,authenticatedLists:[catalog],mode:.offline,observedAt:try now())
            let q = try XCTUnwrap(results.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(q.qualification.state,country == "BG" ? .indeterminate : .qualified,q.qualification.reason)
            XCTAssertEqual(q.evidence.time.state,.proven);XCTAssertEqual(q.evidence.revocation.state,.good)
            XCTAssertEqual(q.path.state,.verified)
            let lotlDigest = TLAuthenticator.sha256(try data("europe"))
            XCTAssertTrue(catalog.source.authorizingReferences.contains {
                $0.location == EUTrustPolicy.location && $0.xmlSHA256 == lotlDigest
            })
        }
    }
    func testSameIdentityAcrossCountriesNeverChoosesByLabelAndCatalogBridgeIsOffline() async throws {
        let dir = try directory(), net = try network(), service = try coordinator(dir,net)
        _ = try await service.refresh(countries:["IT","AT"],now:now())
        await net.configure(offline:true)
        let before = await net.requests
        let value = await SignatureQualificationService().validate(try report(),catalog:service,mode:.offline,observedAt:try now())
        XCTAssertEqual(value.requestedCountries,["IT","AT"])
        XCTAssertTrue(value.signatures.allSatisfy { $0.qualification.state == .indeterminate })
        XCTAssertTrue(value.signatures.allSatisfy { !$0.path.alternativeServices.isEmpty })
        let after = await net.requests;XCTAssertEqual(before,after)
    }
    func testEquivalentAndNegativeHistoricTransitionsKeepIndependentProofs() async throws {
        let report = try report()
        for (name,expected) in [("transition-equivalent",SignatureQualificationState.qualified),("transition-negative",.indeterminate)] {
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[try list(variant:name)],mode:.offline,observedAt:try now())
            let value = try XCTUnwrap(values.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(value.qualification.state,expected,value.qualification.reason)
            XCTAssertEqual(value.evidence.time.state,.proven);XCTAssertEqual(value.evidence.revocation.state,.good)
            XCTAssertTrue(value.qualification.serviceStateFromHistory || name == "transition-negative")
            XCTAssertEqual(value.evidence.revocationPath?.evaluatedAt,value.evidence.time.provenTime)
        }
    }
    func testCurrentGoodWithoutHistoricalWindowNoTimeOrExpiredTLNeverQES() async throws {
        let report = try report(), catalog = try list(), observed = try now()
        let values = await SignatureQualificationService().validate(report,authenticatedLists:[catalog],mode:.offline,observedAt:observed)
        let complete = try XCTUnwrap(values.first { $0.qualification.statements?.compliance == true })
        XCTAssertEqual(complete.qualification.state,.qualified)
        let signature = try XCTUnwrap(report.signatures.first { $0.id == complete.signatureID })
        let late = complete.evidence.revocation.certificates.map { r in
            RevocationEvidenceResult(state:.good,kind:r.kind,evaluatedAt:observed,thisUpdate:observed.addingTimeInterval(-1),nextUpdate:r.nextUpdate,revokedAt:nil,reason:"synthetic current-good policy case")
        }
        let currentOnly = SignatureEvidenceValidationResult(signatureID:complete.signatureID,
            revocation:.init(state:.good,reason:"current only",certificates:late),time:complete.evidence.time,
            associations:complete.evidence.associations,revocationPath:complete.evidence.revocationPath)
        let q = SignatureQualificationService.assess(signature,evidence:currentOnly,lists:[catalog],mode:.offline,observedAt:observed)
        XCTAssertEqual(q.state,.indeterminate);XCTAssertTrue(q.reason.contains("finestra"),q.reason)
        let noTime = SignatureEvidenceValidationResult(signatureID:complete.signatureID,revocation:complete.evidence.revocation,
            time:.init(state:.notProven,declaredSigningTime:"2020-01-01T00:00:00Z",provenTime:nil,reason:"declared only",authorities:[]),associations:[])
        XCTAssertEqual(SignatureQualificationService.assess(signature,evidence:noTime,lists:[catalog],mode:.offline,observedAt:observed).state,.indeterminate)
        let expired = await SignatureQualificationService().validate(report,authenticatedLists:[catalog],mode:.offline,observedAt:catalog.document.nextUpdate.addingTimeInterval(1))
        XCTAssertTrue(expired.allSatisfy { $0.qualification.state == .indeterminate })
    }
}
