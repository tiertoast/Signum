import XCTest
@testable import SignumTrustAuthentication

final class EuropeanBarrierTests: XCTestCase {
    func fixture(_ name: String, folder: String = "Fixtures") throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:"xml",subdirectory:folder)))
    }
    func testFrozenOfficialListsAuthenticateBeforeInterpretation() throws {
        let now = ISO8601DateFormatter().date(from:"2026-10-21T06:00:00Z")!
        let eu = try LOTLPivotChain.authenticate(current:fixture("eu-lotl"),pivotsOldestFirst:[],now:now)
        XCTAssertFalse(eu.source.authorizingReferences.isEmpty)
        for country in ["IT","AT","DE","BE","FR","ES"] {
            let xml = try country == "IT" ? fixture("it") : fixture(country.lowercased(),folder:"Fixtures/European")
            let catalog = try TLAuthenticator.authenticateNational(xml,country:country,lotl:eu,now:now)
            XCTAssertEqual(catalog.source.xmlSHA256,TLAuthenticator.sha256(xml))
            XCTAssertTrue(catalog.source.authorizingReferences.contains { $0.xmlSHA256 == eu.revision.xmlSHA256 })
            XCTAssertEqual(catalog.usableServiceCount+catalog.excludedServices.count,catalog.document.providers.reduce(0) { $0 + $1.services.count })
            XCTAssertGreaterThan(catalog.usableServiceCount,0)
            if ["BE","FR","ES"].contains(country) { XCTAssertEqual(catalog.interpretationState,.partial);XCTAssertFalse(catalog.excludedServices.isEmpty) }
            let reasons = Dictionary(grouping:catalog.excludedServices,by: \.reason).mapValues(\.count)
            let record: [String:Any] = ["country":country,"authenticated":true,"state":catalog.interpretationState.rawValue,"usable":catalog.usableServiceCount,"excluded":catalog.excludedServices.count,"reasons":reasons]
            print("E1R-OFFICIAL " + String(decoding:try JSONSerialization.data(withJSONObject:record,options:.sortedKeys),as:UTF8.self))
        }
    }
}
