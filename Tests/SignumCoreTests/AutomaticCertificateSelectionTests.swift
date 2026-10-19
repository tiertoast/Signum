#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

extension DeviceSelection {
    @discardableResult mutating func acceptCompleteFixture(_ rows:[DiscoveredMiddleware],request:UUID,at date:Date=Date()) -> Bool {
        accept(rows,request:request,at:date,expectedPaths:Set(rows.map(\.candidatePath)))
    }
}

final class AutomaticCertificateSelectionTests: XCTestCase {
    let fixture = DeviceSelectionTests()
    func provider(_ name:String="A",_ certificate:String="valid",slot:UInt=7) throws -> DiscoveredMiddleware {
        fixture.provider(name,der:try CertificateEligibilityTests.fixtures.get().der(certificate),slot:slot)
    }
    func row(_ p:DiscoveredMiddleware,status:MiddlewareDetectionStatus?=nil,state:DiscoveredToken.CertificateState?=nil) -> DiscoveredMiddleware {
        .init(id:p.id,definition:p.definition,origin:p.origin,candidatePath:p.candidatePath,inspection:p.inspection,
              status:status ?? p.status,tokens:p.tokens.map { .init(token:$0.token,certificates:$0.certificates,certificateState:state ?? $0.certificateState) },version:nil,unavailableSlots:0)
    }
    func testZeroAuthenticationAndIneligibleNeverSelect() throws {
        for names in [[],["authentication"],["expired"],["wrongKU"],["missingKU"],["authentication","expired","missingKU"]] {
            let rows=try names.enumerated().map { try provider("P\($0.offset)",$0.element) }
            var s=DeviceSelection();let r=s.beginDiscovery();s.acceptCompleteFixture(rows,request:r)
            XCTAssertNil(s.selectedRoute);XCTAssertNil(s.selectionOrigin)
        }
    }
    func testSingleSigningRouteAndSigningPlusAuthenticationUseSG04NotNames() throws {
        for names in [["valid"],["valid","authentication"],["authentication","valid","expired","wrongKU","missingKU"]] {
            let rows=try names.enumerated().map {try provider("P\($0.offset)",$0.element)}
            for ordered in [rows,Array(rows.reversed())] {
                var s=DeviceSelection();let r=s.beginDiscovery();XCTAssertNil(s.selectedRoute)
                s.acceptCompleteFixture(ordered,request:r)
                XCTAssertEqual(s.selectionOrigin,.automatic);XCTAssertTrue(s.selectedRoute?.assessment.permitsSigning == true)
                XCTAssertEqual(s.selectedRoute?.der,try CertificateEligibilityTests.fixtures.get().der("valid"))
                XCTAssertTrue(s.message.contains("automaticamente"))
            }
        }
    }
    func testMultipleCertificatesAndSameDERAcrossSlotsOrProvidersAreAmbiguous() throws {
        let a=try provider()
        for rows in [[a,try provider("B","replaced")],[a,try provider("B")],[a,try provider("A",slot:99)]] {
            var s=DeviceSelection();let r=s.beginDiscovery();s.acceptCompleteFixture(rows,request:r)
            XCTAssertNil(s.selectedRoute);XCTAssertEqual(s.certificates.flatMap(\.routes).count,2)
        }
        var s=DeviceSelection();let r=s.beginDiscovery();s.acceptCompleteFixture([a,a],request:r)
        XCTAssertEqual(s.certificates.flatMap(\.routes).count,1,"Identical observation is not a second route")
        XCTAssertEqual(s.selectionOrigin,.automatic)
    }
    func testCoverageMustIncludeAllConfiguredProviders() throws {
        let a=try provider(),b=try provider("B")
        for expected in [nil,Set([a.candidatePath,b.candidatePath])] as [Set<String>?] {
            var s=DeviceSelection();let r=s.beginDiscovery()
            s.accept(.init(providers:[a],expectedPaths:expected),request:r)
            XCTAssertNil(s.selectedRoute);XCTAssertFalse(s.discoveryComplete)
        }
        var s=DeviceSelection();let r=s.beginDiscovery()
        s.accept(.init(providers:[a,row(b,status:.missing)],expectedPaths:Set([a.candidatePath,b.candidatePath])),request:r)
        XCTAssertTrue(s.discoveryComplete);XCTAssertEqual(s.selectionOrigin,.automatic)
    }
    func testErrorsPartialUnreadableHiddenCertificatesNeverProveUniqueness() throws {
        let a=try provider(),b=try provider("B","authentication")
        let uncertain=[row(b,status:.partial),row(b,status:.communicationError),row(b,status:.unsafe),row(b,status:.cancelled)] +
            [DiscoveredToken.CertificateState.empty,.authenticationRequired,.communicationError,.notInspected].map {row(b,state:$0)}
        for bad in uncertain {
            var s=DeviceSelection();let r=s.beginDiscovery();s.acceptCompleteFixture([a,bad],request:r)
            XCTAssertFalse(s.discoveryComplete);XCTAssertNil(s.selectedRoute)
        }
    }
    func testOutOfOrderCancellationAndRepeatedCompletionCannotReplaceSelection() throws {
        let a=try provider(),b=try provider("B","replaced")
        var s=DeviceSelection();let old=s.beginDiscovery(),current=s.beginDiscovery()
        XCTAssertFalse(s.acceptCompleteFixture([b],request:old));XCTAssertTrue(s.isSearching)
        XCTAssertTrue(s.acceptCompleteFixture([a],request:current));let selected=s.selectedRouteID
        XCTAssertFalse(s.acceptCompleteFixture([b],request:current));XCTAssertEqual(s.selectedRouteID,selected)
        let cancelled=s.beginDiscovery();s.cancelDiscovery()
        XCTAssertFalse(s.acceptCompleteFixture([a],request:cancelled));XCTAssertNil(s.selectedRoute)
    }
    func testManualChoiceSurvivesRefreshAndArrivalOfAlternatives() throws {
        let a=try provider(),b=try provider("B","replaced")
        var s=DeviceSelection();let r=s.beginDiscovery();s.acceptCompleteFixture([a,b],request:r)
        let choice=try XCTUnwrap(s.certificates.flatMap(\.routes).first { $0.der == a.tokens[0].certificates[0].der })
        XCTAssertTrue(s.select(routeID:choice.id));XCTAssertEqual(s.selectionOrigin,.manual)
        for _ in 0..<3 {
            let next=s.beginDiscovery();XCTAssertNil(s.selectedRoute)
            s.acceptCompleteFixture([b,a],request:next);XCTAssertEqual(s.selectedRouteID,choice.id);XCTAssertEqual(s.selectionOrigin,.manual)
        }
    }
    func testAutoChoiceIsReevaluatedOnRefreshRemovalReinsertSlotAndDERChange() throws {
        let a=try provider(),b=try provider("B","replaced")
        var s=DeviceSelection();var r=s.beginDiscovery();s.acceptCompleteFixture([a],request:r)
        let original=s.selectedRouteID
        r=s.beginDiscovery();s.acceptCompleteFixture([a,b],request:r);XCTAssertNil(s.selectedRoute)
        r=s.beginDiscovery();s.acceptCompleteFixture([],request:r);XCTAssertNil(s.selectedRoute)
        for changed in [a,try provider("A",slot:99),try provider("A","replaced"),b] {
            r=s.beginDiscovery();XCTAssertNil(s.selectedRoute);s.acceptCompleteFixture([changed],request:r)
            XCTAssertEqual(s.selectionOrigin,.automatic)
            if changed.candidatePath != a.candidatePath || changed.tokens[0].token.slot != 7 || changed.tokens[0].certificates[0].der != a.tokens[0].certificates[0].der {
                XCTAssertNotEqual(s.selectedRouteID,original)
            }
        }
    }
    func testExpiredManualChoiceCannotBypassReevaluation() throws {
        let a=try provider()
        var s=DeviceSelection();var r=s.beginDiscovery();s.acceptCompleteFixture([a],request:r)
        s.select(routeID:s.selectedRouteID)
        r=s.beginDiscovery();s.acceptCompleteFixture([a],request:r,at:Date(timeIntervalSince1970:0))
        XCTAssertNil(s.selectedRoute)
    }
    func testLegacyCertificateCacheDoesNotPickFirstOfMultipleEligible() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("valid")
        var cache=LoadedCertificates()
        cache.certificates=[.init(label:"DS3",identifier:Data([1])),.init(label:"CNL0",identifier:Data([2]))]
        for c in cache.certificates {cache.assessments[c.id]=CertificateEligibility.evaluate(certificateDER:der)}
        var s=ProviderSelection();s.applyCertificates(cache);XCTAssertNil(s.selectedCertificateID)
    }
    func testAvailabilityBeforeConsentRechecksObservedDERAndSlotWithoutLogin() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("valid"),mock=try MockModule(certificate:der,audit:true)
        let worker=ProcessInfo.processInfo.environment["SIGNUM_TEST_BATCH_WORKER"].map(URL.init(fileURLWithPath:)) ??
            Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
        let client=IsolatedPKCS11Client(executable:worker)
        let rows=MiddlewareDiscovery(client:client).discover(registry:[],manualPaths:[mock.path.path])
        let route=try XCTUnwrap(DeviceCertificate.collect(rows).first?.routes.first)
        XCTAssertNoThrow(try route.requireCurrentCredential(client:client))
        let observed=try XCTUnwrap(rows.first),t=try XCTUnwrap(observed.tokens.first)
        for replaced in [false,true] {
            let token=SignumToken(slot:replaced ? t.token.slot:99,label:t.token.label,manufacturer:t.token.manufacturer,model:t.token.model,reader:t.token.reader,serial:t.token.serial)
            let certificate=IsolatedPKCS11Client.Certificate(certificate:route.certificate,der:replaced ? try CertificateEligibilityTests.fixtures.get().der("replaced"):der)
            let changed=DiscoveredMiddleware(id:observed.id,definition:observed.definition,origin:observed.origin,candidatePath:observed.candidatePath,inspection:observed.inspection,status:.ready,tokens:[.init(token:token,certificates:[certificate],certificateState:.readable)],version:nil,unavailableSlots:0)
            let stale=try XCTUnwrap(DeviceCertificate.collect([changed]).first?.routes.first)
            XCTAssertThrowsError(try stale.requireCurrentCredential(client:client))
        }
        let audit=try String(contentsOf:mock.folder.appendingPathComponent("operations"))
        XCTAssertFalse(audit.split(separator:"\n").contains("8"));XCTAssertFalse(audit.split(separator:"\n").contains("16"))
    }
    func testPublicDiscoveryAndAutoSelectionDoNotLoginOrSign() throws {
        let der=try CertificateEligibilityTests.fixtures.get().der("valid"),mock=try MockModule(certificate:der,audit:true)
        let worker=ProcessInfo.processInfo.environment["SIGNUM_TEST_BATCH_WORKER"].map(URL.init(fileURLWithPath:)) ??
            Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
        let rows=MiddlewareDiscovery(client:.init(executable:worker)).discover(registry:[],manualPaths:[mock.path.path])
        var s=DeviceSelection();let r=s.beginDiscovery();s.accept(.init(providers:rows,expectedPaths:[mock.path.path]),request:r)
        XCTAssertEqual(s.selectionOrigin,.automatic)
        let audit=try String(contentsOf:mock.folder.appendingPathComponent("operations"))
        XCTAssertFalse(audit.split(separator:"\n").contains("8"),"C_Login must not be called")
        XCTAssertFalse(audit.split(separator:"\n").contains("16"),"C_Sign must not be called")
    }
}
#endif
