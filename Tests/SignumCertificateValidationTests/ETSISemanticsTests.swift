import XCTest
import SignumCore
@testable import SignumTrustCore
import SignumTrustAuthentication
@testable import SignumCertificateValidation

final class ETSISemanticsTests: XCTestCase {
    let prefix = TLQualificationRules.prefix
    struct Facts: TLQualificationMaterial {
        var policies: Set<String> = [], keyUsage: [String:Bool] = ["digitalSignature":true,"nonRepudiation":true]
        var subjectAttributes: Set<String>? = ["2.5.4.3","1.3.6.1.4.1.18838.1.1"]
        var extendedKeyUsage: Set<String>? = ["1.3.6.1.5.5.7.3.8"]
    }
    func data(_ name: String,_ ext: String = "xml",folder: String = "E1R") throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:name,withExtension:ext,subdirectory:"Fixtures/"+folder)))
    }
    func now() throws -> Date {
        let clock = try JSONSerialization.jsonObject(with:data("clock","json")) as! [String:String]
        return try XCTUnwrap(ISO8601DateFormatter().date(from:clock["evaluatedAt"]!))
    }
    func list(_ name: String) throws -> InterpretedTrustCatalog {
        try TLAuthenticator.authenticate(data(name,folder:"E1S"),authorizedCertificateSHA256:[TLAuthenticator.sha256(data("tl-signer","der",folder:"E1S"))],territory:"IT",now:now())
    }
    func rules(_ body: String, assertion: String = "all", qualifiers: [String] = ["QCWithQSCD"]) throws -> [TLServiceExtension] {
        let qualifier = qualifiers.map { "<s:Qualifier uri=\"\(prefix+$0)\"/>" }.joined()
        let xml = """
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:s="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:a="http://uri.etsi.org/02231/v2/additionaltypes#" xmlns:x="http://uri.etsi.org/01903/v1.3.2#">
        <SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber><SchemeTerritory>IT</SchemeTerritory><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2027-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>
        <TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name>T</Name></TSPName></TSPInformation><TSPServices><TSPService><ServiceInformation><ServiceName><Name>S</Name></ServiceName><ServiceTypeIdentifier>CA</ServiceTypeIdentifier><ServiceStatus>granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime><ServiceInformationExtensions><Extension Critical="true"><s:Qualifications><s:QualificationElement><s:Qualifiers>\(qualifier)</s:Qualifiers><s:CriteriaList assert="\(assertion)">\(body)</s:CriteriaList></s:QualificationElement></s:Qualifications></Extension></ServiceInformationExtensions></ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>
        """
        return try XCTUnwrap(UntrustedTLParser.parse(Data(xml.utf8)).providers.first?.services.first?.extensions)
    }
    func criterion(_ body: String, assertion: String = "all") throws -> TLServiceExtension {
        try XCTUnwrap(rules(body,assertion:assertion).first?.children.first?.children.first?.children.last)
    }
    let dn = "<s:otherCriteriaList><a:CertSubjectDNAttribute><a:AttributeOID><x:Identifier>1.3.6.1.4.1.18838.1.1</x:Identifier></a:AttributeOID></a:CertSubjectDNAttribute></s:otherCriteriaList>"
    let eku = "<s:otherCriteriaList><a:ExtendedKeyUsage><a:KeyPurposeId><x:Identifier Qualifier=\"OIDAsURI\">urn:oid:1.3.6.1.5.5.7.3.8</x:Identifier></a:KeyPurposeId></a:ExtendedKeyUsage></s:otherCriteriaList>"
    func testGeneralOIDCriteriaThreeStatesAndActualCertificateFacts() throws {
        let node = try criterion(dn+eku)
        XCTAssertEqual(TLQualificationRules.criteriaResult(node,material:Facts()),.matches)
        var facts = Facts();facts.subjectAttributes = []
        XCTAssertEqual(TLQualificationRules.criteriaResult(node,material:facts),.doesNotMatch)
        facts.subjectAttributes = nil
        XCTAssertEqual(TLQualificationRules.criteriaResult(node,material:facts),.unsupported)
        facts = Facts();facts.extendedKeyUsage = []
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(eku),material:facts),.doesNotMatch)
        let policy = "<s:PolicySet><s:PolicyIdentifier><x:Identifier Qualifier=\"OIDAsURN\">urn:oid:1.2.3.4</x:Identifier></s:PolicyIdentifier></s:PolicySet>"
        facts = Facts();facts.policies = ["1.2.3.4"]
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(policy),material:facts),.matches)
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(policy.replacingOccurrences(of:"urn:oid:",with:"")),material:facts),.unsupported)
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(policy.replacingOccurrences(of:"OIDAsURN",with:"Unrecognized")),material:facts),.unsupported)
        let tsa = try CertificateQualificationMaterial(data("tsa","der"))
        XCTAssertTrue(tsa.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.8") == true)
        XCTAssertTrue(tsa.subjectAttributes?.contains("2.5.4.3") == true)
        XCTAssertNotNil(tsa.subjectKeyIdentifier)
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(eku),material:tsa),.matches)
    }
    func testRecursiveBooleanCriteriaUnknownIsNeverFalseAndBadOIDOrNamespace() throws {
        let absent = dn.replacingOccurrences(of:"1.3.6.1.4.1.18838.1.1",with:"2.5.4.97")
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(dn+absent),material:Facts()),.doesNotMatch)
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(dn+absent,assertion:"atLeastOne"),material:Facts()),.matches)
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(absent,assertion:"none"),material:Facts()),.matches)
        let nested = "<s:CriteriaList assert=\"none\">\(absent)</s:CriteriaList>"
        XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(dn+nested),material:Facts()),.matches)
        for malformed in ["<s:Unknown/>",dn.replacingOccurrences(of:"a:CertSubjectDNAttribute",with:"s:CertSubjectDNAttribute"),dn.replacingOccurrences(of:"1.3.6.1.4.1.18838.1.1",with:"1.40.3"),dn.replacingOccurrences(of:"1.3.6.1.4.1.18838.1.1",with:"1.2..3")] {
            XCTAssertFalse(TLQualificationRules.supports(try rules(malformed)))
            XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(dn+malformed,assertion:"atLeastOne"),material:Facts()),.unsupported)
            XCTAssertEqual(TLQualificationRules.criteriaResult(try criterion(malformed,assertion:"none"),material:Facts()),.unsupported)
        }
    }
    func testLegacySSCDRegimeAsInCertNegativeAndContradictoryQualifiers() throws {
        let before = TLQualificationRules.regulationStart.addingTimeInterval(-1), after = TLQualificationRules.regulationStart
        let ku = "<s:KeyUsage><s:KeyUsageBit name=\"digitalSignature\">true</s:KeyUsageBit></s:KeyUsage>"
        for name in ["QCSSCDStatusAsInCert","QCNoSSCD","QCWithSSCD","QCForLegalPerson"] { XCTAssertTrue(TLQualificationRules.supports(try rules(ku,qualifiers:[name]))) }
        func device(_ names: [String],_ cert: Bool,_ at: Date) -> TLDeviceEvidence {
            TLQualificationRules.deviceEvidence(qualifiers:Set(names.map { prefix+$0 }),sscd:cert,policies:[],at:at)
        }
        XCTAssertEqual(device(["QCSSCDStatusAsInCert"],false,before),.no)
        XCTAssertEqual(device(["QCSSCDStatusAsInCert"],true,before),.yes)
        XCTAssertEqual(device(["QCNoSSCD"],false,before),.no)
        XCTAssertEqual(device(["QCNoSSCD"],true,before),.indeterminate)
        XCTAssertEqual(device(["QCWithSSCD"],false,before),.yes)
        XCTAssertEqual(device(["QCWithSSCD"],false,after),.indeterminate)
        XCTAssertEqual(device(["QCQSCDStatusAsInCert"],false,after),.no)
        for names in [["QCWithSSCD","QCNoSSCD"],["QCSSCDStatusAsInCert","QCWithSSCD"],["QCWithQSCD","QCNoQSCD"],["QCStatement","NotQualified"]] {
            XCTAssertFalse(TLQualificationRules.supports(try rules(ku,qualifiers:names)))
            XCTAssertNil(TLQualificationRules.evaluate(try rules(ku,qualifiers:names),material:Facts()))
        }
    }
    func replacingHistory(_ s: TLService,_ history: [TLServiceHistory]) -> TLService {
        TLService(subjectNames:s.subjectNames,subjectKeyIdentifiers:s.subjectKeyIdentifiers,name:s.name,typeURI:s.typeURI,
            statusURI:s.statusURI,statusSince:s.statusSince,certificateDERs:s.certificateDERs,history:history,extensions:s.extensions)
    }
    func testHistoricalSKIAndSubjectResolveWithoutEventDERAndNeverByNameAlone() throws {
        let catalog = try list("historical-ski"), service = try XCTUnwrap(catalog.usableProviders.first?.services.first)
        let timeline = try XCTUnwrap(service.timeline(issuedAt:catalog.document.issuedAt)), event = try XCTUnwrap(timeline.first)
        XCTAssertTrue(event.certificateDERs.isEmpty);XCTAssertFalse(event.subjectKeyIdentifiers.isEmpty);XCTAssertFalse(event.subjectNames.isEmpty)
        XCTAssertEqual(event.end,timeline.last?.start)
        let resolved = TLServiceIdentityResolver.certificates(event,service:service)
        XCTAssertFalse(resolved.isEmpty)
        let at = try now().addingTimeInterval(-120)
        let path = CertificatePathValidator.evaluate(signer:try data("leaf","der"),intermediates:[],identities:CertificatePathValidator.identities(catalog,now:at),now:at)
        XCTAssertEqual(path.state,.verified,path.reason)
        var history = service.history;history[0].subjectKeyIdentifiers = []
        let subjectOnly = replacingHistory(service,history)
        XCTAssertTrue(TLServiceIdentityResolver.certificates(try XCTUnwrap(subjectOnly.timeline(issuedAt:catalog.document.issuedAt)?.first),service:subjectOnly).isEmpty)
        history = service.history;history[0].subjectNames = ["CN=unrelated"]
        let wrongName = replacingHistory(service,history)
        XCTAssertTrue(TLServiceIdentityResolver.certificates(try XCTUnwrap(wrongName.timeline(issuedAt:catalog.document.issuedAt)?.first),service:wrongName).isEmpty)
        let unrelated = try list("historical-ambiguous")
        XCTAssertFalse(CertificatePathValidator.identities(unrelated,now:at).contains { $0.eligible && $0.match.service == service.name })
    }
    func testSignedBadTimelineExcludesOnlyAffectedService() throws {
        let catalog = try list("historical-order")
        XCTAssertEqual(catalog.interpretationState,.partial);XCTAssertEqual(catalog.excludedServices.count,1)
        XCTAssertTrue(catalog.excludedServices[0].reason.contains("timeline"));XCTAssertEqual(catalog.usableServiceCount,2)
        let service = try XCTUnwrap(catalog.document.providers.first?.services.first)
        XCTAssertNil(service.timeline(issuedAt:catalog.document.issuedAt))
        XCTAssertNotNil(replacingHistory(service,Array(service.history.prefix(1))).timeline(issuedAt:catalog.document.issuedAt))
        XCTAssertNil(service.timeline(issuedAt:service.statusSince.addingTimeInterval(-1)))
        XCTAssertEqual(catalog.source.xmlSHA256,TLAuthenticator.sha256(try data("historical-order",folder:"E1S")))
    }
    func testHistoricalTSAAndQualificationUseOwnRulesPerSigner() async throws {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let report = try SignumVerificationService.verify(data:data("multi","cms"),name:"multi.cms",helper:URL(fileURLWithPath:helper))
        for (name,expected) in [("historical-ski",SignatureQualificationState.qualified),("historical-negative",.indeterminate),("historical-ambiguous",.indeterminate)] {
            let values = await SignatureQualificationService().validate(report,authenticatedLists:[try list(name)],mode:.online,observedAt:try now())
            let first = try XCTUnwrap(values.first { $0.qualification.statements?.compliance == true })
            XCTAssertEqual(first.qualification.state,expected,first.qualification.reason)
            XCTAssertEqual(first.evidence.time.state,.proven,first.evidence.time.reason)
            if name == "historical-ski" { XCTAssertEqual(first.evidence.revocation.state,.good);XCTAssertTrue(first.qualification.serviceStateFromHistory) }
            XCTAssertEqual(values.first { $0.signatureID != first.signatureID }?.qualification.state,.electronic)
        }
    }
    func testDNCorrespondenceEscapingAndMultivaluedRDNs() {
        XCTAssertEqual(TLServiceIdentityResolver.distinguishedName("CN=Example\\, CA+OU=Unit, C=IT"),TLServiceIdentityResolver.distinguishedName("OU=Unit+2.5.4.3=\"Example, CA\",2.5.4.6=IT"))
        XCTAssertNil(TLServiceIdentityResolver.distinguishedName("CN=unfinished\\"))
        XCTAssertNotEqual(TLServiceIdentityResolver.distinguishedName("CN=one,C=IT"),TLServiceIdentityResolver.distinguishedName("CN=two,C=IT"))
    }
}
