import Foundation
import XCTest
@testable import SignumTrustCore

final class TLContinuityPolicyTests: XCTestCase {
    private let now = ISO8601DateFormatter().date(from: "2026-10-20T12:00:00Z")!

    private func revision(
        sequence: Int = 5,
        version: Int = 6,
        territory: String = "IT",
        issued: String = "2026-10-19T08:00:00Z",
        next: String = "2026-10-27T08:00:00Z",
        digestByte: UInt8 = 1
    ) throws -> UntrustedTLRevision {
        let xml = """
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
          <SchemeInformation>
            <TSLVersionIdentifier>\(version)</TSLVersionIdentifier>
            <TSLSequenceNumber>\(sequence)</TSLSequenceNumber>
            <SchemeTerritory>\(territory)</SchemeTerritory>
            <ListIssueDateTime>\(issued)</ListIssueDateTime>
            <NextUpdate><dateTime>\(next)</dateTime></NextUpdate>
          </SchemeInformation>
        </TrustServiceStatusList>
        """
        let document = try UntrustedTLParser.parse(Data(xml.utf8))
        return try UntrustedTLRevision(document: document, xmlSHA256: Data(repeating: digestByte, count: 32))
    }

    func testFirstCandidateNeverClaimsTrust() throws {
        XCTAssertEqual(TLContinuityPolicy.assess(previous: nil, candidate: try revision(), now: now),
                       .initialCandidate)
    }

    func testIdenticalCandidateAndNewerSequence() throws {
        let old = try revision()
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old, candidate: old, now: now),
                       .unchangedCandidate)
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(sequence: 6, digestByte: 2), now: now),
                       .newerCandidate)
    }

    func testSameSequenceDifferentBytesOrDateRejected() throws {
        let old = try revision()
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(digestByte: 4), now: now),
                       .rejected(.sequenceReusedWithDifferentContent))
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(issued: "2026-10-20T08:00:00Z"), now: now),
                       .rejected(.sequenceReusedWithDifferentContent))
    }

    func testSequenceAndIssueTimeRollbackRejected() throws {
        let old = try revision()
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(sequence: 4), now: now),
                       .rejected(.sequenceRollback))
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(sequence: 6, issued: "2026-10-18T08:00:00Z"), now: now),
                       .rejected(.issueTimeRollback))
    }

    func testTerritoryAndVersionDowngradeRejected() throws {
        let old = try revision()
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(sequence: 6, territory: "FR"), now: now),
                       .rejected(.territoryChanged))
        XCTAssertEqual(TLContinuityPolicy.assess(previous: old,
                     candidate: try revision(sequence: 6, version: 5), now: now),
                       .rejected(.versionDowngrade))
    }

    func testExpiredAndFutureDatedAreNotCurrent() throws {
        XCTAssertEqual(TLContinuityPolicy.assess(previous: nil,
                     candidate: try revision(next: "2026-10-19T09:00:00Z"), now: now),
                       .rejected(.expired))
        XCTAssertEqual(TLContinuityPolicy.assess(previous: nil,
                     candidate: try revision(issued: "2026-10-20T12:05:01Z"), now: now),
                       .rejected(.issuedInFuture))
        XCTAssertEqual(TLContinuityPolicy.assess(previous: nil,
                     candidate: try revision(issued: "2026-10-20T12:05:00Z"), now: now),
                       .initialCandidate)
    }

    func testBadDigestAndNonPositiveSequenceFailAtConstruction() throws {
        let xml = """
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
          <SchemeInformation>
            <TSLVersionIdentifier>6</TSLVersionIdentifier>
            <TSLSequenceNumber>2</TSLSequenceNumber>
            <SchemeTerritory>IT</SchemeTerritory>
            <ListIssueDateTime>2026-10-19T00:00:00Z</ListIssueDateTime>
            <NextUpdate><dateTime>2026-11-19T00:00:00Z</dateTime></NextUpdate>
          </SchemeInformation>
        </TrustServiceStatusList>
        """
        let doc = try UntrustedTLParser.parse(Data(xml.utf8))
        XCTAssertThrowsError(try UntrustedTLRevision(document: doc, xmlSHA256: Data([0x01]))) {
            XCTAssertEqual($0 as? TLContinuityFailure, .malformedRevision)
        }
    }
}
