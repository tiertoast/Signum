import XCTest
import Darwin
@testable import SignumCertificateValidation

final class RevocationEvidenceTests: XCTestCase {
    private func data(_ name: String, _ ext: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures/Revocation")))
    }
    private func now() throws -> Date {
        let clock = try JSONDecoder().decode([String:String].self, from: data("clock", "json"))
        return try XCTUnwrap(ISO8601DateFormatter().date(from: XCTUnwrap(clock["evaluatedAt"])))
    }
    private func verify(_ name: String, _ kind: RevocationEvidenceKind, at date: Date? = nil, issuer: String = "issuer") throws -> RevocationEvidenceResult {
        RevocationEvidenceVerifier.verify(.init(kind: kind, der: try data(name, kind == .ocsp ? "ocsp" : "crl")),
            certificate: try data("leaf", "der"), issuer: try data(issuer, "der"), now: try date ?? now())
    }
    func testCurrentIssuerOCSPAndCRLGood() throws {
        for kind in [RevocationEvidenceKind.ocsp, .crl] {
            let result = try verify("good", kind)
            XCTAssertEqual(result.state, .good, result.reason)
            XCTAssertTrue(result.authenticated)
            XCTAssertNotNil(result.thisUpdate); XCTAssertNotNil(result.nextUpdate)
        }
    }
    func testRevokedOCSPAndCRL() throws {
        for kind in [RevocationEvidenceKind.ocsp, .crl] {
            let result = try verify("revoked", kind)
            XCTAssertEqual(result.state, .revoked, result.reason)
            XCTAssertLessThan(try XCTUnwrap(result.revokedAt), try now())
        }
    }
    func testTamperedEvidenceAndWrongIssuerNeverGood() throws {
        for kind in [RevocationEvidenceKind.ocsp, .crl] {
            XCTAssertEqual(try verify("altered", kind).state, .invalid)
            XCTAssertEqual(try verify("good", kind, issuer: "other").state, .invalid)
        }
    }
    func testStaleFutureAndExpiredCacheClockNeverGood() throws {
        for kind in [RevocationEvidenceKind.ocsp, .crl] {
            for name in ["stale", "future"] { XCTAssertEqual(try verify(name, kind).state, .stale, name) }
            XCTAssertEqual(try verify("good", kind, at: now().addingTimeInterval(3*86400)).state, .stale)
        }
    }
    func testResponderDelegationAndAuthorization() throws {
        let delegated = try verify("delegated", .ocsp)
        XCTAssertEqual(delegated.state, .good, delegated.reason)
        XCTAssertEqual(try verify("wrong-responder", .ocsp).state, .invalid)
        XCTAssertEqual(try verify("unauthorized", .ocsp).state, .invalid)
        XCTAssertEqual(try verify("unchecked-responder", .ocsp).state, .unknown)
    }
    func testOCSPUnknownWrongCertificateAndAbsentNextUpdate() throws {
        for name in ["unknown", "unrelated", "no-next"] {
            let result = try verify(name, .ocsp)
            XCTAssertEqual(result.state, .unknown, "\(name): \(result.reason)")
            XCTAssertFalse(result.authenticated)
        }
    }
    func testPartialDeltaAndCriticalCRLsCannotProveGood() throws {
        for name in ["delta", "restricted", "critical"] {
            XCTAssertEqual(try verify(name, .crl).state, .unknown, name)
        }
        XCTAssertEqual(try verify("wrong-key", .crl).state, .invalid)
    }
    func testMalformedTruncatedTrailingDERAndLimits() throws {
        let cert = try data("leaf", "der"), issuer = try data("issuer", "der"), date = try now()
        for kind in [RevocationEvidenceKind.ocsp, .crl] {
            let good = try data("good", kind == .ocsp ? "ocsp" : "crl")
            for bytes in [Data([0,1]), Data(good.dropLast()), good + Data([0])] {
                XCTAssertEqual(RevocationEvidenceVerifier.verify(.init(kind: kind, der: bytes), certificate: cert, issuer: issuer, now: date).state, .invalid)
            }
            let tooBig = RevocationEvidenceVerifier.verify(.init(kind: kind, der: Data(repeating: 0, count: RevocationEvidenceVerifier.maximumBytes+1)), certificate: cert, issuer: issuer, now: date)
            XCTAssertEqual(tooBig.state, .unknown)
            XCTAssertEqual(RevocationEvidenceVerifier.verify(.init(kind: kind, der: good), certificate: cert, issuer: issuer, now: Date(timeIntervalSince1970: .nan)).state, .unknown)
        }
    }
    func testCacheReverifiesOfflineAndRetainsLastValidOnBadReplacement() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cache = RevocationEvidenceCache(directory: dir), date = try now()
        let cert = try data("leaf", "der"), issuer = try data("issuer", "der")
        let good = RevocationEvidence(kind: .ocsp, der: try data("good", "ocsp"))
        let stored = try await cache.store(good, certificate: cert, issuer: issuer, now: date)
        XCTAssertEqual(stored.state, .good)
        let rejected = try await cache.store(.init(kind: .ocsp, der: data("altered", "ocsp")), certificate: cert, issuer: issuer, now: date)
        XCTAssertEqual(rejected.state, .invalid)
        let loaded = try await cache.load(.ocsp, certificate: cert, issuer: issuer, now: date)
        XCTAssertEqual(loaded?.evidence, good);XCTAssertEqual(loaded?.result.state, .good)
        let stale = try await cache.load(.ocsp, certificate: cert, issuer: issuer, now: date.addingTimeInterval(3*86400))
        XCTAssertEqual(stale?.result.state, .stale)
        let other = try await cache.load(.ocsp, certificate: cert, issuer: data("other", "der"), now: date)
        XCTAssertNil(other)
    }
    func testCacheTamperAndSymlinkRejected() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cache = RevocationEvidenceCache(directory: dir), date = try now()
        let cert = try data("leaf", "der"), issuer = try data("issuer", "der")
        _ = try await cache.store(.init(kind: .crl, der: data("good", "crl")), certificate: cert, issuer: issuer, now: date)
        let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).first { $0.pathExtension == "json" })
        let original = try Data(contentsOf: file)
        try Data("{}".utf8).write(to: file)
        do { _ = try await cache.load(.crl, certificate: cert, issuer: issuer, now: date);XCTFail("Tampered envelope accepted") }
        catch { }
        let target = dir.appendingPathComponent("target")
        try original.write(to: target); try FileManager.default.removeItem(at: file)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        do { _ = try await cache.load(.crl, certificate: cert, issuer: issuer, now: date);XCTFail("Symlink followed") }
        catch RevocationEvidenceCache.CacheError.unsupportedFile { }
    }
    func testCacheRejectsNonRegularLockWithoutBlocking() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cache = RevocationEvidenceCache(directory: dir), date = try now()
        let cert = try data("leaf", "der"), issuer = try data("issuer", "der")
        let evidence = RevocationEvidence(kind: .crl, der: try data("good", "crl"))
        _ = try await cache.store(evidence, certificate: cert, issuer: issuer, now: date)
        let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).first { $0.pathExtension == "lock" })
        try FileManager.default.removeItem(at: file)
        XCTAssertEqual(mkfifo(file.path, 0o600), 0)
        do { _ = try await cache.store(evidence, certificate: cert, issuer: issuer, now: date);XCTFail("Non-regular lock accepted") }
        catch RevocationEvidenceCache.CacheError.unsupportedFile { }
    }
    func testCacheDoesNotReplaceRevokedWithGood() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cache = RevocationEvidenceCache(directory: dir), date = try now()
        let cert = try data("leaf", "der"), issuer = try data("issuer", "der")
        _ = try await cache.store(.init(kind: .ocsp, der: data("revoked", "ocsp")), certificate: cert, issuer: issuer, now: date)
        do {
            _ = try await cache.store(.init(kind: .ocsp, der: data("good", "ocsp")), certificate: cert, issuer: issuer, now: date)
            XCTFail("Contradictory authenticated status must not produce good")
        } catch RevocationEvidenceCache.CacheError.conflictingEvidence { }
        let retained = try await cache.load(.ocsp, certificate: cert, issuer: issuer, now: date)
        XCTAssertEqual(retained?.result.state, .revoked)
    }
}
