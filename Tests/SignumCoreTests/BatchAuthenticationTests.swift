#if os(macOS)
import XCTest
@testable import SignumCore

final class BatchAuthenticationTests: XCTestCase {
    var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    func count(_ mock: MockModule, _ op: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(op) }.count
    }
    func fixture(always: Bool = false, unknown: Bool = false, preauthenticated: Bool = false,
                 phase: Int? = nil, effect: Int = 0, after: Int = 0,
                 _ body: (MockModule, BatchSignatureConnection) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase,
            workerEffect: effect, audit: true, alwaysAuth: always, unknownAuth: unknown, preauthenticated: preauthenticated, faultAfter: after)
        let jobs = try (1...3).map { index in BatchWorkerJob(id: UUID(), snapshotID: UUID(), sha256: String(repeating: "a", count: 64),
            attributes: try CAdES.Prepared(document: Data("Synthetic batch \(index)".utf8), certificateDER: signer.der).attributesToSign) }
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let manifest = BatchWorkerStart(version: 2, batchID: UUID(), provider: inspected.canonicalPath, slot: 7,
            serial: "SYNTHETIC-0001", certificate: WorkerCertificate(.init(label: "Synthetic", identifier: Data([1])), der: signer.der),
            automatic: false, moduleIdentity: inspected.identity, jobs: jobs, pin: nil)
        let connection = BatchSignatureConnection(manifest: manifest, executable: worker)
        defer { connection.abort() }
        try body(mock, connection)
    }
    func testThreeSignaturesWithOneUSERLoginAndCheckedTeardown() throws {
        try fixture { mock, session in
            for (index, job) in session.manifest.jobs.enumerated() {
                _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: index == 0 ? "synthetic-fixture" : nil)
                XCTAssertTrue(session.reusable)
            }
            try session.finish()
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), 0)
            XCTAssertEqual(count(mock, 16), 3); XCTAssertEqual(count(mock, 10), 0)
            XCTAssertEqual(count(mock, 0), 1); XCTAssertEqual(count(mock, 1), 1)
        }
    }
    func testAlwaysAuthenticateClosesAfterFirstSignatureWithContextLogin() throws {
        try fixture(always: true) { mock, session in
            let first = session.manifest.jobs[0]
            _ = try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture")
            XCTAssertFalse(session.reusable)
            let next = session.manifest.jobs[1]
            XCTAssertThrowsError(try session.sign(jobID: next.id, attributes: next.attributes, pin: nil))
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), 1)
            XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 1), 1)
        }
    }
    func testUnknownAttributeNeverEnablesReuse() throws {
        try fixture(unknown: true) { mock, session in
            let job = session.manifest.jobs[0]
            _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture")
            XCTAssertFalse(session.reusable); XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 1), 1)
        }
    }
    func testPreexistingAuthenticationNeverCountsAsFreshPINVerification() throws {
        try fixture(preauthenticated: true) { mock, session in
            let job = session.manifest.jobs[0]
            XCTAssertThrowsError(try session.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture"))
            XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0); XCTAssertEqual(count(mock, 10), 0)
        }
    }
    func testDuplicateOrOutOfOrderRequestsNeverSignAgain() throws {
        try fixture { mock, session in
            let first = session.manifest.jobs[0], third = session.manifest.jobs[2]
            _ = try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture")
            XCTAssertThrowsError(try session.sign(jobID: first.id, attributes: first.attributes, pin: nil))
            XCTAssertThrowsError(try session.sign(jobID: third.id, attributes: third.attributes, pin: nil))
            XCTAssertEqual(count(mock, 16), 1); try session.finish()
        }
    }
    func testLoginFailureDoesNotRetryOrSign() throws {
        try fixture(phase: 8, effect: 4) { mock, session in
            let first = session.manifest.jobs[0]
            XCTAssertThrowsError(try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture"))
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 0)
        }
    }
}
#endif
