#if os(macOS)
import XCTest
@testable import SignumCore

final class BatchAuthenticationTests: XCTestCase {
    var worker: URL { ProcessInfo.processInfo.environment["SIGNUM_TEST_BATCH_WORKER"].map { URL(fileURLWithPath: $0) } ?? Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    func count(_ mock: MockModule, _ op: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(op) }.count
    }
    func fixture(always: Bool = false, unknown: Bool = false, preauthenticated: Bool = false, preinitialized: Bool = false,
                 phase: Int? = nil, effect: Int = 0, after: Int = 0,
                 temporary: Bool = false, documents: Int = 3, lifetime: Double? = nil, idle: Double? = nil,
                 _ body: (MockModule, BatchSignatureConnection) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase,
            workerEffect: effect, audit: true, alwaysAuth: always, unknownAuth: unknown, preauthenticated: preauthenticated, preinitialized: preinitialized, faultAfter: after, strictContext: temporary)
        let jobs = try (1...documents).map { index in BatchWorkerJob(id: UUID(), snapshotID: UUID(), sha256: String(repeating: "a", count: 64),
            attributes: try CAdES.Prepared(document: Data("Synthetic batch \(index)".utf8), certificateDER: signer.der).attributesToSign) }
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        var manifest = BatchWorkerStart(version: temporary ? 3 : 2, batchID: UUID(), provider: inspected.canonicalPath, slot: 7,
            serial: "SYNTHETIC-0001", certificate: WorkerCertificate(.init(label: "Synthetic", identifier: Data([1])), der: signer.der),
            automatic: false, moduleIdentity: inspected.identity, jobs: jobs, pin: nil)
        if temporary { manifest.temporaryPIN = true; manifest.pinLifetimeSeconds = lifetime; manifest.pinIdleSeconds = idle }
        let connection = BatchSignatureConnection(manifest: manifest, executable: worker)
        defer { connection.abort() }
        try body(mock, connection)
    }
    func testThreeSignaturesWithOneUSERLoginAndCheckedTeardown() throws {
        try fixture { mock, session in
            for (index, job) in session.manifest.jobs.enumerated() {
                _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: index == 0 ? "synthetic-fixture" : nil)
                XCTAssertTrue(session.reusable)
                XCTAssertNil(session.manifest.pin)
                let command = BatchWorkerCommand(version: 2, batchID: session.manifest.batchID, jobID: job.id, index: index, finish: false)
                let wire = String(decoding: try JSONEncoder().encode(command), as: UTF8.self)
                XCTAssertFalse(wire.contains("synthetic-fixture")); XCTAssertFalse(wire.contains("\"pin\""))
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
    func testSessionLossAndDeviceRemovalEndReuseWithoutRetry() throws {
        for (phase, effect, after) in [(7, 6, 2), (16, 8, 1)] {
            try fixture(phase: phase, effect: effect, after: after) { mock, session in
                let first = session.manifest.jobs[0], second = session.manifest.jobs[1], third = session.manifest.jobs[2]
                _ = try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture")
                XCTAssertThrowsError(try session.sign(jobID: second.id, attributes: second.attributes, pin: nil))
                XCTAssertFalse(session.reusable)
                let calls = count(mock, 16)
                XCTAssertThrowsError(try session.sign(jobID: third.id, attributes: third.attributes, pin: nil))
                XCTAssertEqual(count(mock, 16), calls); XCTAssertEqual(count(mock, 8), 1)
            }
        }
    }
    func testAnotherBatchCannotBorrowTheAuthenticatedWorkerOrLease() throws {
        try fixture { mock, first in
            let job = first.manifest.jobs[0]
            _ = try first.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture")
            let m = first.manifest
            let other = BatchWorkerStart(version: 2, batchID: UUID(), provider: m.provider, slot: m.slot,
                serial: m.serial, certificate: m.certificate, automatic: m.automatic, moduleIdentity: m.moduleIdentity, jobs: m.jobs, pin: nil)
            let second = BatchSignatureConnection(manifest: other, executable: worker)
            XCTAssertThrowsError(try second.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture", timeout: 0.15))
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 1)
            try first.finish()
            let fresh = BatchSignatureConnection(manifest: other, executable: worker)
            _ = try fresh.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture")
            try fresh.finish()
            XCTAssertEqual(count(mock, 8), 2); XCTAssertEqual(count(mock, 16), 2)
        }
    }
    func testChangedSerialOrModuleCannotReceivePINOrSign() throws {
        for changeModule in [false, true] {
            try fixture { mock, original in
                let m = original.manifest
                let changed = BatchWorkerStart(version: 2, batchID: UUID(), provider: m.provider, slot: m.slot,
                    serial: changeModule ? m.serial : "OTHER-TOKEN", certificate: m.certificate, automatic: false,
                    moduleIdentity: m.moduleIdentity, jobs: m.jobs, pin: nil)
                if changeModule {
                    let file = try FileHandle(forWritingTo: mock.path)
                    try file.seekToEnd(); try file.write(contentsOf: Data([0])); try file.close()
                }
                let session = BatchSignatureConnection(manifest: changed, executable: worker)
                let job = changed.jobs[0]
                XCTAssertThrowsError(try session.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture"))
                XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0)
            }
        }
    }

    func testProviderInitializedByAnotherOwnerIsNotFinalizedOrReused() throws {
        try fixture(preinitialized: true) { mock, session in
            let job = session.manifest.jobs[0]
            _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture")
            XCTAssertFalse(session.reusable)
            XCTAssertEqual(count(mock, 0), 1); XCTAssertEqual(count(mock, 1), 0)
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 1)
        }
    }

    func testTemporaryPINSupportsThreeAndSevenContextAuthenticationsFromOneUIValue() throws {
        for documents in [3, 7] {
            try fixture(always: true, temporary: true, documents: documents) { mock, session in
                let manifest = String(decoding: try JSONEncoder().encode(session.manifest), as: UTF8.self)
                XCTAssertFalse(manifest.contains("\"pin\"")); XCTAssertFalse(manifest.contains("synthetic-fixture"))
                for (index, job) in session.manifest.jobs.enumerated() {
                    _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: index == 0 ? "synthetic-fixture" : nil)
                    XCTAssertTrue(session.reusable)
                }
                try session.finish()
                XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), documents)
                XCTAssertEqual(count(mock, 16), documents); XCTAssertEqual(count(mock, 1), 1)
                XCTAssertFalse((try String(contentsOf: mock.folder.appendingPathComponent("operations"))).contains("synthetic-fixture"))
            }
        }
    }
    func testTemporaryFalseAttributeNeedsNoFurtherPINOrContextLogin() throws {
        try fixture(temporary: true, documents: 7) { mock, session in
            for (index, job) in session.manifest.jobs.enumerated() {
                _ = try session.sign(jobID: job.id, attributes: job.attributes, pin: index == 0 ? "synthetic-fixture" : nil)
            }
            try session.finish()
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), 0); XCTAssertEqual(count(mock, 16), 7)
        }
    }
    func testTemporaryUnknownAttributeClosesAndCannotUseStoredPIN() throws {
        try fixture(unknown: true, temporary: true) { mock, session in
            let first = session.manifest.jobs[0], next = session.manifest.jobs[1]
            _ = try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture")
            XCTAssertFalse(session.reusable)
            XCTAssertThrowsError(try session.sign(jobID: next.id, attributes: next.attributes, pin: nil))
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 1), 1)
        }
    }
    func testTemporaryContextFailureRetiresWorkerWithoutRetry() throws {
        try fixture(always: true, phase: 9, effect: 4, after: 1, temporary: true) { mock, session in
            let jobs = session.manifest.jobs
            _ = try session.sign(jobID: jobs[0].id, attributes: jobs[0].attributes, pin: "synthetic-fixture")
            XCTAssertThrowsError(try session.sign(jobID: jobs[1].id, attributes: jobs[1].attributes, pin: nil))
            XCTAssertThrowsError(try session.sign(jobID: jobs[2].id, attributes: jobs[2].attributes, pin: nil))
            XCTAssertEqual(count(mock, 9), 2); XCTAssertEqual(count(mock, 16), 1)
        }
    }
    func testTemporaryLifetimeAndIdleTimeoutRetireWithoutAnotherLogin() throws {
        for idleLimit in [false, true] {
            try fixture(always: true, temporary: true, lifetime: idleLimit ? 30 : 1.5, idle: idleLimit ? 0.3 : 60) { mock, session in
                let jobs = session.manifest.jobs
                _ = try session.sign(jobID: jobs[0].id, attributes: jobs[0].attributes, pin: "synthetic-fixture")
                Thread.sleep(forTimeInterval: idleLimit ? 0.5 : 1.7)
                XCTAssertThrowsError(try session.sign(jobID: jobs[1].id, attributes: jobs[1].attributes, pin: nil))
                XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), 1); XCTAssertEqual(count(mock, 16), 1)
            }
        }
    }
    func testTemporaryRawProtocolRejectsDifferentBatchJobAndSequence() throws {
        for change in 0..<3 {
            try fixture(always: true, temporary: true) { mock, unused in
                let start = unused.manifest
                let channel = try SupervisedWorkerChannel(executable: worker); defer { channel.abort() }
                let first = try channel.exchange(start, secret: "synthetic-fixture", timeout: 5, isCancelled: { false })
                XCTAssertTrue(first.reusable)
                let command = BatchWorkerCommand(version: 2, batchID: change == 0 ? UUID() : start.batchID,
                    jobID: change == 1 ? UUID() : start.jobs[1].id, index: change == 2 ? 2 : 1, finish: false)
                XCTAssertThrowsError(try channel.exchange(command, timeout: 2, isCancelled: { false }))
                XCTAssertEqual(count(mock, 16), 1); XCTAssertEqual(count(mock, 9), 1)
            }
        }
    }
    func testTemporaryNewBatchCannotUseThePreviousSecret() throws {
        try fixture(always: true, temporary: true) { mock, session in
            let first = session.manifest.jobs[0]
            _ = try session.sign(jobID: first.id, attributes: first.attributes, pin: "synthetic-fixture")
            try session.finish()
            let fresh = BatchSignatureConnection(manifest: session.manifest, executable: worker)
            XCTAssertThrowsError(try fresh.sign(jobID: first.id, attributes: first.attributes, pin: nil))
            XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 9), 1)
        }
    }

    func testTemporaryMemoryLockRefusalIsExplicitAndOccursBeforeProviderLogin() throws {
        try fixture(always: true, temporary: true) { mock, unused in
            let source = mock.folder.appendingPathComponent("limited-worker.c"), wrapper = mock.folder.appendingPathComponent("limited-worker")
            try """
            #include <sys/resource.h>
            #include <unistd.h>
            int main(int argc, char **argv) {
                struct rlimit limit = {0,0};
                if (setrlimit(RLIMIT_MEMLOCK, &limit)) return 3;
                execv(\(String(reflecting: worker.path)), argv);
                return 4;
            }
            """.write(to: source, atomically: false, encoding: .utf8)
            let cc = Process(); cc.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
            cc.arguments = [source.path, "-o", wrapper.path]; try cc.run(); cc.waitUntilExit(); XCTAssertEqual(cc.terminationStatus, 0)
            let session = BatchSignatureConnection(manifest: unused.manifest, executable: wrapper)
            let job = session.manifest.jobs[0]
            XCTAssertThrowsError(try session.sign(jobID: job.id, attributes: job.attributes, pin: "synthetic-fixture")) {
                XCTAssertTrue($0 is BatchSignatureConnection.Failure)
            }
            XCTAssertEqual(count(mock, 0), 0); XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0)
        }
    }

    func testTemporaryLostUSEROrRemovedTokenDoesNotReauthenticate() throws {
        for (phase, effect, after) in [(7, 6, 2), (16, 8, 1)] {
            try fixture(always: true, phase: phase, effect: effect, after: after, temporary: true) { mock, session in
                let jobs = session.manifest.jobs
                _ = try session.sign(jobID: jobs[0].id, attributes: jobs[0].attributes, pin: "synthetic-fixture")
                XCTAssertThrowsError(try session.sign(jobID: jobs[1].id, attributes: jobs[1].attributes, pin: nil))
                let calls = count(mock, 16)
                XCTAssertThrowsError(try session.sign(jobID: jobs[2].id, attributes: jobs[2].attributes, pin: nil))
                XCTAssertEqual(count(mock, 16), calls); XCTAssertEqual(count(mock, 8), 1)
            }
        }
    }
    func testTemporaryChangedModuleRetiresBeforeTheNextContextLogin() throws {
        try fixture(always: true, temporary: true) { mock, session in
            let jobs = session.manifest.jobs
            _ = try session.sign(jobID: jobs[0].id, attributes: jobs[0].attributes, pin: "synthetic-fixture")
            let handle = try FileHandle(forWritingTo: mock.path); try handle.seekToEnd(); try handle.write(contentsOf: Data([0])); try handle.close()
            XCTAssertThrowsError(try session.sign(jobID: jobs[1].id, attributes: jobs[1].attributes, pin: nil))
            XCTAssertEqual(count(mock, 9), 1); XCTAssertEqual(count(mock, 16), 1)
        }
    }
    func testTemporaryManifestRejectsEmbeddedPINAndInvalidLimits() throws {
        try fixture(temporary: true) { _, session in
            var m = session.manifest
            XCTAssertTrue(m.valid)
            m.pin = "synthetic-fixture"; XCTAssertFalse(m.valid); m.pin = nil
            m.pinLifetimeSeconds = 601; XCTAssertFalse(m.valid)
            m.pinLifetimeSeconds = 30; m.pinIdleSeconds = 61; XCTAssertFalse(m.valid)
        }
    }

}
#endif
