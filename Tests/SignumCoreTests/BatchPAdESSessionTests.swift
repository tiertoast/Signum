#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

/// PDFs in an authenticated batch: one PIN, one worker session. The PDF helper
/// runs as a remote signer (no middleware, no PIN) and still verifies/publishes.
/// Synthetic PKCS#11 provider only. Needs SIGNUM_TEST_PADES_HELPER.
@MainActor final class BatchPAdESSessionTests: XCTestCase {
    private var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    private func count(_ mock: MockModule, _ operation: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(operation) }.count
    }
    private func pdf(_ size: CGSize = CGSize(width: 595, height: 842)) throws -> Data {
        let output = NSMutableData(); var box = CGRect(origin: .zero, size: size)
        let context = try XCTUnwrap(CGContext(consumer: try XCTUnwrap(CGDataConsumer(data: output as CFMutableData)), mediaBox: &box, nil))
        context.beginPDFPage(nil); context.endPDFPage(); context.closePDF(); return output as Data
    }
    private struct Fixture { let root: URL; let mock: MockModule; let batch: BatchSigningCoordinator; let plan: BatchApproval; let session: BatchCAdESSession; let inputs: [Data] }

    private func fixture(phase: Int? = nil, effect: Int = 0, _ body: (Fixture) async throws -> Void) async throws {
        let helper = URL(fileURLWithPath: try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"]))
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase, workerEffect: effect, audit: true)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let token = try XCTUnwrap(IsolatedPKCS11Client(executable: worker).scan(provider: inspected.canonicalPath).tokens.first)
        let binding = OneShotContextTests().context(path: inspected.canonicalPath, identity: inspected.identity, token: token, der: signer.der)
        // Mixed order on purpose: PDF first (its DigestInfo opens the session), then CAdES, then PDF.
        let inputs = [try pdf(), Data("Approved synthetic text".utf8), try pdf(CGSize(width: 842, height: 1191))]
        let names = ["first.pdf", "middle.txt", "last.pdf"]
        let files = try zip(names, inputs).map { name, bytes -> URL in let url = root.appendingPathComponent(name); try bytes.write(to: url); return url }
        let batch = BatchSigningCoordinator(padesHelper: helper); defer { batch.reset() }
        await batch.addDocuments([files[0]], format: .pades)
        await batch.addDocuments([files[1]], format: .cades)
        await batch.addDocuments([files[2]], format: .pades)
        // A visible stamp on the last PDF exercises the appearance frame in remote mode.
        let lastPage = try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data: inputs[2] as CFData)))?.page(at: 1))
        let geometry = try PAdESPageGeometry(page: lastPage)
        var config = try geometry.defaultAppearance(); config.showSigner = false; config.customText = "Synthetic"
        let appearance = try PAdESAppearanceRenderer.render(config, certificateDER: signer.der, cropBox: geometry.cropBox, pageRotation: geometry.rotation)
        let plan = try await batch.prepareReview(provider: binding.provider, slot: 7, certificate: .init(label: "Synthetic", identifier: Data([1])),
            der: signer.der, destination: .originalFolders, providerContext: binding, appearances: [batch.documents[2].id: appearance])
        try batch.freezeReview(plan); try batch.confirm(plan)
        XCTAssertTrue(BatchAuthenticationPolicy.canAttempt(jobs: plan.jobs, serial: token.serial, mode: .automatic))
        let session = try BatchCAdESSession(approval: plan, serial: token.serial, moduleIdentity: inspected.identity, executable: worker,
            padesRunner: { job, operation, remote in
                try SignumPAdESHelper.sign(job: job, pin: nil, appearanceName: "Synthetic", field: nil, operation: operation,
                                           executable: helper, appearance: job.padesAppearance, remoteSigner: remote)
            })
        do { try await body(Fixture(root: root, mock: mock, batch: batch, plan: plan, session: session, inputs: inputs)) }
        catch { await session.stopAndWait(); throw error }
        await session.stopAndWait()
    }

    func testMixedPDFAndCAdESBatchSignsEverythingWithOnePIN() async throws {
        try await fixture { f in
            try await f.batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                try f.session.sign(job: job, pin: pin, operation: operation)
            }
            XCTAssertTrue(f.session.canContinue)
            await f.batch.continueAuthenticatedBatch(using: f.session)
            XCTAssertEqual(f.batch.documents.map(\.state), [.completed, .completed, .completed])
            XCTAssertEqual(count(f.mock, 8), 1, "one USER login for the whole batch")
            XCTAssertEqual(count(f.mock, 16), 3, "exactly one C_Sign per document")
            for (index, job) in f.plan.jobs.enumerated() {
                let output = try Data(contentsOf: job.destination)
                if job.format == .pades {
                    XCTAssertTrue(output.starts(with: f.inputs[index]), "incremental update over the approved bytes")
                    XCTAssertNotNil(output.range(of: Data("/ByteRange".utf8)))
                } else {
                    XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, f.inputs[index])
                }
            }
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: f.root.path).contains { $0.hasPrefix(".signum-") })
        }
    }

    func testWrongPINOnFirstPDFIsAnOrdinaryRefusalWithoutSigning() async throws {
        try await fixture(phase: 8, effect: 10) { f in
            try await f.batch.authorizeNext(pin: "wrong-fixture") { job, pin, operation in
                try f.session.sign(job: job, pin: pin, operation: operation)
            }
            XCTAssertEqual(count(f.mock, 16), 0)
            XCTAssertFalse(f.batch.needsOutcomeReview)
            XCTAssertFalse(f.batch.documents[0].snapshot.isRetired, "same approved PDF, ready for a new PIN")
            XCTAssertEqual(f.batch.documents[0].state, .waitingForAuthorization)
            XCTAssertEqual(f.batch.documents[0].authenticationRefusal, .pinIncorrect)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.plan.jobs[0].destination.path))
            XCTAssertFalse(f.session.canContinue)
        }
    }
}
#endif
