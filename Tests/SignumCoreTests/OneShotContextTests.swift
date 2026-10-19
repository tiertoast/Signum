#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore
@testable import SignumApp

final class OneShotContextTests: XCTestCase {
    private var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    func context(path: String, identity: MiddlewareFileIdentity, token: SignumToken, der: Data, objectID: Data = Data([1])) -> SigningProviderContext {
        .init(version: 1, provider: path, moduleIdentity: identity, automatic: false, token: token, objectID: objectID,
            certificateSHA256: DocumentSnapshot.digest(der), routeID: String(repeating: "a", count: 64), discoveryID: UUID())
    }
    func count(_ mock: MockModule, _ operation: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(operation) }.count
    }
    func testWorkerContextMismatchIsRejectedBeforeAuthenticationAtUnchangedDER() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false); defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root), mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let client = IsolatedPKCS11Client(executable: worker), token = try XCTUnwrap(client.scan(provider: inspected.canonicalPath).tokens.first)
        let good = context(path: inspected.canonicalPath, identity: inspected.identity, token: token, der: signer.der)
        let other = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let different = try MiddlewareFileSecurity.inspect(other.path.path, automatic: false)
        let changed = SignumToken(slot: 7, label: token.label, manufacturer: token.manufacturer, model: "changed", reader: token.reader, serial: token.serial)
        let wrongSlot = SignumToken(slot: 9, label: token.label, manufacturer: token.manufacturer, model: token.model, reader: token.reader, serial: token.serial)
        let metadataChanges = [
            SignumToken(slot: 7, label: "changed", manufacturer: token.manufacturer, model: token.model, reader: token.reader, serial: token.serial),
            SignumToken(slot: 7, label: token.label, manufacturer: "changed", model: token.model, reader: token.reader, serial: token.serial),
            SignumToken(slot: 7, label: token.label, manufacturer: token.manufacturer, model: token.model, reader: "changed", serial: token.serial),
            SignumToken(slot: 7, label: token.label, manufacturer: token.manufacturer, model: token.model, reader: token.reader, serial: "changed")
        ].map { context(path: inspected.canonicalPath, identity: inspected.identity, token: $0, der: signer.der) }
        let bad = metadataChanges + [context(path: inspected.canonicalPath, identity: inspected.identity, token: changed, der: signer.der),
            context(path: inspected.canonicalPath, identity: inspected.identity, token: wrongSlot, der: signer.der),
            context(path: inspected.canonicalPath, identity: different.identity, token: token, der: signer.der),
            context(path: different.canonicalPath, identity: different.identity, token: token, der: signer.der),
            context(path: inspected.canonicalPath, identity: inspected.identity, token: token, der: signer.der, objectID: Data([2]))]
        let prepared = try CAdES.Prepared(document: Data("Synthetic".utf8), certificateDER: signer.der)
        for context in bad {
            XCTAssertThrowsError(try client.sign(provider: inspected.canonicalPath, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der, attributes: prepared.attributesToSign,
                pin: "synthetic", id: UUID(), providerContext: context))
        }
        XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0)
        let signature = try client.sign(provider: inspected.canonicalPath, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: signer.der, attributes: prepared.attributesToSign,
            pin: "synthetic", id: UUID(), providerContext: good)
        XCTAssertEqual(signature.count, 256); XCTAssertEqual(count(mock, 8), 1); XCTAssertEqual(count(mock, 16), 1)
    }
    @MainActor func testBoundCAdESAndPAdESJobsVerifyAndPreserveOriginals() throws {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root), mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let client = IsolatedPKCS11Client(executable: worker), token = try XCTUnwrap(client.scan(provider: inspected.canonicalPath).tokens.first)
        let binding = context(path: inspected.canonicalPath, identity: inspected.identity, token: token, der: signer.der)
        for mode in 0...2 {
            let format: SigningFormat = mode == 0 ? .cades : .pades
            let bytes = mode == 0 ? Data("Synthetic approved content".utf8) : try PAdESAppearanceTests().pdf(rotation: 90, pages: 1)
            let file = root.appendingPathComponent("input-\(mode)." + (mode == 0 ? "txt" : "pdf")); try bytes.write(to: file)
            let snapshot = try DocumentSnapshot.capture(source: file, format: format, privateRoot: root)
            let appearance = mode == 2 ? try PAdESAppearanceRenderer.render(PAdESAppearanceTests().config(), certificateDER: signer.der, cropBox: PAdESAppearanceTests().crop, pageRotation: 90) : nil
            let job = try SigningJob(snapshot: snapshot, providerPath: binding.provider, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der,
                destination: root.appendingPathComponent("output-\(mode)." + (mode == 0 ? "p7m" : "pdf")), padesAppearance: appearance, providerContext: binding)
            XCTAssertEqual(job.providerContext, binding)
            if mode == 0 { try job.signCAdES(using: client, pin: "synthetic", operation: SigningOperation()) }
            else { try SignumPAdESHelper.sign(job: job, pin: "synthetic", appearanceName: "Synthetic", field: nil,
                executable: URL(fileURLWithPath: helper)) }
            if mode == 0 { XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, bytes) }
            else { XCTAssertTrue(try Data(contentsOf: job.destination).starts(with: bytes)) }
            XCTAssertEqual(try Data(contentsOf: file), bytes)
            XCTAssertThrowsError(try job.requireAvailableDestination())
        }
        XCTAssertEqual(count(mock, 8), 3); XCTAssertEqual(count(mock, 16), 3)
    }
    @MainActor func testPAdESBoundContextRejectsTokenChangesBeforeAuthentication() throws {
        let helper = try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"])
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root), mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let client = IsolatedPKCS11Client(executable: worker), token = try XCTUnwrap(client.scan(provider: inspected.canonicalPath).tokens.first)
        let changed = SignumToken(slot: 7, label: token.label, manufacturer: token.manufacturer, model: token.model, reader: token.reader, serial: "changed")
        let binding = context(path: inspected.canonicalPath, identity: inspected.identity, token: changed, der: signer.der)
        let input = root.appendingPathComponent("synthetic.pdf"); try PAdESAppearanceTests().pdf().write(to: input)
        let snapshot = try DocumentSnapshot.capture(source: input, format: .pades, privateRoot: root)
        let job = try SigningJob(snapshot: snapshot, providerPath: binding.provider, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der,
            destination: root.appendingPathComponent("output.pdf"), providerContext: binding)
        XCTAssertThrowsError(try SignumPAdESHelper.sign(job: job, pin: "synthetic", appearanceName: "Synthetic", field: nil,
            executable: URL(fileURLWithPath: helper))) { error in
            guard case SignumError.module = error else { return XCTFail("Pre-authentication rejection was not explicit: \(error)") }
        }
        XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path))
    }
    func testVersionTwoRequiresCompleteContextAndCannotSilentlyUseLegacyVersionOne() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid")
        var request = PKCS11WorkerRequest(version: 2, action: .rsaSHA256, provider: "/synthetic/provider", slot: 7,
            certificate: .init(.init(label: "Synthetic", identifier: Data([1])), der: der), attributes: Data([1]), pin: "synthetic")
        XCTAssertFalse(request.valid)
        let row = DeviceSelectionTests().provider(der: der)
        let route = try XCTUnwrap(DeviceCertificate.collect([row]).first?.routes.first)
        request.providerContext = route.signingContext(discoveryID: UUID())
        XCTAssertFalse(request.valid) // Provider and module fields still disagree.
        let binding = try XCTUnwrap(request.providerContext)
        var complete = PKCS11WorkerRequest(version: 2, action: .rsaSHA256, provider: binding.provider, slot: binding.token.slot,
            certificate: .init(route.certificate, der: der), attributes: Data([1]), pin: "synthetic")
        complete.providerContext = binding; complete.expectedModule = binding.moduleIdentity; complete.automaticModule = binding.automatic
        XCTAssertTrue(complete.valid)
        let encoded = try JSONEncoder().encode(complete)
        XCTAssertTrue(try JSONDecoder().decode(PKCS11WorkerRequest.self, from: encoded).valid)
        var legacy = PKCS11WorkerRequest(action: .rsaSHA256, provider: binding.provider, slot: binding.token.slot,
            certificate: .init(route.certificate, der: der), attributes: Data([1]), pin: "synthetic")
        legacy.providerContext = binding
        XCTAssertFalse(legacy.valid)
    }

    func testReplacedMiddlewareIsRejectedInWorkerBeforeInitializeOrAuthentication() throws {
        let der = try CertificateEligibilityTests.fixtures.get().der("valid"), mock = try MockModule(certificate: der, audit: true)
        let inspected = try MiddlewareFileSecurity.inspect(mock.path.path, automatic: false)
        let client = IsolatedPKCS11Client(executable: worker), token = try XCTUnwrap(client.scan(provider: inspected.canonicalPath).tokens.first)
        let binding = context(path: inspected.canonicalPath, identity: inspected.identity, token: token, der: der)
        try? FileManager.default.removeItem(at: mock.folder.appendingPathComponent("operations"))
        let replaced = mock.folder.appendingPathComponent("replacement")
        try Data("Synthetic replacement, never executable".utf8).write(to: replaced)
        XCTAssertEqual(rename(replaced.path, mock.path.path), 0)
        XCTAssertThrowsError(try client.sign(provider: inspected.canonicalPath, slot: 7,
            certificate: .init(label: "Synthetic", identifier: Data([1])), der: der, attributes: Data([1]),
            pin: "synthetic", id: UUID(), providerContext: binding)) { error in
            guard case IsolatedPKCS11Client.Failure.contextChanged = error else { return XCTFail("Missing explicit context rejection") }
        }
        XCTAssertEqual(count(mock, 0), 0); XCTAssertEqual(count(mock, 8), 0); XCTAssertEqual(count(mock, 16), 0)
    }

    @MainActor func testReviewFreezesObservedContextAndRejectsOldDiscoveryGeneration() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("synthetic.txt"); try Data("Synthetic approved".utf8).write(to: file)
        let der = try CertificateEligibilityTests.fixtures.get().der("valid"), row = DeviceSelectionTests().provider(der: der)
        var selection = DeviceSelection(); let old = selection.beginDiscovery(); let current = selection.beginDiscovery()
        XCTAssertFalse(selection.acceptCompleteFixture([row], request: old)); XCTAssertTrue(selection.acceptCompleteFixture([row], request: current))
        let route = try XCTUnwrap(selection.selectedRoute), binding = route.signingContext(discoveryID: current)
        let batch = BatchSigningCoordinator(); defer { batch.reset() }; await batch.addDocuments([file], format: .cades)
        let review = SigningReview()
        var context = SigningReviewContext(revision: batch.revision, provider: route.providerPath, slot: 7,
            certificate: route.certificate, der: der, destination: .originalFolders, routeID: route.id, discoveryID: current,
            providerContext: binding)
        await review.prepare(context, batch: batch, validate: {})
        let plan = try XCTUnwrap(review.approval); XCTAssertEqual(plan.jobs.first?.providerContext, binding)
        XCTAssertTrue(review.matches(context, batch: batch))
        context.providerContext = route.signingContext(discoveryID: UUID())
        XCTAssertFalse(review.matches(context, batch: batch))
        try batch.freezeReview(plan); try batch.confirm(plan)
        XCTAssertEqual(batch.approval?.jobs.first?.providerContext, binding)
        XCTAssertNotEqual(batch.approval?.jobs.first?.providerContext, context.providerContext)
    }

}
#endif
