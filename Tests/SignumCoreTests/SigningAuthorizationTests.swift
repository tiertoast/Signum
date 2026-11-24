#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

/// The window's consent/PIN flow without UI. Synthetic PKCS#11 provider only.
@MainActor final class SigningAuthorizationTests: XCTestCase {
    private var workerURL: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    private func count(_ mock: MockModule, _ operation: Int) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(operation) }.count
    }
    private struct Fixture {
        let mock: MockModule, batch: BatchSigningCoordinator, route: DeviceCertificateRoute
        let worker: IsolatedPKCS11Client, interaction: SigningInteraction, authorization: SigningAuthorization
        let inputs: [Data]
    }
    /// Collects every task the flow hands to the window and awaits them, including
    /// the ones scheduled from a completion (continuation, retirement).
    private final class Owner {
        var tasks: [Task<Void, Never>] = [], statuses: [String] = [], signed = 0
        @MainActor func drain() async { var i = 0; while i < tasks.count { await tasks[i].value; i += 1 } }
    }
    private func hooks(_ owner: Owner, accepts: @escaping () -> Bool = { true }) -> SigningAuthorization.Hooks {
        .init(accepts: accepts, own: { owner.tasks.append($0) }, status: { owner.statuses.append($0) }, signed: { owner.signed += 1 })
    }

    private func fixture(phase: Int? = nil, effect: Int = 0, mode: BatchAuthenticationMode = .automatic,
                         _ body: (Fixture) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: phase, workerEffect: effect, audit: true)
        let worker = IsolatedPKCS11Client(executable: workerURL), modulePath = mock.path.path
        let providers = await Task.detached { MiddlewareDiscovery(client: worker).discover(registry: [], manualPaths: [modulePath]) }.value
        var selection = DeviceSelection(); let request = selection.beginDiscovery()
        XCTAssertTrue(selection.accept(providers, request: request, expectedPaths: [modulePath]))
        XCTAssertTrue(selection.select(routeID: selection.certificates.first?.routes.first?.id))
        let route = try XCTUnwrap(selection.selectedRoute)
        let inputs = [Data("Synthetic approved 1".utf8), Data("Synthetic approved 2".utf8)]
        let files = try inputs.enumerated().map { index, bytes -> URL in
            let url = root.appendingPathComponent("doc-\(index).txt"); try bytes.write(to: url); return url
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments(files, format: .cades)
        let plan = try await batch.prepareReview(provider: route.providerPath, slot: route.token.slot, certificate: route.certificate,
            der: route.der, destination: .originalFolders, providerContext: route.signingContext(discoveryID: selection.requestID))
        try batch.freezeReview(plan); try batch.confirm(plan)
        let authorization = SigningAuthorization()
        authorization.approved(holder: "Synthetic", route: route, mode: mode, formats: plan.jobs.map(\.format))
        try await body(Fixture(mock: mock, batch: batch, route: route, worker: worker, interaction: SigningInteraction(),
                               authorization: authorization, inputs: inputs))
        authorization.reset()
    }

    func testApprovalRecordsConsentAndExplainsTheSession() async throws {
        try await fixture { f in
            XCTAssertEqual(f.authorization.approvedHolder, "Synthetic")
            XCTAssertEqual(f.authorization.approvedRoute?.id, f.route.id)
            XCTAssertEqual(f.authorization.approvedMode, .automatic)
            XCTAssertFalse(f.authorization.attempted); XCTAssertFalse(f.authorization.notice.isEmpty)
            f.authorization.withdrawApproval()
            XCTAssertNil(f.authorization.approvedRoute); XCTAssertTrue(f.authorization.approvedHolder.isEmpty)
            var pin = "synthetic-fixture"
            XCTAssertFalse(f.authorization.authorizeNext(pin: &pin, batch: f.batch, interaction: f.interaction, worker: f.worker,
                                                        hooks: hooks(Owner())), "no consent, nothing starts")
            XCTAssertEqual(count(f.mock, 8), 0)
        }
    }

    func testOnePINSignsTheWholeApprovedBatch() async throws {
        try await fixture { f in
            let owner = Owner(); var pin = "synthetic-fixture"
            XCTAssertTrue(f.authorization.authorizeNext(pin: &pin, batch: f.batch, interaction: f.interaction, worker: f.worker, hooks: hooks(owner)))
            XCTAssertTrue(pin.isEmpty, "the field is cleared synchronously")
            XCTAssertTrue(f.authorization.attempted); XCTAssertNotNil(f.authorization.session)
            await owner.drain()
            XCTAssertEqual(f.batch.documents.map(\.state), [.completed, .completed])
            XCTAssertEqual(count(f.mock, 8), 1); XCTAssertEqual(count(f.mock, 16), 2)
            XCTAssertNil(f.authorization.session)
            XCTAssertEqual(f.authorization.notice, f.batch.authenticationNotice.isEmpty ? "Sessione autenticata conclusa." : f.batch.authenticationNotice)
            XCTAssertEqual(owner.statuses.last, SigningAuthorization.summary(f.batch))
            XCTAssertEqual(owner.signed, 2)
            for (index, document) in f.batch.documents.enumerated() {
                XCTAssertEqual(try CAdESVerifier.verify(file: try XCTUnwrap(document.destination)).originalDocument, f.inputs[index])
            }
        }
    }

    func testRefusedPINLetsTheNextPINOpenANewSession() async throws {
        try await fixture(phase: 8, effect: 10) { f in
            let owner = Owner(); var pin = "wrong-fixture"
            XCTAssertTrue(f.authorization.authorizeNext(pin: &pin, batch: f.batch, interaction: f.interaction, worker: f.worker, hooks: hooks(owner)))
            await owner.drain()
            XCTAssertEqual(count(f.mock, 16), 0)
            XCTAssertNil(f.authorization.session)
            XCTAssertFalse(f.authorization.attempted, "a new PIN may start a new session")
            XCTAssertTrue(f.authorization.notice.isEmpty, "the refusal is shown at the PIN field, not as a session notice")
            XCTAssertEqual(owner.statuses.last, SigningAuthenticationFailure.pinIncorrect.localizedDescription)
            XCTAssertEqual(f.batch.documents.first?.state, .waitingForAuthorization)
            XCTAssertFalse(f.batch.needsOutcomeReview)
        }
    }

    func testPerSignatureModeNeverOpensASession() async throws {
        try await fixture(mode: .perSignature) { f in
            let owner = Owner(); var pin = "synthetic-fixture"
            XCTAssertTrue(f.authorization.authorizeNext(pin: &pin, batch: f.batch, interaction: f.interaction, worker: f.worker, hooks: hooks(owner)))
            XCTAssertNil(f.authorization.session)
            await owner.drain()
            XCTAssertEqual(f.batch.documents.map(\.state), [.completed, .waitingForAuthorization])
            XCTAssertEqual(owner.statuses.last, "Consulta l'esito e inserisci il PIN per la firma successiva.")
        }
    }

    func testClosedWindowReceivesNoLateStatus() async throws {
        try await fixture { f in
            let owner = Owner(); var open = true, pin = "synthetic-fixture"
            XCTAssertTrue(f.authorization.authorizeNext(pin: &pin, batch: f.batch, interaction: f.interaction, worker: f.worker,
                                                        hooks: hooks(owner, accepts: { open })))
            open = false
            await owner.drain()
            XCTAssertTrue(owner.statuses.isEmpty); XCTAssertEqual(owner.signed, 0)
        }
    }

    func testTextsAndReset() {
        XCTAssertEqual(SigningAuthorization.continuingNotice(.temporaryPIN), "PIN temporaneo attivo soltanto per questo batch approvato.")
        XCTAssertEqual(SigningAuthorization.continuingNotice(.automatic), "Sessione autenticata per questo batch. Nessun PIN riutilizzato.")
        let authorization = SigningAuthorization()
        authorization.attempted = true; authorization.notice = "x"; authorization.approvedHolder = "y"
        authorization.clear()
        XCTAssertFalse(authorization.attempted); XCTAssertTrue(authorization.notice.isEmpty); XCTAssertTrue(authorization.approvedHolder.isEmpty)
    }
}
#endif
