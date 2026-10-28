#if os(macOS)
import XCTest
import SwiftUI
import AppKit
import Darwin
@testable import SignumCore
@testable import SignumApp

@MainActor final class S04WindowRevocationTests: XCTestCase {
    enum Route: String, CaseIterable { case close, performClose, replaceRoot, replaceWindow }
    final class Gate: @unchecked Sendable {
        let reached: XCTestExpectation
        private let condition = NSCondition(); private var released = false
        init(_ reached: XCTestExpectation) { self.reached = reached }
        func enter() throws {
            condition.lock(); defer { condition.unlock() }; reached.fulfill()
            let deadline = Date().addingTimeInterval(15)
            while !released { guard condition.wait(until: deadline) else { throw SupervisedProcess.Failure.timeout } }
        }
        func release() { condition.lock(); released = true; condition.broadcast(); condition.unlock() }
    }
    struct Fixture {
        let root: URL, mock: MockModule, worker: IsolatedPKCS11Client
        let batch: BatchSigningCoordinator, results: SigningSessionResults, workspace: SigningWorkspaceSelection
        let controller: SignumMainWindowController, defaults: UserDefaults
        let plan: BatchApproval?
    }
    func repeated(_ name: String = #function, _ body: () async throws -> Void) async throws {
        let repetitions = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1,repetitions) {
            let failures = testRun?.failureCount ?? 0
            try await body()
            let record = "PHASE3B_REPEAT \(name) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-failures)\n"
            FileHandle.standardError.write(Data(record.utf8))
        }
    }
    func fixture(approved: Bool = true, blocked: Bool = false, _ body: (Fixture) async throws -> Void) async throws {
        let root = try FixtureFiles.directory("s04-window")
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), workerPhase: blocked ? 16 : nil, workerEffect: blocked ? 2 : 0, audit: true)
        let worker = IsolatedPKCS11Client(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
        let certificate = try XCTUnwrap(worker.certificates(provider: mock.path.path, slot: 7).first)
        try CertificateEligibility.requireEligible(certificateDER: certificate.der)
        let files = try (1...3).map { index -> URL in
            let file = root.appendingPathComponent("source-\(index).txt"); try Data("Synthetic approved \(index)".utf8).write(to: file); return file
        }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        await batch.addDocuments(files, format: .cades)
        var plan: BatchApproval?
        if approved {
            plan = try await batch.prepareApproval(provider: mock.path.path, slot: 7, certificate: certificate.certificate, der: certificate.der)
            try batch.confirm(XCTUnwrap(plan))
        }
        let suite = "Signum.S04."+UUID().uuidString, defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let results = SigningSessionResults(), workspace = SigningWorkspaceSelection(snapshot: batch.documents[0].snapshot, format: .cades)
        let appeared = expectation(description: "installed production root appeared")
        let view = SignumWindow(batch: batch, selectedSnapshot: batch.documents[0].snapshot, automaticallyDiscover: false, defaults: defaults, workspace: workspace, sessionResults: results).onAppear { appeared.fulfill() }
        let controller = SignumMainWindowController(content: AnyView(view))
        controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil)
        let originalWindow = try XCTUnwrap(controller.window)
        defer { originalWindow.close(); originalWindow.contentViewController = nil; controller.window = nil }
        await fulfillment(of: [appeared], timeout: 5)
        controller.contentHost.view.layoutSubtreeIfNeeded()
        let settled = expectation(description: "native representable installed")
        DispatchQueue.main.async { settled.fulfill() }; await fulfillment(of: [settled], timeout: 3)
        let toolbar = try XCTUnwrap(controller.window?.toolbar)
        XCTAssertEqual(try XCTUnwrap(toolbar.items.first { $0.itemIdentifier.rawValue == "signum.settings" }).isEnabled, !approved, "Mounted root observes the SAME injected batch")
        try await body(Fixture(root: root, mock: mock, worker: worker, batch: batch, results: results, workspace: workspace, controller: controller, defaults: defaults, plan: plan))
    }
    func close(_ route: Route, _ fixture: Fixture) async {
        switch route {
        case .close: fixture.controller.window?.close()
        case .performClose: fixture.controller.window?.performClose(nil)
        case .replaceRoot: fixture.controller.contentHost.rootView = AnyView(Text("Replacement"))
        case .replaceWindow: fixture.controller.window = nil
        }
        let fence = expectation(description: "native lifecycle delivered")
        DispatchQueue.main.async { fence.fulfill() }; await fulfillment(of: [fence], timeout: 3)
    }
    func count(_ fixture: Fixture, _ operation: Int) -> Int {
        ((try? String(contentsOf: fixture.mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n").filter { $0 == String(operation) }.count
    }
    func states(_ fixture: Fixture) -> [BatchDocumentState] {
        fixture.batch.documents.isEmpty ? fixture.results.receipts.map(\.state) : fixture.batch.documents.map(\.state)
    }
    func testFixtureMountedRootUsesApprovedBatchAndVerifiableSoftwareSigner() async throws {
        try await repeated {
            try await fixture { f in
                let worker = f.worker
                try await f.batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in try job.signCAdES(using: worker, pin: pin, operation: operation) }
                XCTAssertEqual(try CAdESVerifier.verify(file: XCTUnwrap(f.plan).jobs[0].destination).originalDocument, Data("Synthetic approved 1".utf8))
                XCTAssertEqual(states(f), [.completed,.waitingForAuthorization,.pending])
                XCTAssertEqual(count(f,8),1); XCTAssertEqual(count(f,16),1); f.batch.cancelPending()
            }
        }
    }
    func testNativeClosureMatrixCancelsPendingSelection() async throws {
        try await repeated {
            for route in Route.allCases {
                try await fixture(approved: false) { f in
                    await close(route,f)
                    XCTAssertEqual(states(f),[.cancelled,.cancelled,.cancelled],route.rawValue)
                    XCTAssertNil(f.workspace.snapshot,route.rawValue)
                    XCTAssertEqual(count(f,8),0); XCTAssertEqual(count(f,16),0)
                    f.batch.cancelPending()
                }
            }
        }
    }
    func testNativeClosureMatrixBeforePrivateRequest() async throws {
        try await repeated {
            for route in Route.allCases {
                try await fixture { f in
                    let gate = Gate(expectation(description: "pre-private checkpoint")); defer { gate.release() }
                    let op = FixtureLocked<SigningOperation?>(nil)
                    let task = Task { try await f.batch.authorizeNext(pin: "synthetic-fixture") { _,_,operation in
                        op.withValue { $0 = operation }; try gate.enter(); try operation.checkCancellation()
                        throw SignumError.module("Uncancelled fixture reached execution")
                    } }
                    await fulfillment(of: [gate.reached], timeout: 5)
                    await close(route,f)
                    XCTAssertTrue(op.withValue { $0?.isCancellationRequested == true },route.rawValue)
                    if op.withValue({ $0?.isCancellationRequested != true }) { f.batch.cancelAll() } // red-only drain
                    gate.release(); try await task.value
                    XCTAssertEqual(states(f),[.cancelled,.cancelled,.cancelled],route.rawValue)
                    XCTAssertEqual(count(f,8),0); XCTAssertEqual(count(f,16),0)
                    f.batch.cancelPending()
                }
            }
        }
    }
    func testNativeClosureMatrixPreservesConfirmedPublication() async throws {
        try await repeated {
            for route in Route.allCases {
                try await fixture { f in
                    let gate = Gate(expectation(description: "confirmed publication")); defer { gate.release() }
                    let worker = f.worker
                    let task = Task { try await f.batch.authorizeNext(pin: "synthetic-fixture") { job,pin,operation in
                        try job.signCAdES(using:worker,pin:pin,operation:operation); try gate.enter()
                    } }
                    await fulfillment(of: [gate.reached],timeout:5); await close(route,f)
                    gate.release(); try await task.value
                    XCTAssertEqual(states(f),[.completed,.cancelled,.cancelled],route.rawValue)
                    XCTAssertEqual(try CAdESVerifier.verify(file: XCTUnwrap(f.plan).jobs[0].destination).originalDocument,Data("Synthetic approved 1".utf8))
                    XCTAssertEqual(count(f,16),1); XCTAssertFalse(f.batch.needsOutcomeReview); f.batch.cancelPending()
                }
            }
        }
    }
    func testFixtureExplicitCancellationTerminatesBlockedWorker() async throws { try await blockedWorker(native: false) }
    func testNativeCloseInsideSignReapsWorkerAndNeverContinues() async throws { try await blockedWorker(native: true) }
    private func blockedWorker(native: Bool) async throws {
        try await repeated("blockedWorker(native: \(native))") {
            try await fixture(blocked: true) { f in
                let file = f.mock.folder.appendingPathComponent("operations"), fd = open(f.mock.folder.appendingPathComponent("operations").path,O_EVTONLY)
                XCTAssertGreaterThanOrEqual(fd,0); guard fd >= 0 else { return }
                let reached = expectation(description: "worker entered private C_Sign"), delivered = FixtureLocked(false)
                let watch = DispatchSource.makeFileSystemObjectSource(fileDescriptor:fd,eventMask:.write,queue:.global())
                watch.setEventHandler {
                    if ((try? String(contentsOf:file)) ?? "").split(separator:"\n").contains("16"), delivered.withValue({ value in if value { return false }; value=true; return true }) { reached.fulfill() }
                }
                watch.setCancelHandler { Darwin.close(fd) }; watch.resume(); defer { watch.cancel() }
                let worker=f.worker
                let task=Task { try await f.batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in try job.signCAdES(using:worker,pin:pin,operation:operation,timeout:5) } }
                await fulfillment(of:[reached],timeout:8)
                let pid=try XCTUnwrap((try? String(contentsOf:f.mock.folder.appendingPathComponent("operations.pid"))).flatMap(Int32.init))
                if native { await close(.close,f) } else { f.batch.cancelAll() }
                XCTAssertTrue(f.batch.activeOperation?.isCancellationRequested == true)
                if f.batch.activeOperation?.isCancellationRequested != true { f.batch.cancelAll() }
                try await task.value
                XCTAssertEqual(kill(pid,0),-1); XCTAssertEqual(errno,ESRCH)
                XCTAssertTrue(f.batch.needsOutcomeReview); XCTAssertEqual(states(f),[.uncertain,.cancelled,.cancelled])
                XCTAssertEqual(count(f,8),1); XCTAssertEqual(count(f,16),1)
                XCTAssertFalse(try XCTUnwrap(f.plan).jobs.contains { FileManager.default.fileExists(atPath:$0.destination.path) })
                f.batch.cancelPending()
            }
        }
    }
}
#endif
