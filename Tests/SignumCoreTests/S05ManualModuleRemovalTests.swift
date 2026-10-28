#if os(macOS)
import XCTest
import AppKit
import SwiftUI
import Combine
import Darwin
@testable import SignumCore
@testable import SignumApp

@MainActor final class S05ManualModuleRemovalTests: XCTestCase {
    struct Fixture {
        let root: URL, mock: MockModule, worker: IsolatedPKCS11Client
        let window: SignumWindow, controller: SignumMainWindowController, session: SigningWindowSession
        let batch: BatchSigningCoordinator, defaults: UserDefaults
        let paths: FixtureLocked<[[String]]>
    }
    func repeated(_ name: String = #function, _ body: () async throws -> Void) async throws {
        let n = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for i in 1...max(1,n) {
            let before = testRun?.failureCount ?? 0
            try await body()
            FileHandle.standardError.write(Data("PHASE3B_REPEAT \(name) iteration=\(i) failures=\((testRun?.failureCount ?? 0)-before)\n".utf8))
        }
    }
    func fixture(blocked: MockModule? = nil, late: S04WindowRevocationTests.Gate? = nil,
                 _ body: (Fixture) async throws -> Void) async throws {
        let root = try FixtureFiles.directory("s05-window"); defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, audit: true)
        let worker = IsolatedPKCS11Client(executable: Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
        let prepared = DeviceDiscoveryResult(providers: MiddlewareDiscovery(client: worker).discover(registry: [], manualPaths: [mock.path.path]), expectedPaths: [mock.path.path])
        XCTAssertEqual(prepared.certificates.count,1); XCTAssertTrue(prepared.isComplete)
        let suite = "Signum.S05."+UUID().uuidString, defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let source = root.appendingPathComponent("unsigned.txt"); try Data("S05 synthetic source".utf8).write(to: source)
        let batch = BatchSigningCoordinator(); await batch.addDocuments([source], format: .cades); defer { batch.reset() }
        let session = SigningWindowSession(), paths = FixtureLocked<[[String]]>([])
        var installed: SignumWindow?
        var view = SignumWindow(batch: batch, selectedSnapshot: batch.documents.first?.snapshot, automaticallyDiscover: false, defaults: defaults, session: session,
            sessionReady: { installed = $0 }, discoveryLoader: { input, cancelled in
                paths.withValue { $0.append(input) }
                if let blocked, input.contains(blocked.path.path) {
                    _ = MiddlewareDiscovery(client: worker).discover(registry: [], manualPaths: input, isCancelled: cancelled)
                    try? late?.enter() // Worker has returned; deliberately deliver an obsolete successful result.
                    return prepared
                }
                return DeviceDiscoveryResult(providers: MiddlewareDiscovery(client: worker).discover(registry: [], manualPaths: input, isCancelled: cancelled), expectedPaths: Set(input))
            }, worker: worker)
        view.systemDocuments = SystemDocuments()
        let appeared = expectation(description: "S05 production root appeared")
        let controller = SignumMainWindowController(content: AnyView(view.onAppear { appeared.fulfill() }), session: session)
        controller.showWindow(nil)
        let native = try XCTUnwrap(controller.window)
        defer { session.revoke(); native.close(); native.contentViewController = nil; controller.window = nil }
        await fulfillment(of: [appeared], timeout: 5)
        let fence = expectation(description: "S05 root installed")
        DispatchQueue.main.async { fence.fulfill() }; await fulfillment(of: [fence], timeout: 3)
        try await body(Fixture(root: root, mock: mock, worker: worker, window: try XCTUnwrap(installed), controller: controller, session: session, batch: batch, defaults: defaults, paths: paths))
    }
    func drain(_ f: Fixture) async {
        let done = expectation(description: "S05 owned discovery and review drained")
        f.session.whenDrained { done.fulfill() }; await fulfillment(of: [done], timeout: 15)
    }
    func discoverAndReview(_ f: Fixture) async {
        let ready = expectation(description: "S05 real discovery produced a bound review")
        var delivered = false
        let observation = f.window.review.$approval.sink { value in if value != nil && !delivered { delivered = true; ready.fulfill() } }
        f.window.discover(manual: f.mock.path.path)
        await fulfillment(of: [ready], timeout: 20); await drain(f)
        XCTAssertNotNil(f.window.devices.selectedRoute); XCTAssertNotNil(f.window.provider.signingProvider)
        XCTAssertTrue(f.window.canApproveBatch); XCTAssertNotNil(f.batch.review)
        withExtendedLifetime(observation) {}
    }
    func assertNoPrivateUse(_ f: Fixture) {
        let codes = ((try? String(contentsOf: f.mock.folder.appendingPathComponent("operations"))) ?? "").split(separator: "\n")
        XCTAssertFalse(codes.contains("8")); XCTAssertFalse(codes.contains("16"))
    }
    func testFixtureRealDiscoveryReviewAndOrdinaryRefreshWorkBeforeRemoval() async throws {
        try await repeated {
            try await fixture { f in
                await discoverAndReview(f)
                let old = f.window.devices.requestID
                f.window.discover(); XCTAssertNotEqual(f.window.devices.requestID,old)
                await drain(f)
                XCTAssertFalse(f.window.devices.isSearching); XCTAssertNil(f.window.refresh.requestID)
                XCTAssertNotNil(f.window.devices.selectedRoute)
                XCTAssertTrue(MiddlewarePreferences(defaults:f.defaults).paths.contains(f.mock.path.path))
                XCTAssertEqual(f.paths.withValue { $0 },[[f.mock.path.path],[f.mock.path.path]])
                assertNoPrivateUse(f)
            }
        }
    }
    func testRemovalAfterCompletedDiscoveryClearsSelectionConsentAndAllowsRefresh() async throws {
        try await repeated {
            try await fixture { f in
                await discoverAndReview(f)
                f.window.provider.pin = "synthetic-fixture"
                f.window.approvedRoute = f.window.devices.selectedRoute; f.window.approvedHolder = "obsolete consent"
                f.window.removeManualModule(f.mock.path.path)
                XCTAssertFalse(f.window.devices.isSearching)
                XCTAssertNil(f.window.devices.selectedRoute); XCTAssertNil(f.window.provider.signingProvider)
                XCTAssertTrue(f.window.provider.pin.isEmpty); XCTAssertTrue(f.window.provider.certificateDERs.isEmpty)
                XCTAssertNil(f.window.review.approval); XCTAssertNil(f.batch.review)
                XCTAssertNil(f.window.approvedRoute); XCTAssertTrue(f.window.approvedHolder.isEmpty)
                XCTAssertTrue(f.window.authorizedManualPaths.isEmpty)
                XCTAssertTrue(MiddlewarePreferences(defaults:f.defaults).paths.isEmpty)
                let invalidated = f.window.devices.requestID
                f.window.discover(); XCTAssertNotEqual(f.window.devices.requestID,invalidated)
                await drain(f)
                XCTAssertFalse(f.window.devices.isSearching); XCTAssertNil(f.window.refresh.requestID)
                XCTAssertTrue(f.window.devices.providers.isEmpty); XCTAssertEqual(f.paths.withValue { $0.last },[])
                assertNoPrivateUse(f)
            }
        }
    }
    func testFixtureExplicitCancellationOfBlockedDiscoveryReapsChild() async throws { try await blockedDiscovery(removing:false) }
    func testRemovalCancelsBlockedWorkerAndRejectsLateResultAfterNextRefresh() async throws { try await blockedDiscovery(removing:true) }
    private func blockedDiscovery(removing: Bool) async throws {
        try await repeated("blockedDiscovery(removing: \(removing))") {
            let blocked = try MockModule(workerPhase:0,workerEffect:2,audit:true)
            let file = blocked.folder.appendingPathComponent("operations"); try Data().write(to:file)
            let late = S04WindowRevocationTests.Gate(expectation(description:"cancelled public worker reaped before late completion")); defer { late.release() }
            try await fixture(blocked: blocked, late: late) { f in
                let reached = expectation(description:"removed provider entered Initialize"), once = FixtureLocked(false)
                let fd = open(file.path,O_EVTONLY); XCTAssertGreaterThanOrEqual(fd,0); guard fd >= 0 else { return }
                let watch = DispatchSource.makeFileSystemObjectSource(fileDescriptor:fd,eventMask:.write,queue:.global())
                watch.setEventHandler { if once.withValue({ flag in if flag { return false }; flag=true; return true }) { reached.fulfill() } }
                watch.setCancelHandler { Darwin.close(fd) }; watch.resume(); defer { watch.cancel() }
                f.window.discover(manual:blocked.path.path); await fulfillment(of:[reached],timeout:8)
                let operation = try XCTUnwrap(f.window.discoveryOperation)
                let pid = try XCTUnwrap((try? String(contentsOf:blocked.folder.appendingPathComponent("operations.pid"))).flatMap(Int32.init))
                if removing { f.window.removeManualModule(blocked.path.path) } else { f.controller.window?.close() }
                XCTAssertTrue(operation.isCancellationRequested)
                if !operation.isCancellationRequested { operation.requestCancellation() } // Drain the baseline red without waiting for a process timeout.
                await fulfillment(of:[late.reached],timeout:8)
                XCTAssertEqual(kill(pid,0),-1); XCTAssertEqual(errno,ESRCH)
                XCTAssertFalse(f.window.devices.isSearching); XCTAssertNil(f.window.refresh.requestID)
                let invalidated = f.window.devices.requestID
                if removing { f.window.discover(); XCTAssertNotEqual(f.window.devices.requestID,invalidated) }
                let current = f.window.devices.requestID
                late.release(); await drain(f)
                XCTAssertEqual(f.window.devices.requestID,current)
                XCTAssertFalse(f.window.devices.isSearching); XCTAssertTrue(f.window.devices.providers.isEmpty)
                XCTAssertNil(f.window.provider.signingProvider); XCTAssertNil(f.window.review.approval)
                if removing { XCTAssertEqual(f.paths.withValue { $0.last },[]) }; assertNoPrivateUse(f)
            }
        }
    }
    func testReopenDoesNotAuthorizeSavedManualModuleWithoutExplicitLoad() async throws {
        try await repeated {
            try await fixture { f in
                await discoverAndReview(f)
                XCTAssertTrue(MiddlewarePreferences(defaults:f.defaults).paths.contains(f.mock.path.path))
                f.controller.window?.close(); await drain(f)
                f.controller.showWindow(nil)
                let opened = expectation(description:"S05 explicit reopen delivered")
                DispatchQueue.main.async { opened.fulfill() }; await fulfillment(of:[opened],timeout:3)
                XCTAssertTrue(f.session.isActive); XCTAssertTrue(f.window.authorizedManualPaths.isEmpty)
                f.window.discover(); await drain(f)
                XCTAssertEqual(f.paths.withValue { $0 },[[f.mock.path.path],[]])
                XCTAssertTrue(f.window.devices.providers.isEmpty); XCTAssertNil(f.window.devices.selectedRoute)
                XCTAssertTrue(f.window.provider.pin.isEmpty); assertNoPrivateUse(f)
            }
        }
    }
}
#endif
