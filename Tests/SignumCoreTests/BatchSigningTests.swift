#if os(macOS)
import XCTest
import Foundation
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

@MainActor final class BatchSigningTests: XCTestCase {
    private var worker: URL { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker") }
    private func fixture(_ body: (URL, SoftwareSigner, MockModule, BatchSigningCoordinator, [URL]) async throws -> Void) async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let signer = try SoftwareSigner(folder: root)
        let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
        let paths = (1...3).map { root.appendingPathComponent("synthetic-\($0).txt") }
        for (i, path) in paths.enumerated() { try Data("Approved synthetic document \(i)".utf8).write(to: path) }
        let coordinator = BatchSigningCoordinator(padesHelper: ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"].map { URL(fileURLWithPath: $0) })
        defer { coordinator.reset() }
        try await body(root, signer, mock, coordinator, paths)
    }
    private func approve(_ batch: BatchSigningCoordinator, root: URL, signer: SoftwareSigner, mock: MockModule) async throws -> BatchApproval {
        let approval = try await batch.prepareApproval(provider: mock.path.path, slot: 7,
            certificate: SignumCertificate(label: "Synthetic", identifier: Data([1])), der: signer.der, directory: root)
        try batch.confirm(approval)
        return approval
    }
    private func audit(_ mock: MockModule, _ code: String) -> Int {
        ((try? String(contentsOf: mock.folder.appendingPathComponent("operations"), encoding: .utf8)) ?? "")
            .split(separator: "\n").filter { $0 == code }.count
    }
    func testThreeCAdESRequireThreeExplicitAuthorizationsAndKeepApprovedBytes() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments(paths, format: .cades)
            let approvedData = batch.documents.map { $0.snapshot.approvedBytes }
            let approval = try await approve(batch, root: root, signer: signer, mock: mock)
            let identities = approval.jobs.map(\.snapshotIdentity), ids = approval.jobs.map(\.id)
            for path in paths { try Data("Changed AFTER approval".utf8).write(to: path) }
            await batch.addDocuments([signer.folder.appendingPathComponent("certificate.cnf")], format: .cades)
            XCTAssertEqual(batch.documents.count, 3)
            let worker = worker
            for i in 0..<3 {
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
                }
                XCTAssertEqual(batch.finishedCount, i + 1)
                XCTAssertEqual(audit(mock, "8"), i + 1)
                XCTAssertEqual(audit(mock, "16"), i + 1)
                XCTAssertEqual(batch.approval?.jobs.map(\.id), ids)
                XCTAssertEqual(batch.approval?.jobs.map(\.snapshotIdentity), identities)
                XCTAssertEqual(try CAdESVerifier.verify(file: approval.jobs[i].destination).originalDocument, approvedData[i])
            }
            XCTAssertTrue(batch.documents.allSatisfy { $0.state == .completed })
            XCTAssertTrue(batch.documents.allSatisfy { !FileManager.default.fileExists(atPath: $0.snapshot.fileURL.path) })
            XCTAssertTrue(batch.sessionReport.contains("Completato"))
        }
    }
    func testDuplicateRemovalOrderAndExistingDestinationAreSafe() async throws {
        try await fixture { root, signer, mock, batch, paths in
            let duplicate = root.appendingPathComponent("different-name.txt")
            try FileManager.default.copyItem(at: paths[0], to: duplicate)
            await batch.addDocuments([paths[0], paths[0], paths[1], duplicate, paths[2]], format: .cades)
            XCTAssertEqual(batch.documents.map { $0.snapshot.originalURL.lastPathComponent }, paths.map(\.lastPathComponent))
            XCTAssertEqual(batch.selectionIssues.count, 2)
            let removed = batch.documents[1].snapshot
            batch.remove(removed.identity.id)
            XCTAssertTrue(removed.isRetired)
            XCTAssertFalse(batch.documents.contains { $0.id == removed.identity.id })
            // Logical revocation is immediate; physical cleanup is intentionally off-main.
            let cleaned = expectation(for: NSPredicate { _, _ in !FileManager.default.fileExists(atPath: removed.fileURL.path) }, evaluatedWith: nil)
            await fulfillment(of: [cleaned], timeout: 5)
            XCTAssertFalse(FileManager.default.fileExists(atPath: removed.fileURL.path))
            let existing = root.appendingPathComponent(paths[0].lastPathComponent + ".p7m")
            try Data("PRESERVE".utf8).write(to: existing)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            XCTAssertNotEqual(plan.jobs[0].destination, existing)
            XCTAssertEqual(try String(contentsOf: existing), "PRESERVE")
            batch.remove(batch.documents[0].id)
            XCTAssertEqual(batch.documents.count, 2) // Frozen list cannot be edited.
        }
    }
    func testFailureOnSecondDoesNotAdvanceOrCorruptFirstOrThird() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments(paths, format: .cades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            let worker = worker
            try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
            }
            let first = try Data(contentsOf: plan.jobs[0].destination)
            try await batch.authorizeNext(pin: "synthetic-fixture") { job, _, _ in
                var io = SignumFileOutput.OutputIO()
                io.beforePublish = { throw SignumError.module("Synthetic pre-commit failure") }
                try job.executeCAdES(io: io) { try signer.cms(for: $0) }
            }
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .failed, .waitingForAuthorization])
            XCTAssertEqual(try Data(contentsOf: plan.jobs[0].destination), first)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[2].destination.path))
            XCTAssertEqual(audit(mock, "8"), 1)
            try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
            }
            XCTAssertEqual(batch.documents[2].state, .completed)
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.contains("staging") })
        }
    }
    func testCancellationDuringActiveJobCancelsOnlyPendingDocuments() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments(paths, format: .cades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            let worker = worker
            let task = Task { @MainActor in
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    Thread.sleep(forTimeInterval: 0.1)
                    try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
                }
            }
            let waitDeadline = ProcessInfo.processInfo.systemUptime+5
            while !batch.isRunning, ProcessInfo.processInfo.systemUptime < waitDeadline { await Task.yield() }
            XCTAssertTrue(batch.isRunning, "Timed out waiting for async fixture")
            batch.cancelPending()
            try await task.value
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .cancelled, .cancelled])
            XCTAssertEqual(audit(mock, "8"), 1)
            XCTAssertTrue(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[1].destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[2].destination.path))
            XCTAssertTrue(batch.documents.allSatisfy { !FileManager.default.fileExists(atPath: $0.snapshot.fileURL.path) })
        }
    }
    func testNewDestinationCollisionBeforeAuthenticationNeverInvokesSigner() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments(paths, format: .cades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            try Data("PRESERVE".utf8).write(to: plan.jobs[0].destination)
            try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in XCTFail("Must reject before private request") }
            XCTAssertEqual(batch.documents[0].state, .failed)
            XCTAssertEqual(try String(contentsOf: plan.jobs[0].destination), "PRESERVE")
            XCTAssertEqual(audit(mock, "8"), 0)
        }
    }
    func testUncertainOutcomeRequiresAcknowledgmentAndCannotRetrySameDocument() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments(paths, format: .cades)
            _ = try await approve(batch, root: root, signer: signer, mock: mock)
            try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in throw SignumError.outputUncertain("Synthetic interruption") }
            XCTAssertTrue(batch.needsOutcomeReview)
            do {
                try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in XCTFail("Automatic continuation") }
                XCTFail("Missing review gate")
            } catch { }
            batch.acknowledgeUncertainOutcome()
            XCTAssertEqual(batch.nextDocument?.id, batch.documents[1].id)
            batch.cancelDocument(batch.documents[1].id)
            XCTAssertEqual(batch.nextDocument?.id, batch.documents[2].id)
        }
    }
    func testMixedBatchUsesExistingNativePAdESAndWorkerCAdES() async throws {
        let helper = try FixtureRequirements.helper()
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments([paths[0]], format: .cades)
            let pdf = NSMutableData()
            let sink = try XCTUnwrap(CGDataConsumer(data: pdf as CFMutableData))
            var box = CGRect(x: 0, y: 0, width: 400, height: 500)
            let context = try XCTUnwrap(CGContext(consumer: sink, mediaBox: &box, nil))
            context.beginPDFPage(nil); context.endPDFPage(); context.closePDF()
            let path = root.appendingPathComponent("synthetic.pdf"); try (pdf as Data).write(to: path)
            await batch.addDocuments([path], format: .pades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock), worker = worker
            for _ in 0..<2 {
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    if job.format == .cades { try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation) }
                    else { try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: "Synthetic", field: nil, operation: operation, executable: URL(fileURLWithPath: helper)) }
                }
            }
            XCTAssertEqual(batch.documents.map(\.state), [.completed, .completed])
            XCTAssertEqual(audit(mock, "8"), 2); XCTAssertEqual(audit(mock, "16"), 2)
            XCTAssertTrue(plan.jobs.allSatisfy { FileManager.default.fileExists(atPath: $0.destination.path) })
        }
    }
    func testThreePAdESUseExplicitDiscoveredRouteAndImmutableApprovedPDFs() async throws {
        let helper = try FixtureRequirements.helper()
        try await fixture { root, _, mock, batch, _ in
            var paths: [URL] = [], approved: [Data] = []
            for index in 0..<3 {
                let bytes = NSMutableData()
                let consumer = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
                var box = CGRect(x: 0, y: 0, width: 400, height: 500)
                let context = try XCTUnwrap(CGContext(consumer: consumer, mediaBox: &box, nil))
                context.beginPDFPage(nil)
                context.setFillColor(CGColor(gray: CGFloat(index + 1) / 4, alpha: 1))
                context.fill(CGRect(x: 20, y: 20, width: 30 + index, height: 20))
                context.endPDFPage(); context.closePDF()
                let path = root.appendingPathComponent("approved-\(index).pdf")
                try (bytes as Data).write(to: path); paths.append(path); approved.append(bytes as Data)
            }
            await batch.addDocuments(paths, format: .pades)
            XCTAssertEqual(batch.documents.count, 3)
            let worker = worker, modulePath = mock.path.path
            let providers = await Task.detached {
                MiddlewareDiscovery(client: .init(executable: worker)).discover(registry: [], manualPaths: [modulePath])
            }.value
            var selection = DeviceSelection(); let request = selection.beginDiscovery()
            XCTAssertTrue(selection.accept(providers, request: request, expectedPaths:[modulePath])); XCTAssertEqual(selection.selectionOrigin,.automatic)
            XCTAssertTrue(selection.select(routeID: selection.certificates.first?.routes.first?.id))
            let route = try XCTUnwrap(selection.selectedRoute)
            let plan = try await batch.prepareApproval(provider: route.providerPath, slot: route.token.slot,
                certificate: route.certificate, der: route.der, directory: root)
            try batch.confirm(plan)
            let ids = plan.jobs.map(\.id), hashes = plan.jobs.map(\.contentSHA256)
            for path in paths { try Data("Changed after approval".utf8).write(to: path) }
            // A separate new discovery must not retarget already approved jobs.
            selection.beginDiscovery(); XCTAssertNil(selection.selectedRoute)
            for index in 0..<3 {
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    try route.requireCurrentModule()
                    try SignumPAdESHelper.sign(job: job, pin: pin, appearanceName: "Synthetic", field: nil,
                        operation: operation, executable: URL(fileURLWithPath: helper))
                }
                XCTAssertEqual(batch.finishedCount, index + 1)
                XCTAssertEqual(audit(mock, "8"), index + 1); XCTAssertEqual(audit(mock, "16"), index + 1)
                XCTAssertEqual(batch.approval?.jobs.map(\.id), ids); XCTAssertEqual(batch.approval?.jobs.map(\.contentSHA256), hashes)
                let signed = try Data(contentsOf: plan.jobs[index].destination)
                XCTAssertTrue(signed.starts(with: approved[index])) // Verified incremental PAdES over approved bytes.
                XCTAssertEqual(plan.jobs[index].providerPath, route.providerPath)
                XCTAssertEqual(plan.jobs[index].certificateDER, route.der)
            }
            XCTAssertEqual(audit(mock, "10"), 0) // No indiscriminate Logout.
            XCTAssertTrue(batch.documents.allSatisfy { $0.state == .completed })
            XCTAssertTrue(batch.documents.allSatisfy { !FileManager.default.fileExists(atPath: $0.snapshot.fileURL.path) })
            for path in paths { XCTAssertEqual(try Data(contentsOf: path), Data("Changed after approval".utf8)) }
        }
    }
    func testDropCallbacksKeepOrderAndIgnoreLateOrDuplicateReplies() {
        let collected = FixtureLocked<[[URL]]>([])
        let state = FileDropResolution(count: 3) { urls in collected.withValue { $0.append(urls) } }
        let a = URL(fileURLWithPath: "/synthetic/a"), b = URL(fileURLWithPath: "/synthetic/b")
        state.receive(index: 1, url: b); state.receive(index: 0, url: a)
        state.receive(index: 0, url: URL(fileURLWithPath: "/ignored")); state.finish()
        state.receive(index: 2, url: URL(fileURLWithPath: "/late")); state.finish()
        XCTAssertEqual(collected.withValue { $0 }, [[a, b]])
    }
    func testSelectionBoundAndDeclinedApprovalRemainEditableWithoutAuthentication() async throws {
        try await fixture { root, signer, mock, batch, _ in
            let paths = (0..<34).map { root.appendingPathComponent("bounded-\($0).txt") }
            for (i, path) in paths.enumerated() { try Data("Unique synthetic \(i)".utf8).write(to: path) }
            await batch.addDocuments(paths, format: .cades)
            XCTAssertEqual(batch.documents.count, 32); XCTAssertFalse(batch.selectionIssues.isEmpty)
            let approval = try await batch.prepareApproval(provider: mock.path.path, slot: 7,
                certificate: SignumCertificate(label: "Synthetic", identifier: Data([1])), der: signer.der, directory: root)
            XCTAssertTrue(batch.isFrozen)
            batch.declineApproval()
            XCTAssertFalse(batch.isFrozen); XCTAssertFalse(batch.isApproved)
            do { try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in XCTFail("No batch approval") }; XCTFail("Unapproved signing") } catch { }
            XCTAssertEqual(audit(mock, "8"), 0)
            batch.remove(batch.documents[0].id)
            XCTAssertEqual(batch.documents.count, 31)
            XCTAssertTrue(approval.jobs.allSatisfy { !FileManager.default.fileExists(atPath: $0.destination.path) })
        }
    }
    func testEqualBasenamesGetDistinctFrozenDestinations() async throws {
        try await fixture { root, signer, mock, batch, _ in
            var files: [URL] = []
            for name in ["one", "two"] {
                let dir = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
                let file = dir.appendingPathComponent("same.txt")
                try Data(name.utf8).write(to: file); files.append(file)
            }
            await batch.addDocuments(files, format: .cades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            XCTAssertEqual(plan.jobs.map { $0.destination.lastPathComponent }, ["same.txt.p7m", "same (2).txt.p7m"])
            XCTAssertEqual(plan.jobs.map(\.snapshotIdentity.id), batch.documents.map(\.id))
        }
    }
    func testExecutorReturnAloneIsNotAConfirmedPublication() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments([paths[0]], format: .cades)
            let plan = try await approve(batch, root: root, signer: signer, mock: mock)
            try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in /* no confirmed publication */ }
            XCTAssertEqual(batch.documents[0].state, .uncertain)
            XCTAssertTrue(batch.needsOutcomeReview)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plan.jobs[0].destination.path))
            XCTAssertEqual(audit(mock, "8"), 0)
        }
    }
    func testEmptyAuthorizationAndConcurrentSecondRequestNeverAuthenticate() async throws {
        try await fixture { root, signer, mock, batch, paths in
            await batch.addDocuments([paths[0]], format: .cades)
            _ = try await approve(batch, root: root, signer: signer, mock: mock)
            do { try await batch.authorizeNext(pin: "") { _, _, _ in XCTFail("Empty authorization") }; XCTFail("Empty authorization accepted") } catch { }
            XCTAssertEqual(audit(mock, "8"), 0)
            let worker = worker
            let first = Task { @MainActor in
                try await batch.authorizeNext(pin: "synthetic-fixture") { job, pin, operation in
                    Thread.sleep(forTimeInterval: 0.1)
                    try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: pin, operation: operation)
                }
            }
            let waitDeadline = ProcessInfo.processInfo.systemUptime+5
            while !batch.isRunning, ProcessInfo.processInfo.systemUptime < waitDeadline { await Task.yield() }
            XCTAssertTrue(batch.isRunning, "Timed out waiting for async fixture")
            do { try await batch.authorizeNext(pin: "synthetic-fixture") { _, _, _ in XCTFail("Concurrent private request") }; XCTFail("Concurrent request accepted") } catch { }
            try await first.value
            XCTAssertEqual(batch.documents[0].state, .completed)
            XCTAssertEqual(audit(mock, "8"), 1); XCTAssertEqual(audit(mock, "16"), 1)
        }
    }
}
#endif
