#if os(macOS)
import XCTest
import AppKit
import Combine
import UniformTypeIdentifiers
import Darwin
@testable import SignumCore
@testable import SignumApp

extension S04WindowRevocationTests {
    func drained(_ session: SigningWindowSession) async {
        let done = expectation(description: "all session work drained")
        session.whenDrained { done.fulfill() }
        await fulfillment(of: [done],timeout:10)
    }
    func testTerminationDeadlineIsBoundedAndRepliesOnlyOnce() async throws {
        try await repeated {
            try await fixture { f in
                let gate = Gate(expectation(description:"pre-private shutdown checkpoint")); defer { gate.release() }
                let task = Task { try await f.batch.authorizeNext(pin:"synthetic-fixture") { _,_,operation in
                    try gate.enter(); try operation.checkCancellation()
                } }
                await fulfillment(of:[gate.reached],timeout:5)
                var deadline: (@MainActor () -> Void)?, replies: [Bool] = []
                let delegate = SignumLifecycle(controller:f.controller,reply:{ replies.append($0) },scheduleDeadline:{ deadline = $0 })
                XCTAssertEqual(SignumLifecycle.terminationGrace,2)
                XCTAssertEqual(delegate.applicationShouldTerminate(NSApplication.shared),.terminateLater)
                XCTAssertTrue(f.batch.activeOperation?.isCancellationRequested == true)
                XCTAssertTrue(replies.isEmpty); XCTAssertFalse(f.session.isDrained)
                let generation = f.session.generation
                try XCTUnwrap(deadline)(); try XCTUnwrap(deadline)()
                delegate.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification))
                XCTAssertEqual(replies,[true]); XCTAssertEqual(f.session.generation,generation)
                gate.release(); try await task.value; await drained(f.session)
                XCTAssertEqual(replies,[true]); XCTAssertEqual(count(f,8),0); XCTAssertEqual(count(f,16),0)
            }
        }
    }
    func testReopenHasNoOldPINConsentOrAuthorizedManualPath() async throws {
        try await repeated {
            try await fixture(approved:false) { f in
                f.installed.provider.pin = "synthetic-fixture"
                f.installed.approvedHolder = "stale synthetic consent"
                f.installed.authorizedManualPaths = [f.mock.path.path]
                let generation = f.session.generation
                await close(.close,f); await drained(f.session)
                XCTAssertFalse(f.session.accepts(generation)); XCTAssertTrue(f.installed.provider.pin.isEmpty)
                XCTAssertNil(f.installed.approvedRoute); XCTAssertTrue(f.installed.approvedHolder.isEmpty)
                let countBefore = f.batch.documents.count
                f.installed.addDocuments([f.root.appendingPathComponent("late.txt")])
                XCTAssertEqual(f.batch.documents.count,countBefore)
                f.controller.showWindow(nil); f.controller.window?.makeKeyAndOrderFront(nil)
                let opened = expectation(description:"native reopen delivered")
                DispatchQueue.main.async { opened.fulfill() }; await fulfillment(of:[opened],timeout:3)
                XCTAssertTrue(f.session.isActive); XCTAssertTrue(f.installed.provider.pin.isEmpty)
                XCTAssertTrue(f.installed.authorizedManualPaths.isEmpty)
                XCTAssertFalse(f.installed.canApproveBatch); XCTAssertFalse(f.installed.canAuthorizeNext)
                XCTAssertFalse(f.session.accepts(generation)); XCTAssertEqual(count(f,16),0)
            }
        }
    }
    func testClosureMatrixCancelsActualNativeDropAndRejectsLateDelivery() async throws {
        try await repeated {
            for route in Route.allCases {
                try await fixture(approved:false) { f in
                    let ready = expectation(description:"native item provider registered"), deferred = DeferredDrop()
                    let item = NSItemProvider()
                    item.registerDataRepresentation(forTypeIdentifier:UTType.fileURL.identifier,visibility:.all) { callback in
                        deferred.install(callback); ready.fulfill(); return nil
                    }
                    XCTAssertTrue(f.installed.receiveDrop([item]))
                    await fulfillment(of:[ready],timeout:5)
                    await close(route,f); await drained(f.session)
                    let status = f.installed.status
                    deferred.finish()
                    let delivered = expectation(description:"late callback processed")
                    DispatchQueue.main.async { delivered.fulfill() }; await fulfillment(of:[delivered],timeout:3)
                    XCTAssertFalse(f.installed.busy); XCTAssertEqual(f.installed.status,status)
                    XCTAssertEqual(states(f),[.cancelled,.cancelled,.cancelled]); XCTAssertNil(f.workspace.snapshot)
                    XCTAssertEqual(count(f,8),0); XCTAssertEqual(count(f,16),0)
                }
            }
        }
    }
    func testClosureMatrixRetiresLateCapturedArtifact() async throws {
        try await repeated {
            for route in Route.allCases {
                let gate = Gate(expectation(description:"fourth snapshot already captured")); defer { gate.release() }
                let captured = FixtureLocked<(DocumentSnapshot,SigningOperation)?>(nil)
                try await fixture(approved:false,capture:{ url,format,operation in
                    let snapshot = try DocumentSnapshot.capture(source:url,format:format,isCancelled:{ operation.isCancellationRequested })
                    if url.lastPathComponent == "fourth.txt" { captured.withValue { $0 = (snapshot,operation) }; try gate.enter() }
                    return snapshot
                }) { f in
                    let file=f.root.appendingPathComponent("fourth.txt"); try Data("Late synthetic capture".utf8).write(to:file)
                    f.installed.addDocuments([file]); await fulfillment(of:[gate.reached],timeout:5)
                    let value=try XCTUnwrap(captured.withValue { $0 })
                    let removed=expectation(description:"revoked snapshot unlinked"), fd=open(value.0.fileURL.path,O_EVTONLY)
                    XCTAssertGreaterThanOrEqual(fd,0); guard fd >= 0 else { return }
                    let watch=DispatchSource.makeFileSystemObjectSource(fileDescriptor:fd,eventMask:.delete,queue:.global())
                    watch.setEventHandler { removed.fulfill() }; watch.setCancelHandler { Darwin.close(fd) }; watch.resume(); defer { watch.cancel() }
                    await close(route,f); XCTAssertTrue(value.1.isCancellationRequested)
                    gate.release(); await drained(f.session); await fulfillment(of:[removed],timeout:5)
                    XCTAssertTrue(value.0.isRetired); XCTAssertFalse(FileManager.default.fileExists(atPath:value.0.fileURL.path))
                    XCTAssertEqual(states(f),[.cancelled,.cancelled,.cancelled]); XCTAssertNil(f.workspace.snapshot)
                    XCTAssertEqual(count(f,16),0)
                }
            }
        }
    }
    func testClosureMatrixReapsBlockedDiscoveryAndDiscardsItsCompletion() async throws {
        try await repeated {
            let blocked = try MockModule(workerPhase:0,workerEffect:2,audit:true)
            let file = blocked.folder.appendingPathComponent("operations"); try Data().write(to:file)
            for route in Route.allCases {
                try await fixture(approved:false) { f in
                    // A new child writes its PID before auditing Initialize.
                    let ready=expectation(description:"public worker entered Initialize"), fd=open(file.path,O_EVTONLY)
                    let once=FixtureLocked(false)
                    let watch=DispatchSource.makeFileSystemObjectSource(fileDescriptor:fd,eventMask:.write,queue:.global())
                    watch.setEventHandler { if once.withValue({ flag in if flag { return false }; flag=true; return true }) { ready.fulfill() } }
                    watch.setCancelHandler { Darwin.close(fd) }; watch.resume(); defer { watch.cancel() }
                    f.installed.discover(manual:blocked.path.path); await fulfillment(of:[ready],timeout:8)
                    let pid=try XCTUnwrap((try? String(contentsOf:blocked.folder.appendingPathComponent("operations.pid"))).flatMap(Int32.init))
                    await close(route,f); await drained(f.session)
                    XCTAssertEqual(kill(pid,0),-1); XCTAssertEqual(errno,ESRCH)
                    XCTAssertFalse(f.installed.devices.isSearching); XCTAssertTrue(f.installed.devices.providers.isEmpty)
                    XCTAssertNil(f.installed.provider.signingProvider); XCTAssertTrue(f.installed.provider.pin.isEmpty)
                    XCTAssertTrue(f.installed.authorizedManualPaths.isEmpty); XCTAssertEqual(count(f,16),0)
                }
            }
        }
    }
    func testClosureMatrixCancelsInstalledReviewBeforeApproval() async throws {
        try await repeated {
            for route in Route.allCases {
                try await fixture(approved:false) { f in
                    let gate=Gate(expectation(description:"actual review validation checkpoint")); defer { gate.release() }
                    let operation=FixtureLocked<SigningOperation?>(nil)
                    let context=SigningReviewContext(revision:f.batch.revision,provider:f.mock.path.path,slot:7,certificate:f.certificate,der:f.der,destination:.originalFolders,routeID:"synthetic",discoveryID:UUID())
                    let task=Task { await f.installed.review.prepare(context,batch:f.batch,validateCancellable:{ control in
                        operation.withValue { $0=control }; try gate.enter(); try control.checkCancellation()
                    }) }
                    f.session.own(task); await fulfillment(of:[gate.reached],timeout:5)
                    await close(route,f); XCTAssertTrue(operation.withValue { $0?.isCancellationRequested == true })
                    gate.release(); await drained(f.session)
                    XCTAssertNil(f.installed.review.approval); XCTAssertNil(f.batch.review)
                    XCTAssertFalse(f.installed.canApproveBatch); XCTAssertEqual(count(f,16),0)
                }
            }
        }
    }
    func testClosureMatrixCancelsRealPaneAppearanceAndRejectsReady() async throws {
        try await repeated {
            for route in Route.allCases {
                let gate=Gate(expectation(description:"real pane's renderer entered")); defer { gate.release() }
                let cancellation=FixtureLocked(false)
                let renderer=PAdESRenderCoordinator(renderer:{ _,_,_,cancelled in
                    try gate.enter(); cancellation.withValue { $0=cancelled() }; throw CancellationError()
                })
                try await fixture(approved:false,format:.pades,renderer:renderer) { f in
                    await fulfillment(of:[gate.reached],timeout:8)
                    XCTAssertTrue(f.installed.appearanceRenderer === renderer)
                    await close(route,f); gate.release(); await drained(f.session)
                    XCTAssertTrue(cancellation.withValue { $0 }); XCTAssertTrue(renderer.isIdle)
                    XCTAssertEqual(renderer.published,0); XCTAssertTrue(f.installed.readyPreviews.isEmpty)
                    XCTAssertNil(f.workspace.snapshot); XCTAssertEqual(count(f,16),0)
                }
            }
        }
    }
    func testFixtureRootPINFlowKeepsAuthenticatedBatchAvailable() async throws { try await rootPIN(blocked:false) }
    func testCloseRevokesRootPINTaskAndItsLateAutomaticContinuation() async throws { try await rootPIN(blocked:true) }
    private func rootPIN(blocked: Bool) async throws {
        try await repeated("rootPIN(blocked: \(blocked))") {
            try await fixture(approved:false,blocked:blocked) { f in
                let reviewed=expectation(description:"production root prepared bound review"), delivered=FixtureLocked(false)
                let observation=f.installed.review.$approval.sink { value in
                    if value != nil, delivered.withValue({ flag in if flag { return false }; flag=true; return true }) { reviewed.fulfill() }
                }
                f.installed.discover(manual:f.mock.path.path)
                await fulfillment(of:[reviewed],timeout:20)
                XCTAssertTrue(f.installed.canApproveBatch)
                f.installed.prepareBatch()
                let plan=try XCTUnwrap(f.batch.approval)
                XCTAssertTrue(f.batch.isApproved); XCTAssertNotNil(f.installed.approvedRoute)
                let done=expectation(description:blocked ? "private worker entered" : "all verified receipts retained")
                let once=FixtureLocked(false)
                var receiptObservation: AnyCancellable?
                var watch: DispatchSourceFileSystemObject?
                if blocked {
                    let fd=open(f.mock.folder.appendingPathComponent("operations").path,O_EVTONLY)
                    let source=DispatchSource.makeFileSystemObjectSource(fileDescriptor:fd,eventMask:.write,queue:.global())
                    source.setEventHandler {
                        let lines=(try? String(contentsOf:f.mock.folder.appendingPathComponent("operations"))) ?? ""
                        if lines.split(separator:"\n").contains("16"), once.withValue({ flag in if flag { return false }; flag=true; return true }) { done.fulfill() }
                    }
                    source.setCancelHandler { Darwin.close(fd) }; source.resume(); watch=source
                } else {
                    receiptObservation=f.results.$receipts.sink { receipts in
                        if receipts.count==3, once.withValue({ flag in if flag { return false }; flag=true; return true }) { done.fulfill() }
                    }
                }
                defer { watch?.cancel() }
                f.installed.provider.pin="synthetic-fixture"
                XCTAssertTrue(f.installed.canAuthorizeNext)
                f.installed.authorizeNextDocument()
                XCTAssertTrue(f.installed.provider.pin.isEmpty)
                await fulfillment(of:[done],timeout:20)
                if blocked {
                    await close(.close,f); await drained(f.session)
                    XCTAssertTrue(f.batch.needsOutcomeReview); XCTAssertEqual(states(f),[.uncertain,.cancelled,.cancelled])
                    XCTAssertNil(f.installed.authenticationSession); XCTAssertEqual(count(f,16),1)
                    XCTAssertFalse(plan.jobs.contains { FileManager.default.fileExists(atPath:$0.destination.path) })
                } else {
                    await drained(f.session)
                    XCTAssertEqual(f.results.receipts.map(\.state),[.completed,.completed,.completed])
                    for (index,job) in plan.jobs.enumerated() {
                        XCTAssertEqual(try CAdESVerifier.verify(file:job.destination).originalDocument,Data("Synthetic approved \(index+1)".utf8))
                    }
                    XCTAssertEqual(count(f,16),3); XCTAssertEqual(count(f,8),1)
                }
                withExtendedLifetime(observation) {}; withExtendedLifetime(receiptObservation) {}
            }
        }
    }

    func testTerminationRecordsPrivateUncertaintyBeforeTheGraceDeadline() async throws {
        try await repeated {
            try await fixture { f in
                let gate=Gate(expectation(description:"verified private reply before publication")); defer { gate.release() }
                let worker=f.worker
                let task=Task { try await f.batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in
                    try job.executeCAdES(isCancelled:{ operation.isCancellationRequested }) { bytes in
                        let prepared=try CAdES.Prepared(document:bytes,certificateDER:job.certificateDER)
                        operation.transition(to:.signing)
                        let signature=try worker.sign(provider:job.providerPath,slot:job.slot,certificate:job.certificate,der:job.certificateDER,attributes:prepared.attributesToSign,pin:pin,id:job.id,isCancelled:{ operation.isCancellationRequested })
                        operation.transition(to:.verifying); try gate.enter(); try operation.checkCancellation()
                        return try prepared.finish(signature:signature)
                    }
                    operation.transition(to:.completed)
                } }
                await fulfillment(of:[gate.reached],timeout:8)
                var deadline: (@MainActor () -> Void)?, replies:[Bool]=[]
                let delegate=SignumLifecycle(controller:f.controller,reply:{replies.append($0)},scheduleDeadline:{deadline=$0})
                XCTAssertEqual(delegate.applicationShouldTerminate(NSApplication.shared),.terminateLater)
                XCTAssertEqual(f.batch.documents.first?.state,.uncertain)
                XCTAssertTrue(f.batch.needsOutcomeReview)
                try XCTUnwrap(deadline)(); XCTAssertEqual(replies,[true])
                gate.release(); try await task.value; await drained(f.session)
                XCTAssertEqual(states(f),[.uncertain,.cancelled,.cancelled])
                XCTAssertEqual(count(f,16),1)
                XCTAssertFalse(try XCTUnwrap(f.plan).jobs.contains { FileManager.default.fileExists(atPath:$0.destination.path) })
            }
        }
    }

    func testLateConfirmedPublicationResolvesOnlyProvisionalWindowUncertainty() async throws {
        try await repeated {
            try await fixture { f in
                let gate=Gate(expectation(description:"helper publication before parent confirmation")); defer { gate.release() }
                let worker=f.worker
                let task=Task { try await f.batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in
                    // Model the helper's independently committed, verified file; its parent status is delayed.
                    try job.executeCAdES { bytes in
                        let prepared=try CAdES.Prepared(document:bytes,certificateDER:job.certificateDER)
                        operation.transition(to:.signing)
                        let signature=try worker.sign(provider:job.providerPath,slot:job.slot,certificate:job.certificate,der:job.certificateDER,attributes:prepared.attributesToSign,pin:pin,id:job.id)
                        operation.transition(to:.verifying); return try prepared.finish(signature:signature)
                    }
                    try gate.enter(); operation.recordPublished()
                } }
                await fulfillment(of:[gate.reached],timeout:8)
                let file=try XCTUnwrap(f.plan).jobs[0].destination
                XCTAssertEqual(try CAdESVerifier.verify(file:file).originalDocument,Data("Synthetic approved 1".utf8))
                await close(.close,f)
                XCTAssertTrue(f.batch.needsOutcomeReview)
                XCTAssertEqual(f.batch.documents.first?.state,.uncertain)
                gate.release(); try await task.value; await drained(f.session)
                XCTAssertEqual(states(f),[.completed,.cancelled,.cancelled])
                XCTAssertFalse(f.batch.needsOutcomeReview)
                XCTAssertEqual(try CAdESVerifier.verify(file:file).originalDocument,Data("Synthetic approved 1".utf8))
                XCTAssertEqual(count(f,16),1)
            }
        }
    }

}
#endif
