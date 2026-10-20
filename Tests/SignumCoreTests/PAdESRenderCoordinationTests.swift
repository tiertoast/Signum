#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

@MainActor final class PAdESRenderCoordinationTests: XCTestCase {
    func testOneActiveAndOnlyLatestPendingRequestCanPublish() async throws {
        let entered = expectation(description:"entered"), done = expectation(description:"latest")
        let release = DispatchSemaphore(value:0)
        let worker = PAdESRenderCoordinator(renderer:{ c,der,crop,cancelled in
            if c.customText == "first" { entered.fulfill(); _ = release.wait(timeout:.now()+5) }
            return try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop,isCancelled:cancelled)
        })
        var c = PAdESAppearanceConfiguration(); c.showSigner=false; c.customText="first"
        let crop=CGRect(x:0,y:0,width:3370,height:2384)
        worker.submit(c,der:Data(),crop:crop) { _ in XCTFail("Obsolete result") }
        await fulfillment(of:[entered],timeout:5)
        for i in 1...120 {
            c.customText="latest \(i)"
            worker.submit(c,der:Data(),crop:crop) { result in
                XCTAssertEqual(try? result.get().configuration.customText,"latest 120"); done.fulfill()
            }
        }
        XCTAssertEqual(worker.started,1)
        release.signal(); await fulfillment(of:[done],timeout:5)
        XCTAssertEqual(worker.started,2); XCTAssertEqual(worker.discarded,1); XCTAssertEqual(worker.published,1)
        XCTAssertTrue(worker.isIdle)
    }
    func testCancellationClearsPendingAndNeverPublishesAfterPaneClosure() async throws {
        let entered=expectation(description:"entered"), release=DispatchSemaphore(value:0)
        let worker=PAdESRenderCoordinator(renderer:{ c,der,crop,cancelled in
            entered.fulfill(); _ = release.wait(timeout:.now()+5)
            return try PAdESAppearanceRenderer.render(c,certificateDER:der,cropBox:crop,isCancelled:cancelled)
        })
        var c=PAdESAppearanceConfiguration(); c.showSigner=false
        let crop=CGRect(x:0,y:0,width:595,height:842)
        worker.submit(c,der:Data(),crop:crop) { _ in XCTFail("Closed pane") }
        await fulfillment(of:[entered],timeout:5)
        c.customText="pending"; worker.submit(c,der:Data(),crop:crop) { _ in XCTFail("Closed pending pane") }
        worker.cancel(); release.signal()
        for _ in 0..<200 { if worker.isIdle { break }; try await Task.sleep(nanoseconds:10_000_000) }
        XCTAssertTrue(worker.isIdle); XCTAssertEqual(worker.started,1); XCTAssertEqual(worker.published,0)
    }
    func testRendererCooperativelyChecksCancellationBeforeAndBetweenExpensivePhases() throws {
        var c=PAdESAppearanceConfiguration(); c.showSigner=false
        c.image=try PAdESAppearanceImage(data:PAdESPlacementPerformanceTests.png(1024))
        let crop=CGRect(x:0,y:0,width:595,height:842)
        XCTAssertThrowsError(try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,isCancelled:{true}))
        var checkpoints=0
        XCTAssertThrowsError(try PAdESAppearanceRenderer.render(c,certificateDER:Data(),cropBox:crop,isCancelled:{checkpoints+=1; return checkpoints==3}))
        XCTAssertEqual(checkpoints,3)
    }
    func testSupersededPreflightsDoNotMultiplyWholeSnapshotReads() async throws {
        try await SigningFormatStabilizationTests().fixture { root,batch,_ in
            let file=root.appendingPathComponent("64MiB.bin"); try Data(repeating:65,count:64*1024*1024).write(to:file)
            await batch.addDocuments([file],format:.cades)
            let der=try CertificateEligibilityTests.fixtures.get().der("valid"), review=SigningReview()
            let entered=expectation(description:"preflight entered"), release=DispatchSemaphore(value:0)
            @MainActor func context(_ i:Int)->SigningReviewContext {
                .init(revision:batch.revision,provider:"/synthetic/provider",slot:7,
                    certificate:.init(label:"Synthetic",identifier:Data([1])),der:der,
                    destination:.originalFolders,routeID:"route \(i)",discoveryID:UUID())
            }
            let first=Task { await review.prepare(context(0),batch:batch,validate:{ entered.fulfill(); _=release.wait(timeout:.now()+5) }) }
            await fulfillment(of:[entered],timeout:5)
            var tasks:[Task<Void,Never>]=[]
            for i in 1...30 {
                let next=context(i)
                tasks.append(Task { await review.prepare(next,batch:batch,validate:{}) })
                await Task.yield()
            }
            let waitDeadline = ProcessInfo.processInfo.systemUptime+5
            while review.context?.routeID != "route 30", ProcessInfo.processInfo.systemUptime < waitDeadline { await Task.yield() }
            XCTAssertFalse(review.context?.routeID != "route 30", "Timed out waiting for async fixture")
            release.signal(); await first.value
            for task in tasks { await task.value }
            XCTAssertEqual(review.preflightsStarted,2)
            XCTAssertEqual(review.approval?.jobs.count,1); XCTAssertEqual(review.context?.routeID,"route 30")
            XCTAssertGreaterThanOrEqual(review.preparationsDiscarded,30)
            print("STABILIZATION preflight contexts=31 started=\(review.preflightsStarted) discarded=\(review.preparationsDiscarded) snapshot_bytes=67108864")
        }
    }
}
#endif
