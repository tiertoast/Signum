#if os(macOS)
import XCTest
import UniformTypeIdentifiers
@testable import SignumCore
@testable import SignumApp

final class DeferredDrop: @unchecked Sendable {
    private let lock = NSLock()
    private var send: ((Data?,Error?) -> Void)?
    func install(_ callback: @escaping (Data?,Error?) -> Void) { lock.lock();send = callback;lock.unlock() }
    func finish() { lock.lock();let callback = send;lock.unlock();callback?(URL(fileURLWithPath:"/synthetic/late.pdf").dataRepresentation,nil) }
}
final class ControlledDrop: @unchecked Sendable {
    private let lock = NSLock()
    private var callbacks: [Int:@Sendable (URL?) -> Void] = [:]
    private var deadline: (@Sendable () -> Void)?
    private let ready: XCTestExpectation
    let count: Int
    init(_ count: Int, ready: XCTestExpectation) { self.count = count; self.ready = ready; ready.expectedFulfillmentCount = count }
    var loaders: [FileDropResolution.Loader] { (0..<count).map { index in { callback in
        self.lock.lock(); self.callbacks[index] = callback; self.lock.unlock(); self.ready.fulfill()
    } } }
    func schedule(_ finish: @escaping @Sendable () -> Void) { lock.lock(); deadline = finish; lock.unlock() }
    func fire() { lock.lock();let callback = deadline;lock.unlock();callback?() }
    func send(_ index: Int,_ name: String) { lock.lock();let callback = callbacks[index];lock.unlock();callback?(URL(fileURLWithPath:"/synthetic/"+name)) }
    func resolve() async -> [URL] { await FileDropResolution.resolve(loaders:loaders,scheduleTimeout:schedule) }
}
@MainActor final class VerificationDropLifecycleTests: XCTestCase {
    private let verifier: VerificationWorkspace.Verifier = { url,_ in
        .init(id:UUID(),documentName:url.lastPathComponent,sha256:"synthetic",format:.unknown,signatures:[],documentState:"unsupported",issue:"",previewPDF:nil,originalContent:nil)
    }
    func testResolverKeepsOrderIgnoresDuplicatesAndBoundsMissingCallback() async throws {
        let ready = expectation(description:"all callbacks registered"), drop = ControlledDrop(3,ready:ready)
        let task = Task { await drop.resolve() }
        await fulfillment(of:[ready],timeout:2)
        drop.send(2,"third");drop.send(2,"duplicate");drop.send(0,"first");drop.fire()
        let result = await task.value
        XCTAssertEqual(result.map(\.lastPathComponent),["first","third"])
        drop.send(1,"late");drop.fire()
        XCTAssertEqual(result.map(\.lastPathComponent),["first","third"])
    }
    func testNewDropAndPickerAppendWithoutDiscardingOldAcquisition() async throws {
        for picker in [false,true] {
            let workspace = VerificationWorkspace(), ready = expectation(description:"old drop registered"), old = ControlledDrop(1,ready:ready)
            let first = workspace.acquire(using:{await old.resolve()},verifier:verifier)
            XCTAssertTrue(workspace.busy);XCTAssertTrue(workspace.acquiring)
            await fulfillment(of:[ready],timeout:2)
            if picker {
                await workspace.start([URL(fileURLWithPath:"/synthetic/picker")],using:verifier).value
            } else {
                let nextReady = expectation(description:"new drop registered"), next = ControlledDrop(1,ready:nextReady)
                let latest = workspace.acquire(using:{await next.resolve()},verifier:verifier)
                await fulfillment(of:[nextReady],timeout:2);next.send(0,"new-drop");await latest.value
            }
            old.send(0,"stale");await first.value
            XCTAssertEqual(workspace.rows.map(\.name),[picker ? "picker" : "new-drop", "stale"])
            XCTAssertFalse(workspace.busy);XCTAssertFalse(workspace.acquiring)
        }
    }
    func testCloseResetTimeoutAndRecoveryResolveOwnedTasks() async throws {
        for action in 0..<3 {
            let workspace = VerificationWorkspace(), ready = expectation(description:"registered"), drop = ControlledDrop(1,ready:ready)
            let task = workspace.acquire(using:{await drop.resolve()},verifier:verifier)
            await fulfillment(of:[ready],timeout:2)
            if action == 0 { workspace.cancel() }
            if action == 1 { workspace.reset() }
            if action == 2 { drop.fire() }
            await task.value
            drop.send(0,"late");XCTAssertTrue(workspace.rows.isEmpty)
            XCTAssertFalse(workspace.busy);XCTAssertFalse(workspace.acquiring)
            if action == 2 { XCTAssertFalse(workspace.issue.isEmpty) }
            await workspace.start([URL(fileURLWithPath:"/synthetic/recovered")],using:verifier).value
            XCTAssertEqual(workspace.rows.map(\.name),["recovered"]);XCTAssertNotNil(workspace.rows[0].report)
        }
    }
    func testAdditionDuringVerificationQueuesWithoutReplacingAnyRow() async throws {
        let workspace = VerificationWorkspace(), entered = expectation(description:"old verifier entered"), release = DispatchSemaphore(value:0)
        let old = workspace.start([URL(fileURLWithPath:"/synthetic/old")]) { url,_ in
            entered.fulfill();_ = release.wait(timeout:.now()+3)
            return .init(id:UUID(),documentName:url.lastPathComponent,sha256:"synthetic",format:.unknown,signatures:[],documentState:"unsupported",issue:"",previewPDF:nil,originalContent:nil)
        }
        await fulfillment(of:[entered],timeout:2)
        let selected = workspace.selectedDocument
        let new = workspace.start([URL(fileURLWithPath:"/synthetic/new")],using:verifier)
        XCTAssertEqual(workspace.rows.map(\.name),["old","new"])
        XCTAssertEqual(workspace.selectedDocument,selected)
        XCTAssertNil(workspace.rows[1].report);XCTAssertFalse(workspace.rows[1].started)
        release.signal();await old.value;await new.value
        XCTAssertTrue(workspace.rows.allSatisfy { $0.report != nil });XCTAssertFalse(workspace.busy)
    }
    func testCancellationResolvesNativeProviderWithoutWaitingForItsCallback() async throws {
        let deferred = DeferredDrop(), entered = expectation(description:"provider entered"), resolved = expectation(description:"cancelled drop resolved")
        let provider = NSItemProvider()
        provider.registerDataRepresentation(forTypeIdentifier:UTType.fileURL.identifier,visibility:.all) { completion in
            deferred.install(completion);entered.fulfill();return nil
        }
        let task = Task { let urls = await VerificationDropLoader.urls(from:[provider]);resolved.fulfill();return urls }
        await fulfillment(of:[entered],timeout:2)
        task.cancel()
        await fulfillment(of:[resolved],timeout:0.5)
        deferred.finish()
        let urls = await task.value
        XCTAssertTrue(urls.isEmpty)
    }
}
#endif
