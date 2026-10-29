import XCTest
import Foundation
@testable import SignumApp

private final class ObservationCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}
private final class ObservationTestCenter: NotificationCenter, @unchecked Sendable {
    let removals = ObservationCounter()
    override func removeObserver(_ observer: Any) { removals.increment(); super.removeObserver(observer) }
}
@MainActor final class NotificationObservationLifecycleTests: XCTestCase {
    private func checkOwner() {
        let center = ObservationTestCenter(), callbacks = ObservationCounter()
        let name = Notification.Name("Signum.synthetic.owner")
        var owner: SignumNotificationObservation? = .init(center: center, name: name, object: nil, queue: nil) { _ in callbacks.increment() }
        weak var weakOwner = owner
        center.post(name: name, object: nil)
        XCTAssertEqual(callbacks.count, 1); XCTAssertEqual(center.removals.count, 0)
        withExtendedLifetime(owner) {}
        owner = nil
        XCTAssertNil(weakOwner); XCTAssertEqual(center.removals.count, 1)
        center.post(name: name, object: nil)
        XCTAssertEqual(callbacks.count, 1); XCTAssertEqual(center.removals.count, 1)
    }
    func testMainActorOwnerRemovesObserverExactlyOnce() {
        let count = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1, count) {
            let before = testRun?.failureCount ?? 0
            checkOwner()
            print("PHASE3_REPEAT \(#function) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-before)")
        }
    }
    func testOwnerCreatedAndReleasedOffMainDoesNotNeedAppKitActor() async {
        let count = Int(ProcessInfo.processInfo.environment["SIGNUM_TEST_LIFECYCLE_REPETITIONS"] ?? "1") ?? 1
        for iteration in 1...max(1, count) {
            let before = testRun?.failureCount ?? 0
            await Task.detached {
                // Neither the owner nor its NSObjectProtocol token crosses an executor.
                let center = ObservationTestCenter(), callbacks = ObservationCounter()
                let name = Notification.Name("Signum.synthetic.detached.owner")
                var owner: SignumNotificationObservation? = .init(center: center, name: name, object: nil, queue: nil) { _ in callbacks.increment() }
                center.post(name: name, object: nil); XCTAssertEqual(callbacks.count, 1)
                withExtendedLifetime(owner) {}
                owner = nil
                center.post(name: name, object: nil)
                XCTAssertEqual(callbacks.count, 1); XCTAssertEqual(center.removals.count, 1)
            }.value
            print("PHASE3_REPEAT \(#function) iteration=\(iteration) failures=\((testRun?.failureCount ?? 0)-before)")
        }
    }
}
