#if os(macOS)
import XCTest
import Foundation
@testable import SignumCore

final class ConcurrencyOwnershipTests: XCTestCase {
    func testProcessCapacityRemainsBoundedAndCanBeReusedAfterConcurrentReleases() {
        for _ in 0..<20 {
            for _ in 0..<8 { XCTAssertTrue(SupervisedProcess.acquire()) }
            DispatchQueue.concurrentPerform(iterations: 32) { _ in XCTAssertFalse(SupervisedProcess.acquire()) }
            DispatchQueue.concurrentPerform(iterations: 8) { _ in SupervisedProcess.release() }
        }
        for _ in 0..<8 { XCTAssertTrue(SupervisedProcess.acquire()) }
        XCTAssertFalse(SupervisedProcess.acquire())
        for _ in 0..<8 { SupervisedProcess.release() }
    }
    func testProcessLaunchFailuresReleaseTheirCapacityExactlyOnce() {
        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            var input = Data()
            do { _ = try SupervisedProcess.run(executable: URL(fileURLWithPath: "/synthetic/nonexistent-worker"), input: &input); XCTFail("Launched missing executable") } catch {}
        }
        for _ in 0..<8 { XCTAssertTrue(SupervisedProcess.acquire()) }
        XCTAssertFalse(SupervisedProcess.acquire())
        for _ in 0..<8 { SupervisedProcess.release() }
    }
    func testConcurrentCancellationAndTerminalCallbacksAreReentrantAndExactlyOnce() {
        let phases = FixtureLocked<[SigningOperationPhase]>([])
        let reference = FixtureLocked<SigningOperation?>(nil)
        let operation = SigningOperation { phase in
            _ = reference.withValue { $0 }?.state // Must not run inside the state lock.
            phases.withValue { $0.append(phase) }
        }
        reference.withValue { $0 = operation }; defer { reference.withValue { $0 = nil } }
        XCTAssertTrue(operation.transition(to: .preparing))
        DispatchQueue.concurrentPerform(iterations: 100) { index in
            if index % 2 == 0 { operation.requestCancellation() }
            else { _ = operation.transition(to: .cancelled) }
        }
        XCTAssertEqual(operation.state, .cancelled)
        XCTAssertEqual(phases.withValue { $0 }, [.preparing, .cancelled])
        XCTAssertFalse(operation.transition(to: .completed))
    }
}
#endif
