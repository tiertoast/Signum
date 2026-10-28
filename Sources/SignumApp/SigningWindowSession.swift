#if os(macOS)
import Foundation
import Combine
import SignumCore

/// One window session. Revocation is synchronous; owned work drains off-main.
/// A closed generation cannot submit or apply a late completion.
@MainActor final class SigningWindowSession: ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    private func notify() { DispatchQueue.main.async { [weak self] in self?.objectWillChange.send() } }
    private(set) var generation = UUID()
    private(set) var isActive = true
    private var cleanup: (() -> Void)?
    private weak var batch: BatchSigningCoordinator?
    private var observation: AnyCancellable?
    private var tasks: [UUID: Task<Void,Never>] = [:]
    private var drained: [UUID: () -> Void] = [:]
    private var reopenID: UUID?
    private var activities = Set<UUID>()
    var isDrained: Bool {
        activities.isEmpty && tasks.isEmpty && !(batch?.isRunning ?? false) && !(batch?.isPreparing ?? false) && !(batch?.isContinuingAuthenticated ?? false)
    }
    func beginActivity() -> UUID { let id = UUID(); activities.insert(id); return id }
    func endActivity(_ id: UUID) { activities.remove(id); checkDrain() }
    func accepts(_ generation: UUID) -> Bool { isActive && self.generation == generation }
    @discardableResult func activate(batch: BatchSigningCoordinator, cleanup: @escaping () -> Void) -> Bool {
        guard isActive || isDrained else { return false }
        let changed = !isActive || self.cleanup == nil
        self.batch = batch; self.cleanup = cleanup; isActive = true
        if changed { notify() }
        if observation == nil {
            observation = batch.objectWillChange.sink { [weak self] _ in
                DispatchQueue.main.async { self?.checkDrain() }
            }
        }
        return true
    }
    func own(_ task: Task<Void,Never>?) {
        guard let task else { return }
        let id = UUID(); tasks[id] = task
        if !isActive { task.cancel() }
        Task { @MainActor [weak self] in
            await task.value
            self?.tasks[id] = nil; self?.checkDrain()
        }
    }
    func revoke() {
        reopenID = nil
        guard isActive else { return }
        isActive = false; generation = UUID()
        tasks.values.forEach { $0.cancel() }
        let action = cleanup; cleanup = nil // Release the installed root capture.
        action?(); notify()
        checkDrain()
    }
    @discardableResult func whenDrained(_ receive: @escaping () -> Void) -> UUID {
        let id = UUID(); drained[id] = receive; checkDrain(); return id
    }
    func removeDrainObserver(_ id: UUID) { drained[id] = nil }
    func reopen(_ activate: @escaping () -> Void) {
        let id = UUID(); reopenID = id
        whenDrained { [weak self] in
            guard self?.reopenID == id else { return }
            self?.reopenID = nil; activate()
        }
    }
    private func checkDrain() {
        guard isDrained else { return }
        let callbacks = Array(drained.values); drained.removeAll()
        callbacks.forEach { $0() }
    }
}
#endif
