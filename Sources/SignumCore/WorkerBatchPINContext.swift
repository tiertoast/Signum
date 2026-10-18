#if os(macOS)
import Foundation
import Darwin
import CSecurePIN
import CPKCS11

/// Worker-only, single owner. Secret never becomes String/Data in this process.
final class WorkerBatchPINContext {
    enum Failure: Error { case memoryUnavailable }
    private var storage: OpaquePointer?
    let deadline: TimeInterval
    let supervisionDeadline: TimeInterval
    init(lifetime: TimeInterval) throws {
        deadline = sg_batch_monotonic_now() + lifetime
        supervisionDeadline = ProcessInfo.processInfo.systemUptime + lifetime
        guard let pointer = sg_secure_pin_create() else { throw Failure.memoryUnavailable }
        storage = pointer
        guard sg_secure_pin_receive(pointer, STDIN_FILENO, min(5, lifetime)) == 0 else {
            erase(); throw SupervisedProcess.Failure.protocolViolation
        }
    }
    var bytes: UnsafePointer<UInt8>? { storage.flatMap(sg_secure_pin_bytes) }
    var length: Int { sg_secure_pin_length(storage) }
    func erase() { if let storage { sg_secure_pin_destroy(storage); self.storage = nil } }
    deinit { erase() }
}
#endif
