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
    private let onErasure: ((UnsafeBufferPointer<UInt8>) -> Void)?
    // Internal seam observes a cleared page while still mapped, never after free.
    init(lifetime: TimeInterval, inputDescriptor: Int32 = STDIN_FILENO,
         onErasure: ((UnsafeBufferPointer<UInt8>) -> Void)? = nil) throws {
        self.onErasure = onErasure
        let now = sg_batch_monotonic_now()
        guard now >= 0 else { throw SupervisedProcess.Failure.launch }
        deadline = now + lifetime
        guard let pointer = sg_secure_pin_create() else { throw Failure.memoryUnavailable }
        storage = pointer
        guard sg_secure_pin_receive(pointer, inputDescriptor, min(5, lifetime)) == 0 else {
            erase(); throw SupervisedProcess.Failure.protocolViolation
        }
    }
    var bytes: UnsafePointer<UInt8>? { storage.flatMap(sg_secure_pin_bytes) }
    var length: Int { sg_secure_pin_length(storage) }
    func erase() {
        guard let storage else { return }
        let bytes = sg_secure_pin_bytes(storage)
        sg_secure_pin_clear(storage)
        if let bytes, let onErasure { onErasure(UnsafeBufferPointer(start: bytes, count: Int(sysconf(_SC_PAGESIZE)))) }
        sg_secure_pin_destroy(storage)
        self.storage = nil
    }
    deinit { erase() }
}
#endif
