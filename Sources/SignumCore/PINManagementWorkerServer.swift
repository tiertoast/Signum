#if os(macOS)
import Foundation
import Darwin
import CPKCS11
import CProcessCoordination

enum PINManagementWorkerServer {
    /// Called after parent-death watch, core-dump disable and vendor output sink.
    static func serve(reply: Int32) -> Int32 {
        var input = Data(), chunk = [UInt8](repeating: 0, count: 4096)
        defer { input.resetBytes(in: 0..<input.count) }
        while true {
            let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, count <= PINManagementWorkerRequest.maximumBytes - input.count else { return 2 }
            if count == 0 { break }
            input.append(contentsOf: chunk.prefix(count))
        }
        Darwin.close(STDIN_FILENO)
        // There is deliberately no mutation opcode or readyForSecrets response.
        guard let request = try? PINManagementWorkerRequest.decode(input) else { return 2 }
        input.resetBytes(in: 0..<input.count)
        let response: PINManagementWorkerResponse
        do {
            let snapshot = try observe(request.context)
            response = .init(version: 1, id: request.id, contextFingerprint: request.context.fingerprint, snapshot: snapshot, failure: nil)
        } catch {
            response = .init(version: 1, id: request.id, contextFingerprint: request.context.fingerprint, snapshot: nil,
                             failure: (error as? PINManagementFailure) ?? .publicReadFailed)
        }
        guard let output = try? JSONEncoder().encode(response), output.count <= PINManagementWorkerRequest.maximumBytes else { return 2 }
        var offset = 0
        while offset < output.count {
            let count = output.withUnsafeBytes { Darwin.write(reply, $0.baseAddress!.advanced(by: offset), output.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return 2 }
            offset += count
        }
        return 0
    }
    private static func string<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
    private static func observe(_ context: PINManagementContext) throws -> PINStatusSnapshot {
        // Never upgrade an existing token lease. Cross-provider exclusive barrier
        // precedes module validation/loading and remains held through cleanup.
        guard let lease = sg_admin_lease_acquire(context.provider, UInt64(context.token.slot), 0) else {
            throw PINManagementFailure.busy
        }
        defer { sg_token_lease_release(lease) }
        try context.requireCurrentModule()
        var pointer: OpaquePointer?
        guard sg_open(context.provider, &pointer, nil, 0) == 0, let pointer else {
            throw PINManagementFailure.publicReadFailed
        }
        var needsClose = true
        defer { if needsClose { _ = sg_close_checked(pointer, nil, 0) } }
        var info = SGPINPublicInfo()
        guard sg_pin_public_info(pointer, context.token.slot, &info) == 0, info.version == 1 else {
            throw PINManagementFailure.publicReadFailed
        }
        let token = SignumToken(slot: info.token.slot, label: string(info.token.label), manufacturer: string(info.token.manufacturer),
                                model: string(info.token.model), reader: string(info.token.reader), serial: string(info.token.serial))
        guard token == context.token else { throw PINManagementFailure.contextChanged }
        var major: UInt32 = 0, minor: UInt32 = 0
        let moduleVersion = sg_module_version(pointer, &major, &minor) == 0 ? "\(major).\(minor)" : nil
        // An absent min/max is unknown; a contradictory pair stays visible.
        let snapshot = PINStatusSnapshot(version: 1, contextFingerprint: context.fingerprint, readAt: Date(), flags: info.flags,
            minimumBytes: info.minimum_known != 0 ? info.minimum_bytes : nil,
            maximumBytes: info.maximum_known != 0 ? info.maximum_bytes : nil, moduleVersion: moduleVersion)
        let cleanup = sg_close_checked(pointer, nil, 0); needsClose = false
        guard cleanup == 0 else { throw PINManagementFailure.publicReadFailed }
        try context.requireCurrentModule()
        return snapshot
    }
}
#endif
