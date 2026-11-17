#if os(macOS)
import Foundation
import Darwin
import COutputPermissions
import CPKCS11

/// A best-effort append-only trace. It never authorizes or controls a signature.
final class CAdESWorkerAudit: @unchecked Sendable {
    enum Event: String, Codable {
        case jobStarted, jobEnded, requestNotStarted
        case workerLaunched, requestSent, requestAccepted, moduleLoaded
        case pkcs11Enter, pkcs11Return
        case responseReceived, responseRejected, replyFailed, providerRejected
        case signatureVerified, signatureRejected
        case timeout, cancelled, ipcError, launchFailed, capacity
        case terminationRequested, terminationEscalated, terminationPending, workerExited, workerSignalled
    }

    struct Entry: Codable {
        let timestampMs: Int64
        let jobID: UUID
        let workerPID: Int32?
        let action: String
        let event: Event
        let function: String?
        let code: UInt64?
        let phase: String?
        let mechanism: UInt64?
        let inputBytes: Int?
        let moduleName: String?
        let moduleDevice: Int32?
        let moduleInode: UInt64?
    }

    private static let directoryName = "Signum-CAdES-Worker-Audit-v1"
    let directory: URL
    private let descriptor: Int32
    private let jobID: UUID
    private let lock = NSLock()
    private var pid: Int32?

    private init(directory: URL, descriptor: Int32, jobID: UUID, pid: Int32?) {
        self.directory = directory
        self.descriptor = descriptor
        self.jobID = jobID
        self.pid = pid
    }
    deinit { Darwin.close(descriptor) }

    static func start(jobID: UUID, supportDirectory: URL?) -> CAdESWorkerAudit? {
        guard let support = supportDirectory ?? (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )), support.isFileURL else { return nil }
        let parent = open(support.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard parent >= 0 else { return nil }
        defer { Darwin.close(parent) }
        var info = stat()
        guard fstat(parent, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0,
              sg_discovery_acl_safe(support.path) == 1 else { return nil }

        let created = mkdirat(parent, directoryName, 0o700) == 0
        guard created || errno == EEXIST else { return nil }
        let root = openat(parent, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { return nil }
        defer { Darwin.close(root) }
        guard (created ? sg_output_make_private(root, 0o700) : sg_output_is_private(root, 0o700)) == 0 else { return nil }
        let file = openat(root, fileName(jobID), O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { return nil }
        guard sg_output_make_private(file, 0o600) == 0 else { Darwin.close(file); return nil }
        let audit = Self(directory: support.appendingPathComponent(directoryName), descriptor: file, jobID: jobID, pid: nil)
        audit.record(.jobStarted)
        return audit
    }

    static func attach(jobID: UUID, directory path: String) -> CAdESWorkerAudit? {
        guard path.hasPrefix("/"), path.utf8.count < Int(PATH_MAX), !path.utf8.contains(0) else { return nil }
        let directory = URL(fileURLWithPath: path, isDirectory: true)
        guard directory.lastPathComponent == directoryName else { return nil }
        let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard root >= 0 else { return nil }
        defer { Darwin.close(root) }
        guard sg_output_is_private(root, 0o700) == 0 else { return nil }
        let file = openat(root, fileName(jobID), O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { return nil }
        guard sg_output_is_private(file, 0o600) == 0 else { Darwin.close(file); return nil }
        return Self(directory: directory, descriptor: file, jobID: jobID, pid: getpid())
    }

    private static func fileName(_ id: UUID) -> String { id.uuidString + ".jsonl" }

    func launched(pid: Int32) {
        lock.lock(); self.pid = pid; lock.unlock()
        record(.workerLaunched)
    }

    func recordExit(_ process: Process) {
        record(process.terminationReason == .exit ? .workerExited : .workerSignalled,
               code: UInt64(UInt32(bitPattern: process.terminationStatus)))
    }

    func finish(phase: SigningOperationPhase) {
        lock.lock(); let launched = pid != nil; lock.unlock()
        if !launched { record(.requestNotStarted) }
        record(.jobEnded, phase: phase)
    }

    func recordModule(path: String) {
        var identity = stat()
        guard stat(path, &identity) == 0 else { return }
        let name = URL(fileURLWithPath: path).lastPathComponent
        record(.moduleLoaded, module: (name, identity.st_dev, identity.st_ino))
    }

    func record(_ event: Event, function: String? = nil, code: UInt64? = nil,
                phase: SigningOperationPhase? = nil, mechanism: UInt64? = nil, inputBytes: Int? = nil,
                module: (name: String, device: Int32, inode: UInt64)? = nil) {
        lock.lock(); let pid = self.pid; lock.unlock()
        let entry = Entry(timestampMs: Int64(Date().timeIntervalSince1970 * 1000), jobID: jobID,
                          workerPID: pid, action: "rsaSHA256", event: event, function: function,
                          code: code, phase: phase?.rawValue, mechanism: mechanism, inputBytes: inputBytes,
                          moduleName: module?.name, moduleDevice: module?.device, moduleInode: module?.inode)
        guard var line = try? JSONEncoder().encode(entry) else { return }
        // One append per event. Never wait on the other process or retry a partial record.
        line.append(0x0a)
        line.withUnsafeBytes { bytes in
            while Darwin.write(descriptor, bytes.baseAddress!, bytes.count) < 0 && errno == EINTR {}
        }
    }

    func observeProvider<T>(_ body: () throws -> T) rethrows -> T {
        sg_observe_calls({ context, call, returned, rv, mechanism, inputBytes in
            guard let context else { return }
            let audit = Unmanaged<CAdESWorkerAudit>.fromOpaque(context).takeUnretainedValue()
            let function: String
            switch call {
            case SG_CALL_INITIALIZE: function = "C_Initialize"
            case SG_CALL_OPEN_SESSION: function = "C_OpenSession"
            case SG_CALL_LOGIN: function = "C_Login"
            case SG_CALL_SIGN_INIT: function = "C_SignInit"
            case SG_CALL_SIGN: function = "C_Sign"
            case SG_CALL_CLOSE_SESSION: function = "C_CloseSession"
            case SG_CALL_FINALIZE: function = "C_Finalize"
            default: return
            }
            let signEntry = call == SG_CALL_SIGN && returned == 0
            audit.record(returned == 0 ? .pkcs11Enter : .pkcs11Return,
                         function: function, code: returned == 0 ? nil : UInt64(rv),
                         mechanism: signEntry ? UInt64(mechanism) : nil, inputBytes: signEntry ? inputBytes : nil)
        }, Unmanaged.passUnretained(self).toOpaque())
        defer { sg_observe_calls(nil, nil) }
        return try withExtendedLifetime(self, body)
    }
}
#endif
