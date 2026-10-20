#if os(macOS)
import Foundation
import Darwin

public struct DocumentAcquisitionFailure: Error, LocalizedError {
    public enum Kind: String, Sendable { case changed, unavailable, read, tooLarge, space, timeout, cancelled, unsupported }
    public let kind: Kind
    public let technicalDetails: String
    init(_ kind: Kind, _ operation: String, code: Int32? = nil) {
        self.kind = kind
        technicalDetails = operation + (code.map { " (errno \($0))" } ?? "")
    }
    public var errorDescription: String? {
        switch kind {
        case .changed: return "Il documento è stato modificato durante l'acquisizione. Riselezionalo."
        case .unavailable: return "Il documento non è più disponibile o il percorso non è consentito."
        case .read: return "Impossibile leggere il documento. Controlla i permessi e riprova."
        case .tooLarge: return "Il documento supera la dimensione massima supportata."
        case .space: return "Spazio insufficiente per preparare il documento."
        case .timeout: return "La preparazione del documento ha impiegato troppo tempo."
        case .cancelled: return "Preparazione del documento annullata."
        case .unsupported: return "Questo filesystem non consente uno snapshot coerente. Usa una copia locale."
        }
    }
    static func system(_ operation: String, code: Int32 = errno) -> Self {
        switch code {
        case ENOSPC, EDQUOT: return .init(.space, operation, code: code)
        case ENOENT, ENOTDIR, ELOOP: return .init(.unavailable, operation, code: code)
        case ENOTSUP, EXDEV: return .init(.unsupported, operation, code: code)
        default: return .init(.read, operation, code: code)
        }
    }
}

/// Observe writes even if a writer restores mtime and bytes. NOTE_ATTRIB alone
/// is not a content change. CoW, not this event stream or two matching hashes,
/// provides the coherent instant represented by the approved snapshot.
final class AcquisitionWatch {
    private let queue: Int32
    init(_ source: Int32) throws {
        queue = kqueue()
        guard queue >= 0 else { throw DocumentAcquisitionFailure.system("kqueue") }
        var event = kevent64_s(ident: UInt64(source), filter: Int16(EVFILT_VNODE), flags: UInt16(EV_ADD | EV_CLEAR),
            fflags: UInt32(NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE), data: 0, udata: 0, ext: (0, 0))
        guard Darwin.kevent64(queue, &event, 1, nil, 0, 0, nil) == 0 else {
            let code = errno; Darwin.close(queue)
            throw DocumentAcquisitionFailure.system("register source vnode", code: code)
        }
    }
    deinit { Darwin.close(queue) }
    func requireUnchanged() throws {
        var event = kevent64_s(), instant = timespec(tv_sec: 0, tv_nsec: 0)
        let count = Darwin.kevent64(queue, nil, 0, &event, 1, 0, &instant)
        guard count >= 0 else { throw DocumentAcquisitionFailure.system("read source vnode events") }
        if count > 0 {
            if event.flags & UInt16(EV_ERROR) != 0 { throw DocumentAcquisitionFailure(.read, "source vnode event error \(event.data)") }
            throw DocumentAcquisitionFailure(.changed, "source vnode flags \(event.fflags)")
        }
    }
}
#endif
