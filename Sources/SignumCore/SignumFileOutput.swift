import Foundation
#if os(macOS)
import Darwin
#endif

/// Creates the signed output exactly once, without silently replacing files.
/// The caller must keep the source file separate from the destination.
public enum SignumFileOutput {
    public static func writeNew(_ data: Data, to url: URL) throws {
        guard url.isFileURL, !data.isEmpty else {
            throw SignumError.module("Invalid file destination or empty signed data")
        }
        #if os(macOS)
        // O_EXCL atomically refuses to overwrite a file, including a symlink.
        // Create with owner-only access; do not write certificates or PINs to logs.
        let fd = url.path.withCString {
            Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        }
        guard fd >= 0 else {
            if errno == EEXIST {
                throw SignumError.module("Il file di destinazione esiste già: scegli un altro nome.")
            }
            throw SignumError.module("Impossibile creare il file di destinazione (errno \(errno)).")
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: url)
            throw error
        }
        #else
        throw SignumError.unsupportedPlatform
        #endif
    }
}
