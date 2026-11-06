#if os(macOS)
import AppKit
import Darwin
import SignumCore

/// Copies only report-owned immutable bytes. Files survive row/window removal
/// and Signum exit: Preview may still be using them. Retire on Preview exit, or
/// at the next use when Preview is not running (including crash leftovers).
@MainActor final class VerifiedPDFPreview {
    static let shared = VerifiedPDFPreview()
    private static let prefix = ".signum-verified-preview-"
    private var observer: NSObjectProtocol?
    private var copies: [URL] = []
    private var opening = 0
    init() {
        observer = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didTerminateApplicationNotification, object: nil, queue: .main) { notification in
            guard let application = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  application.bundleIdentifier == "com.apple.Preview" else { return }
            Task { @MainActor in Self.shared.retireCopies() }
        }
    }
    static func open(_ report: VerificationReport) async throws {
        guard let application = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Preview") else {
            throw SignumError.module("Anteprima macOS non disponibile.")
        }
        shared.retireCopies()
        shared.opening += 1
        defer { shared.opening -= 1 }
        let work = Task.detached(priority: .userInitiated) { try prepare(report) }
        let url = try await work.value
        shared.copies.append(url)
        do {
            let configuration = NSWorkspace.OpenConfiguration()
            _ = try await NSWorkspace.shared.open([url], withApplicationAt: application, configuration: configuration)
        } catch {
            retire(url); shared.copies.removeAll { $0 == url }
            throw SignumError.module("Impossibile aprire la copia PDF in Anteprima: " + error.localizedDescription)
        }
    }
    nonisolated static func prepare(_ report: VerificationReport, root: URL = FileManager.default.temporaryDirectory) throws -> URL {
        guard let bytes = report.previewPDF, !bytes.isEmpty, bytes.count <= SignumVerificationService.maximumInputBytes,
              report.format == .pades || (report.format == .cades && report.integrity == .verified) else {
            throw SignumError.module("Contenuto PDF esaminato non disponibile. Verifica nuovamente il documento.")
        }
        _ = try PDFPreviewPreparation.inspect(bytes)
        let root = root.resolvingSymlinksInPath()
        var rootInfo = stat()
        guard lstat(root.path, &rootInfo) == 0, rootInfo.st_mode & S_IFMT == S_IFDIR,
              rootInfo.st_uid == getuid(), rootInfo.st_mode & 0o077 == 0 else {
            throw SignumError.module("Area temporanea privata non disponibile.")
        }
        var template = Array(root.appendingPathComponent(prefix + "XXXXXX").path.utf8CString)
        guard mkdtemp(&template) != nil else { throw SignumError.module("Impossibile creare la copia PDF privata.") }
        let directory = URL(fileURLWithPath: String(cString: template), isDirectory: true)
        let url = directory.appendingPathComponent("documento.pdf")
        var keep = false
        defer { if !keep { retire(url) } }
        let folder = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard folder >= 0 else { throw SignumError.module("Cartella anteprima non disponibile.") }
        defer { close(folder) }
        guard let acl = acl_init(0) else { throw SignumError.module("Permessi anteprima non disponibili.") }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_set_fd(folder, acl) == 0, fchmod(folder, 0o700) == 0 else { throw SignumError.module("Permessi anteprima non disponibili.") }
        let fd = openat(folder, "documento.pdf", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SignumError.module("Copia PDF non disponibile.") }
        defer { close(fd) }
        guard acl_set_fd(fd, acl) == 0 else { throw SignumError.module("Permessi copia PDF non disponibili.") }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw SignumError.module("Scrittura copia PDF non riuscita.") }
                offset += count
            }
        }
        guard fchmod(fd, 0o400) == 0 else { throw SignumError.module("Impossibile proteggere la copia PDF.") }
        keep = true
        return url
    }
    /// No recursive deletion or symlink following, including crash recovery.
    nonisolated static func retire(_ url: URL) {
        let directory = url.deletingLastPathComponent()
        guard directory.lastPathComponent.hasPrefix(prefix), url.lastPathComponent == "documento.pdf" else { return }
        let fd = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return }
        _ = unlinkat(fd, "documento.pdf", 0)
        _ = rmdir(directory.path)
    }
    private func retireCopies() {
        guard opening == 0, NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.Preview").isEmpty else { return }
        copies.forEach { Self.retire($0) }; copies = []
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        for url in (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? [] where url.lastPathComponent.hasPrefix(Self.prefix) {
            Self.retire(url.appendingPathComponent("documento.pdf"))
        }
    }
}
#endif
