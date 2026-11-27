#if os(macOS)
import Foundation

/// HTTPS only, allowlisted GitHub hosts at every redirect, no cookies, cache or
/// credentials, and a byte limit enforced while receiving.
final class SignumUpdateHTTPS: NSObject, SignumUpdateTransport, URLSessionDataDelegate, @unchecked Sendable {
    private final class Transfer {
        var continuation: CheckedContinuation<Data, Error>?
        var bytes = Data()
        let limit: Int
        init(limit: Int, continuation: CheckedContinuation<Data, Error>) { self.limit = limit; self.continuation = continuation }
    }
    private let lock = NSLock()
    private var transfers: [Int: Transfer] = [:]
    private var session: URLSession!
    override init() {
        super.init()
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil; config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 600
        config.httpAdditionalHeaders = ["Accept": "application/vnd.github+json, application/octet-stream",
                                        "User-Agent": "Signum-Update"]
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
    }

    func fetch(_ url: URL, limit: Int) async throws -> Data {
        guard SignumUpdatePolicy.allows(url) else { throw SignumUpdateError.disallowedURL }
        let task = session.dataTask(with: url)
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock(); transfers[task.taskIdentifier] = Transfer(limit: limit, continuation: continuation); lock.unlock()
                task.resume()
            }
        }, onCancel: { task.cancel() })
    }
    private func finish(_ task: URLSessionTask, _ result: Result<Data, Error>) {
        lock.lock(); let transfer = transfers.removeValue(forKey: task.taskIdentifier); lock.unlock()
        if case .failure = result { task.cancel() }
        transfer?.continuation?.resume(with: result)
    }
    private func transfer(_ task: URLSessionTask) -> Transfer? {
        lock.lock(); defer { lock.unlock() }; return transfers[task.taskIdentifier]
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        if SignumUpdatePolicy.allows(request.url) { completionHandler(request) }
        else { completionHandler(nil); finish(task, .failure(SignumUpdateError.disallowedURL)) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, SignumUpdatePolicy.allows(http.url), let transfer = transfer(dataTask) else {
            completionHandler(.cancel); finish(dataTask, .failure(SignumUpdateError.invalidResponse)); return
        }
        guard http.statusCode == 200 else {
            completionHandler(.cancel); finish(dataTask, .failure(SignumUpdateError.httpStatus(http.statusCode))); return
        }
        guard response.expectedContentLength <= transfer.limit else {
            completionHandler(.cancel); finish(dataTask, .failure(SignumUpdateError.tooLarge)); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let transfer = transfer(dataTask) else { return }
        guard transfer.bytes.count <= transfer.limit - data.count else { finish(dataTask, .failure(SignumUpdateError.tooLarge)); return }
        transfer.bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let transfer = transfer(task) else { return }
        if let error { finish(task, .failure(error)) } else { finish(task, .success(transfer.bytes)) }
    }
}

/// Stages a verified DMG next to nothing that is running, and swaps the bundle
/// only after Signum has quit, from a small helper that restores the old copy
/// if the copy fails.
struct SignumUpdateInstaller {
    enum Installability: Equatable {
        case installable
        case unavailable(String)
    }
    var fileManager = FileManager.default
    var root: URL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        .appendingPathComponent(SignumUpdatePolicy.bundleIdentifier, isDirectory: true)
        .appendingPathComponent("Updates", isDirectory: true)
    /// Replaced in tests; the real check is `codesign --verify --deep --strict`.
    var verifyCodeSignature: (URL) -> Bool = { app in
        SignumUpdateInstaller.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path]).status == 0
    }

    static func installability(of bundle: URL, bundleIdentifier: String?, fileManager: FileManager = .default) -> Installability {
        guard bundle.pathExtension == "app" else { return .unavailable("Signum non è in esecuzione da un’app installata.") }
        guard bundleIdentifier == SignumUpdatePolicy.bundleIdentifier else {
            return .unavailable("Questa build di Signum non si aggiorna da sola.")
        }
        if bundle.path.contains("/AppTranslocation/") {
            return .unavailable("Sposta Signum nella cartella Applicazioni per gli aggiornamenti automatici.")
        }
        let readOnly = (try? bundle.resourceValues(forKeys: [.volumeIsReadOnlyKey]))?.volumeIsReadOnly ?? true
        guard !readOnly else { return .unavailable("Signum è aperta da un disco di sola lettura: copiala in Applicazioni.") }
        guard fileManager.isWritableFile(atPath: bundle.deletingLastPathComponent().path),
              fileManager.isWritableFile(atPath: bundle.path) else {
            return .unavailable("Non hai i permessi per sostituire Signum in questa cartella.")
        }
        return .installable
    }

    func store(_ data: Data, for manifest: SignumUpdateManifest) throws -> URL {
        try manifest.verifyPayload(data)
        let folder = root.appendingPathComponent("build-\(manifest.build)", isDirectory: true)
        try? fileManager.removeItem(at: folder)
        try fileManager.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let dmg = folder.appendingPathComponent(manifest.dmg.name)
        try data.write(to: dmg, options: .atomic)
        return dmg
    }

    /// Mounts read-only, copies `Signum.app` out and checks it is the announced build.
    func stage(dmg: URL, manifest: SignumUpdateManifest) throws -> URL {
        let folder = dmg.deletingLastPathComponent()
        let mount = folder.appendingPathComponent("mount", isDirectory: true)
        let staged = folder.appendingPathComponent("Signum.app", isDirectory: true)
        try? fileManager.removeItem(at: staged)
        try fileManager.createDirectory(at: mount, withIntermediateDirectories: true)
        let attach = Self.run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount.path, dmg.path])
        guard attach.status == 0 else { throw SignumUpdateError.stagingFailed("immagine disco non leggibile") }
        let copy = Self.run("/usr/bin/ditto", [mount.appendingPathComponent("Signum.app").path, staged.path])
        if Self.run("/usr/bin/hdiutil", ["detach", mount.path]).status != 0 {
            _ = Self.run("/usr/bin/hdiutil", ["detach", "-force", mount.path])
        }
        try? fileManager.removeItem(at: mount)
        guard copy.status == 0 else { throw SignumUpdateError.stagingFailed("copia dell’app non riuscita") }
        try validate(staged: staged, manifest: manifest)
        try? fileManager.removeItem(at: dmg)
        return staged
    }

    func validate(staged: URL, manifest: SignumUpdateManifest) throws {
        guard let info = NSDictionary(contentsOf: staged.appendingPathComponent("Contents/Info.plist")) as? [String: Any] else {
            throw SignumUpdateError.stagedAppMismatch("Info.plist mancante")
        }
        guard info["CFBundleIdentifier"] as? String == manifest.bundleIdentifier else { throw SignumUpdateError.stagedAppMismatch("identificativo") }
        guard info["CFBundleVersion"] as? String == String(manifest.build) else { throw SignumUpdateError.stagedAppMismatch("numero di build") }
        guard info["CFBundleShortVersionString"] as? String == manifest.version else { throw SignumUpdateError.stagedAppMismatch("versione") }
        guard verifyCodeSignature(staged) else { throw SignumUpdateError.stagedAppMismatch("firma del codice non valida") }
    }

    /// Waits for `pid` to exit, then swaps the bundle; restores the old copy on failure.
    static let swapScript = """
    pid="$1"; staged="$2"; dest="$3"; relaunch="$4"
    i=0
    while /bin/kill -0 "$pid" 2>/dev/null; do i=$((i+1)); [ "$i" -gt 600 ] && exit 2; /bin/sleep 0.1; done
    [ -d "$staged" ] || exit 3
    backup="$dest.signum-previous"
    /bin/rm -rf "$backup"
    /bin/mv "$dest" "$backup" || exit 4
    if /usr/bin/ditto "$staged" "$dest"; then
      /bin/rm -rf "$backup" "$staged"
    else
      /bin/rm -rf "$dest"; /bin/mv "$backup" "$dest"; exit 5
    fi
    [ "$relaunch" = "1" ] && /usr/bin/open "$dest"
    exit 0
    """

    @discardableResult
    static func launchSwap(staged: URL, destination: URL, relaunch: Bool,
                           pid: Int32 = ProcessInfo.processInfo.processIdentifier) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", swapScript, "signum-update", String(pid), staged.path, destination.path, relaunch ? "1" : "0"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        return process
    }

    static func run(_ tool: String, _ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe; process.standardError = pipe; process.standardInput = FileHandle.nullDevice
        do { try process.run() } catch { return (-1, "\(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
#endif
