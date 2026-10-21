import Foundation

public protocol TLTransport: Sendable {
    func fetch(_ url: URL) async throws -> Data
    func fetchNational(country: String, lotl: AuthenticatedTL, now: Date) async throws -> Data
}

public extension TLTransport {
    func fetchNational(country: String, lotl: AuthenticatedTL, now: Date) async throws -> Data {
        let pointer = try TLAuthenticator.nationalPointer(country: country, lotl: lotl, now: now)
        return try await fetch(URL(string: pointer.location)!)
    }
}

public enum TLRefreshFailure: Error, Equatable, Sendable {
    case unauthorizedURL, redirect, httpStatus(Int), downloadTooLarge, invalidResponse
    case noAuthenticatedCache, invalidInterval
}

enum TLDownloadPolicy {
    static func allows(_ url: URL) -> Bool {
        url.absoluteString == EUTrustPolicy.location || url.absoluteString == EUTrustPolicy.italyLocation || LOTLPivotChain.allowedPivotURL(url.absoluteString)
    }
}

/// Fixed HTTPS bootstrap; national HTTP(S) requires an authenticated LOTL pointer.
/// No cookies, credentials, disk cache or automatic redirects.
/// Memory is bounded while receiving bytes, not after URLSession.data has buffered them.
public struct TLHTTPSClient: TLTransport {
    public init() {}
    public func fetchNational(country: String, lotl: AuthenticatedTL, now: Date) async throws -> Data {
        let pointer = try TLAuthenticator.nationalPointer(country: country, lotl: lotl, now: now)
        return try await BoundedTLTransfer(url: URL(string: pointer.location)!).run()
    }
    public func fetch(_ url: URL) async throws -> Data {
        guard TLDownloadPolicy.allows(url) else { throw TLRefreshFailure.unauthorizedURL }
        return try await BoundedTLTransfer(url: url).run()
    }
}

final class BoundedTLTransfer: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let url: URL
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var session: URLSession?
    private var bytes = Data()
    private var cancelled = false
    private let limit: Int
    private let configuration: URLSessionConfiguration
    init(url: URL, configuration: URLSessionConfiguration = .ephemeral, maximumBytes: Int = 64 * 1024 * 1024) {
        self.url = url; self.configuration = configuration; self.limit = maximumBytes
    }
    func run() async throws -> Data {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { start($0) }
        }, onCancel: { self.cancel() })
    }
    private func start(_ pending: CheckedContinuation<Data, Error>) {
        lock.lock()
        continuation = pending
        if cancelled { lock.unlock(); finish(.failure(CancellationError())); return }
        let config = configuration
        config.urlCache = nil; config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15; config.timeoutIntervalForResource = 45
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
        self.session = session
        let task = session.dataTask(with: url)
        lock.unlock()
        task.resume()
    }
    private func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
        finish(.failure(CancellationError()))
    }
    private func finish(_ result: Result<Data, Error>) {
        lock.lock()
        let pending = continuation; continuation = nil
        let active = session; session = nil
        lock.unlock()
        active?.invalidateAndCancel()
        pending?.resume(with: result)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil); finish(.failure(TLRefreshFailure.redirect))
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, response.url == url else {
            completionHandler(.cancel); finish(.failure(TLRefreshFailure.invalidResponse)); return
        }
        guard http.statusCode == 200 else {
            completionHandler(.cancel); finish(.failure(TLRefreshFailure.httpStatus(http.statusCode))); return
        }
        guard response.expectedContentLength <= limit else {
            completionHandler(.cancel); finish(.failure(TLRefreshFailure.downloadTooLarge)); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard bytes.count <= limit - data.count else { finish(.failure(TLRefreshFailure.downloadTooLarge)); return }
        bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)) } else { finish(.success(bytes)) }
    }
}
