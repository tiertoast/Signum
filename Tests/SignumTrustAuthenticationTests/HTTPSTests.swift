import XCTest
@testable import SignumTrustAuthentication

/// Intercepts only this test's ephemeral session; no real network or URL exceptions.
private final class FixtureURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let mode = request.value(forHTTPHeaderField: "X-Fixture-Mode") ?? "ok"
        if mode == "hang" { return }
        if mode == "offline" { client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet)); return }
        let status = mode == "status" ? 503 : (mode == "redirect" ? 302 : 200)
        if mode == "redirect" {
            let destination = URLRequest(url: URL(string: EUTrustPolicy.italyLocation)!)
            let redirect = HTTPURLResponse(url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": EUTrustPolicy.italyLocation])!
            client?.urlProtocol(self, wasRedirectedTo: destination, redirectResponse: redirect)
            return
        }
        let length = mode == "header-limit" ? "99999" : "-1"
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": length])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data((mode == "body-limit" ? "123456789" : "xml").utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class HTTPSTests: XCTestCase {
    func transfer(_ mode: String) -> BoundedTLTransfer {
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = ["X-Fixture-Mode": mode]
        config.protocolClasses = [FixtureURLProtocol.self]
        return BoundedTLTransfer(url: URL(string: EUTrustPolicy.location)!, configuration: config, maximumBytes: 8)
    }
    func testBoundedTransportStatusDeclaredAndStreamingLimits() async throws {
        let accepted = try await transfer("ok").run()
        XCTAssertEqual(accepted, Data("xml".utf8))
        for mode in ["status", "redirect", "header-limit", "body-limit", "offline"] {
            do { _ = try await transfer(mode).run(); XCTFail("accepted \(mode)") }
            catch {
                switch mode {
                case "status": XCTAssertEqual(error as? TLRefreshFailure, .httpStatus(503))
                case "redirect": XCTAssertEqual(error as? TLRefreshFailure, .redirect)
                case "header-limit", "body-limit": XCTAssertEqual(error as? TLRefreshFailure, .downloadTooLarge)
                default: XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet)
                }
            }
        }
    }
    func testActiveAndPreCancelledTransfersTerminate() async throws {
        let request = transfer("hang")
        let task = Task { try await request.run() }
        try await Task.sleep(nanoseconds: 20_000_000)
        task.cancel()
        do { _ = try await task.value; XCTFail("active cancellation ignored") } catch is CancellationError {} catch { XCTFail("unexpected \(error)") }
        let next = transfer("hang")
        let preCancelled = Task { withUnsafeCurrentTask { $0?.cancel() }; return try await next.run() }
        do { _ = try await preCancelled.value; XCTFail("pre-cancellation ignored") } catch is CancellationError {} catch { XCTFail("unexpected \(error)") }
    }
    func testProductionClientRejectsUnapprovedDestination() async {
        do { _ = try await TLHTTPSClient().fetch(URL(string: "https://example.invalid/")!); XCTFail("destination accepted") }
        catch { XCTAssertEqual(error as? TLRefreshFailure, .unauthorizedURL) }
    }
}
