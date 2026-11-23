import XCTest
@testable import SignumCertificateValidation

final class RevocationRouteTests: XCTestCase {
    func testIPv4IsTriedFirstAndAddressesAlternate() {
        let dns = Data("""
        name: ocsp.example.eu
        ipv6_address: 2001:db8::1
        ipv6_address: 2001:db8::2
        ip_address: 93.184.216.34
        ip_address: 93.184.216.35
        ip_address: 93.184.216.34
        """.utf8)
        let parsed = RevocationRoute.addresses(fromDNS: dns)
        XCTAssertEqual(parsed.count, 5)
        XCTAssertEqual(RevocationRoute.connectionOrder(parsed), ["93.184.216.34", "2001:db8::1", "93.184.216.35"])
        XCTAssertEqual(RevocationRoute.connectionOrder(["2001:db8::1", "2001:db8::2"]), ["2001:db8::1", "2001:db8::2"])
        XCTAssertEqual(RevocationRoute.connectionOrder([]), [])
    }

    func testSystemProxySelectionHonoursSchemeAndBypassList() {
        let settings: [String: Any] = [
            "HTTPEnable": NSNumber(value: 1), "HTTPProxy": "proxy.corp.example", "HTTPPort": NSNumber(value: 3128),
            "HTTPSEnable": NSNumber(value: 1), "HTTPSProxy": "secure.corp.example", "HTTPSPort": NSNumber(value: 8443),
            "ExceptionsList": ["*.internal.example", "crl.direct.example", ".suffix.example"]]
        XCTAssertEqual(RevocationRoute.proxy(settings: settings, scheme: "http", host: "crl.ca.example"), "http://proxy.corp.example:3128")
        XCTAssertEqual(RevocationRoute.proxy(settings: settings, scheme: "https", host: "ocsp.ca.example"), "http://secure.corp.example:8443")
        XCTAssertNil(RevocationRoute.proxy(settings: settings, scheme: "http", host: "crl.direct.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: settings, scheme: "http", host: "a.internal.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: settings, scheme: "http", host: "suffix.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: [:], scheme: "http", host: "crl.ca.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: ["HTTPEnable": NSNumber(value: 0), "HTTPProxy": "p.example", "HTTPPort": NSNumber(value: 80)],
                                           scheme: "http", host: "crl.ca.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: ["HTTPEnable": NSNumber(value: 1), "HTTPProxy": "bad host", "HTTPPort": NSNumber(value: 80)],
                                           scheme: "http", host: "crl.ca.example"))
        XCTAssertNil(RevocationRoute.proxy(settings: ["HTTPEnable": NSNumber(value: 1), "HTTPProxy": "p.example", "HTTPPort": NSNumber(value: 0)],
                                           scheme: "http", host: "crl.ca.example"))
    }
}
