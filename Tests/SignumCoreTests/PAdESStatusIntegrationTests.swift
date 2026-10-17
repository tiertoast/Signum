#if os(macOS)
import XCTest
import CoreGraphics
import CProcessCoordination
@testable import SignumApp
@testable import SignumCore

final class PAdESStatusIntegrationTests: XCTestCase {
    func testNativeV4ThroughAppMappingBeforeAndAfterAuthentication() throws {
        guard let path = ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else {
            throw XCTSkip("Set SIGNUM_TEST_PADES_HELPER to the locally built helper for native end-to-end tests")
        }
        let executable = URL(fileURLWithPath: path)
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: path))
        for scenario in ["busy", "certificateChanged", "signError", "success"] {
            let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: root) }
            let signer = try SoftwareSigner(folder: root)
            let other = try CertificateEligibilityTests.fixtures.get().der("otherSigner")
            let mock = try MockModule(certificate: scenario == "certificateChanged" ? other : signer.der,
                privateKey: signer.rsaPrivateDER(), workerPhase: scenario == "signError" ? 16 : nil, workerEffect: 4, audit: true)
            let bytes = NSMutableData()
            let consumer = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
            var box = CGRect(x: 0, y: 0, width: 400, height: 500)
            let context = try XCTUnwrap(CGContext(consumer: consumer, mediaBox: &box, nil))
            context.beginPDFPage(nil); context.endPDFPage(); context.closePDF()
            let source = root.appendingPathComponent("synthetic.pdf")
            try (bytes as Data).write(to: source)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root)
            let destination = root.appendingPathComponent("result.pdf")
            let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7,
                certificate: SignumCertificate(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der, destination: destination)
            let lease = scenario == "busy" ? sg_token_lease_acquire(mock.path.path, 7, 0, 0) : nil
            if scenario == "busy" { XCTAssertNotNil(lease) }
            defer { if let lease { sg_token_lease_release(lease) } }
            let operation = SigningOperation(); operation.transition(to: .preparing)
            let result = Result { try SignumPAdESHelper.sign(job: job, pin: "synthetic-fixture", appearanceName: "Synthetic", field: nil,
                operation: operation, executable: executable, timeout: 20) }
            switch (scenario, result) {
            case ("success", .success):
                XCTAssertEqual(operation.state, .completed)
                XCTAssertTrue(FileManager.default.fileExists(atPath: destination.path))
            case ("signError", .failure(let error)):
                guard case SignumError.outputUncertain = error else { return XCTFail("Post-authentication error lost uncertainty") }
            case ("busy", .failure(let error)), ("certificateChanged", .failure(let error)):
                guard case SignumError.module = error else { return XCTFail("Pre-authentication rejection became uncertain") }
            default: XCTFail("Unexpected native mapping: \(scenario)")
            }
            let auditPath = mock.folder.appendingPathComponent("operations")
            let audit = (try? String(contentsOf: auditPath, encoding: .utf8))?.split(separator: "\n") ?? []
            let attemptedPrivate = scenario == "signError" || scenario == "success"
            XCTAssertEqual(audit.filter { $0 == "8" }.count, attemptedPrivate ? 1 : 0)
            XCTAssertEqual(audit.filter { $0 == "16" }.count, attemptedPrivate ? 1 : 0)
            if scenario == "busy" { XCTAssertTrue(audit.isEmpty) }
            if scenario != "success" { XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path)) }
            XCTAssertEqual(try Data(contentsOf: source), bytes as Data)
            XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.contains("staging") })
        }
    }
}
#endif
