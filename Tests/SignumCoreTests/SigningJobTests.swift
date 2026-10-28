#if os(macOS)
import XCTest
import Foundation
import Darwin
import PDFKit
import CoreGraphics
@testable import SignumCore

final class SoftwareSigner {
    let folder: URL
    let der: Data
    init(folder: URL) throws {
        self.folder = folder
        let config = """
        [req]
        distinguished_name=dn
        x509_extensions=signer
        [dn]
        [signer]
        basicConstraints=critical,CA:FALSE
        keyUsage=critical,digitalSignature,nonRepudiation
        """
        try Data(config.utf8).write(to: folder.appendingPathComponent("certificate.cnf"))
        try Self.run(["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "certificate.pem", "-days", "2",
                      "-subj", "/CN=Signum Synthetic Job", "-config", "certificate.cnf"], in: folder)
        try Self.run(["x509", "-in", "certificate.pem", "-outform", "DER", "-out", "certificate.der"], in: folder)
        der = try Data(contentsOf: folder.appendingPathComponent("certificate.der"))
    }
    func rsaPrivateDER() throws -> Data {
        try Self.run(["rsa", "-in", "key.pem", "-outform", "DER", "-out", "key.der"], in: folder)
        return try Data(contentsOf: folder.appendingPathComponent("key.der"))
    }
    func cms(for data: Data) throws -> Data {
        let prepared = try CAdES.Prepared(document: data, certificateDER: der)
        try prepared.attributesToSign.write(to: folder.appendingPathComponent("attributes"))
        try Self.run(["dgst", "-sha256", "-sign", "key.pem", "-out", "signature", "attributes"], in: folder)
        return try prepared.finish(signature: Data(contentsOf: folder.appendingPathComponent("signature")))
    }
    private static func run(_ args: [String], in folder: URL) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = args; process.currentDirectoryURL = folder
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); try FixtureProcess.wait(process)
        guard process.terminationStatus == 0 else { throw SignumError.module("Synthetic software CMS fixture failed") }
    }
}
final class SigningJobTests: XCTestCase {
    private let approved = Data("Synthetic document approved before signing\n".utf8)
    private enum Failure: Error { case synthetic }
    private func withJob(_ body: (SigningJob, SoftwareSigner, URL) throws -> Void) throws {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("signum-job-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("source.txt"); try approved.write(to: source)
        let signer = try SoftwareSigner(folder: folder)
        let snapshot = try DocumentSnapshot.capture(source: source, format: .cades, privateRoot: folder)
        defer { snapshot.close() }
        let job = try SigningJob(snapshot: snapshot, providerPath: "/synthetic/provider.dylib", slot: 7,
                                certificate: SignumCertificate(label: "Synthetic", identifier: Data([0x53])),
                                certificateDER: signer.der, destination: folder.appendingPathComponent("result.p7m"))
        try body(job, signer, source)
    }
    private func assertCleanFailure(_ job: SigningJob, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertFalse(FileManager.default.fileExists(atPath: job.destination.path), file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.deletingLastPathComponent().path), file: file, line: line)
        let entries = try FileManager.default.contentsOfDirectory(atPath: job.destination.deletingLastPathComponent().path)
        XCTAssertFalse(entries.contains(where: { $0.hasPrefix(".signum-staging-") }), file: file, line: line)
    }
    func testDirectoryReplacedAfterApprovalBeforeWriterCreatesNoWrongPayload() throws {
        try withJob { old, signer, _ in
            let root = old.destination.deletingLastPathComponent()
            let directory = root.appendingPathComponent("approved")
            try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
            let planned = try OutputDirectoryIdentity.inspect(directory)
            let expected = planned.1
            let job = try SigningJob(snapshot:old.snapshot,providerPath:old.providerPath,slot:old.slot,certificate:old.certificate,
                certificateDER:old.certificateDER,destination:planned.0.appendingPathComponent("result.p7m"),destinationDirectoryIdentity:expected)
            let moved = root.appendingPathComponent("moved")
            XCTAssertThrowsError(try job.executeCAdES { bytes in
                let cms = try signer.cms(for:bytes)
                try FileManager.default.moveItem(at:directory,to:moved)
                try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
                return cms
            })
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:directory.path),[])
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:moved.path),[])
        }
    }
    func testImmutableRequestContainsAllApprovedIdentities() throws {
        try withJob { job, signer, _ in
            XCTAssertEqual(job.format, .cades); XCTAssertEqual(job.slot, 7)
            XCTAssertEqual(job.snapshotIdentity, job.snapshot.identity)
            XCTAssertEqual(job.contentSHA256, DocumentSnapshot.digest(approved))
            XCTAssertEqual(job.certificateDER, signer.der)
            XCTAssertEqual(job.certificateSHA256, DocumentSnapshot.digest(signer.der))
            XCTAssertEqual(job.certificate.id, "53")
            XCTAssertEqual(job.providerPath, "/synthetic/provider.dylib")
            XCTAssertTrue(job.approvalDescription.contains(job.contentSHA256))
            XCTAssertTrue(job.approvalDescription.contains(job.destination.path))
        }
    }
    func testCAdESSignsApprovedSnapshotAfterOriginalReplacement() throws {
        try withJob { job, signer, source in
            try FileManager.default.removeItem(at: source)
            let replacement = Data("Later synthetic version".utf8); try replacement.write(to: source)
            var received: Data?
            try job.executeCAdES { bytes in received = bytes; return try signer.cms(for: bytes) }
            XCTAssertEqual(received, approved)
            XCTAssertEqual(try CAdESVerifier.verify(file: job.destination).originalDocument, approved)
            XCTAssertEqual(try Data(contentsOf: source), replacement)
            XCTAssertFalse(FileManager.default.fileExists(atPath: job.snapshot.fileURL.path))
        }
    }
    func testFailureBeforeSigningCleansAndNeverPublishes() throws {
        try withJob { job, _, _ in
            XCTAssertThrowsError(try job.executeCAdES { _ in throw Failure.synthetic })
            try assertCleanFailure(job)
        }
    }
    func testFailureAfterSigningBeforeCommitCleansAndNeverPublishes() throws {
        try withJob { job, signer, _ in
            var io = SignumFileOutput.OutputIO(), signed = false
            io.beforePublish = { throw Failure.synthetic }
            XCTAssertThrowsError(try job.executeCAdES(io: io) { bytes in signed = true; return try signer.cms(for: bytes) })
            XCTAssertTrue(signed)
            try assertCleanFailure(job)
        }
    }
    func testMissingSnapshotFailsBeforeSignerAndNeverFallsBack() throws {
        try withJob { job, _, _ in
            try FileManager.default.removeItem(at: job.snapshot.fileURL)
            var invoked = false
            XCTAssertThrowsError(try job.executeCAdES { _ in invoked = true; return Data([1]) })
            XCTAssertFalse(invoked); try assertCleanFailure(job)
        }
    }
    func testCorruptedSnapshotBeforeSigningFailsBeforeSigner() throws {
        try withJob { job, _, _ in
            XCTAssertEqual(chmod(job.snapshot.fileURL.path, 0o600), 0)
            try Data(repeating: 0x58, count: approved.count).write(to: job.snapshot.fileURL)
            var invoked = false
            XCTAssertThrowsError(try job.executeCAdES { _ in invoked = true; return Data([1]) })
            XCTAssertFalse(invoked); try assertCleanFailure(job)
        }
    }
    func testSnapshotCorruptedAfterSigningIsNotPublished() throws {
        try withJob { job, signer, _ in
            XCTAssertThrowsError(try job.executeCAdES { bytes in
                let cms = try signer.cms(for: bytes)
                XCTAssertEqual(chmod(job.snapshot.fileURL.path, 0o600), 0)
                try Data(repeating: 0x58, count: approved.count).write(to: job.snapshot.fileURL)
                return cms
            })
            try assertCleanFailure(job)
        }
    }
    func testValidCMSOfDifferentDocumentIsRejectedBeforeCommit() throws {
        try withJob { job, signer, _ in
            XCTAssertThrowsError(try job.executeCAdES { _ in try signer.cms(for: Data("Unapproved".utf8)) })
            try assertCleanFailure(job)
        }
    }
    func testCertificateChangedDuringJobBlocksBeforeLogin() throws {
        try withJob { old, _, _ in
            let mock = try MockModule(), module = try PKCS11Module(path: mock.path.path)
            // This test owns one synchronous raw module. Complete checked
            // disposal before releasing its fixture loader handle. Async deinit
            // remains exercised separately by PKCS11LifecycleIntegrationTests.
            defer { XCTAssertNoThrow(try module.closeInWorker()) }
            let job = try SigningJob(snapshot: old.snapshot, providerPath: module.modulePath, slot: old.slot,
                                    certificate: old.certificate, certificateDER: old.certificateDER, destination: old.destination)
            let replacement = try CertificateEligibilityTests.fixtures.get().der("replaced")
            replacement.withUnsafeBytes { mock.setCertificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count) }
            XCTAssertThrowsError(try job.signCAdES(using: module, pin: "synthetic-value"))
            XCTAssertEqual(mock.count(8), 0); XCTAssertEqual(mock.count(16), 0)
            try assertCleanFailure(job)
        }
    }
    func testWrongProviderIsRejectedBeforeLogin() throws {
        try withJob { job, _, _ in
            let mock = try MockModule(), module = try PKCS11Module(path: mock.path.path)
            // This test owns one synchronous raw module. Complete checked
            // disposal before releasing its fixture loader handle. Async deinit
            // remains exercised separately by PKCS11LifecycleIntegrationTests.
            defer { XCTAssertNoThrow(try module.closeInWorker()) }
            XCTAssertThrowsError(try job.signCAdES(using: module, pin: "synthetic-value"))
            XCTAssertEqual(mock.count(8), 0); try assertCleanFailure(job)
        }
    }
    // Input is validated first (S03); cancellation must still retire the
    // displayed snapshot before any Login/Sign, preserving consent semantics.
    func testCLIApprovesSnapshotDigestAndCancellationCleansBeforeAuthentication() throws {
        try withJob { old, signer, source in
            let mock=try MockModule(certificate:signer.der,audit:true)
            let cli=Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumCLI")
            let target=source.deletingLastPathComponent().appendingPathComponent("cli.p7m")
            var copy:URL?
            let result=try S03CLITerminalFixture.run(arguments:[cli.path,"sign-cades","7","53",source.path,target.path,mock.path.path],root:mock.folder,onReview:{description in
                XCTAssertTrue(description.contains(old.contentSHA256),description)
                XCTAssertTrue(description.contains("scrivi FIRMA"),description)
                let line=try XCTUnwrap(description.components(separatedBy:.newlines).first{$0.hasPrefix("Copia privata da controllare: ")})
                let url=URL(fileURLWithPath:String(line.dropFirst("Copia privata da controllare: ".count)))
                copy=url;XCTAssertTrue(FileManager.default.fileExists(atPath:url.path))
                try Data("Changed after CLI approval request".utf8).write(to:source)
                return "ANNULLA\n"
            })
            let displayedCopy=try XCTUnwrap(copy)
            XCTAssertEqual(result.exit,1);XCTAssertTrue(result.error.contains("annullata"),result.error)
            XCTAssertFalse(result.error.contains("Token PIN"))
            XCTAssertTrue(result.protected);XCTAssertTrue(result.restored);XCTAssertTrue(result.clean)
            XCTAssertFalse(FileManager.default.fileExists(atPath:target.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath:displayedCopy.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath:displayedCopy.deletingLastPathComponent().path))
            XCTAssertEqual(try old.verifiedBytes(),approved)
            let operations=try String(contentsOf:mock.folder.appendingPathComponent("operations")).split(separator:"\n")
            XCTAssertFalse(operations.contains("8"));XCTAssertFalse(operations.contains("16"))
        }
    }
    func testPDFKitPreviewAndJobUseSameSnapshotAfterOriginalChanges() throws {
        try withJob { old, _, source in
            func pdf(width: CGFloat) throws -> Data {
                let bytes = NSMutableData()
                let consumer = try XCTUnwrap(CGDataConsumer(data: bytes as CFMutableData))
                var box = CGRect(x: 0, y: 0, width: width, height: 120)
                let context = try XCTUnwrap(CGContext(consumer: consumer, mediaBox: &box, nil))
                context.beginPDFPage(nil); context.setFillColor(CGColor(gray: 0.5, alpha: 1))
                context.fill(CGRect(x: 10, y: 10, width: 20, height: 20)); context.endPDFPage(); context.closePDF()
                return bytes as Data
            }
            let expected = try pdf(width: 100); try expected.write(to: source)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: source.deletingLastPathComponent())
            defer { snapshot.close() }
            let preview = try XCTUnwrap(PDFDocument(data: snapshot.approvedBytes))
            let job = try SigningJob(snapshot: snapshot, providerPath: old.providerPath, slot: old.slot,
                                    certificate: old.certificate, certificateDER: old.certificateDER,
                                    destination: source.deletingLastPathComponent().appendingPathComponent("result.pdf"))
            try pdf(width: 300).write(to: source)
            XCTAssertEqual(preview.page(at: 0)?.bounds(for: .mediaBox).width, 100)
            XCTAssertEqual(try job.verifiedBytes(), expected)
            XCTAssertEqual(job.contentSHA256, DocumentSnapshot.digest(expected))
            XCTAssertNotEqual(try Data(contentsOf: source), expected)
        }
    }
}
#endif
