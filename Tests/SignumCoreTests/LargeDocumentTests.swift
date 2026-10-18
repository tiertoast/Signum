#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore
@testable import SignumApp

final class LargeDocumentTests: XCTestCase {
    private let mib = 1024 * 1024
    private func fixture(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }
    // A valid PDF with an unreferenced padding stream. No personal content or
    // committed large assets; write chunks and keep xref/EOF close to the end.
    private func pdf(_ path: URL, size: Int) throws {
        var prefix = Data("%PDF-1.4\n%\(path.lastPathComponent)\n".utf8), offsets = [Int]()
        for (i, object) in ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 500] /Resources << >> >>"].enumerated() {
            offsets.append(prefix.count); prefix.append(Data("\(i+1) 0 obj\n\(object)\nendobj\n".utf8))
        }
        let padding = size - 1024
        offsets.append(prefix.count); prefix.append(Data("4 0 obj\n<< /Length \(padding) >>\nstream\n".utf8))
        let endStream = Data("\nendstream\nendobj\n".utf8), xref = prefix.count + padding + endStream.count
        var suffix = endStream + Data("xref\n0 5\n0000000000 65535 f \n".utf8)
        for offset in offsets { suffix.append(Data(String(format: "%010d 00000 n \n", offset).utf8)) }
        suffix.append(Data("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n\(xref)\n%%EOF\n".utf8))
        XCTAssertLessThanOrEqual(prefix.count + padding + suffix.count, size)
        suffix.append(Data(repeating: 0x20, count: size - prefix.count - padding - suffix.count))
        XCTAssertTrue(FileManager.default.createFile(atPath: path.path, contents: nil, attributes: [.posixPermissions: 0o600]))
        let file = try FileHandle(forWritingTo: path); defer { try? file.close() }
        try file.write(contentsOf: prefix)
        let chunk = Data(repeating: 0x20, count: 65536)
        var remaining = padding
        while remaining > 0 { let count = min(chunk.count, remaining); try file.write(contentsOf: chunk.prefix(count)); remaining -= count }
        try file.write(contentsOf: suffix)
    }
    private func peak(_ label: String) {
        var usage = rusage(); _ = getrusage(RUSAGE_SELF, &usage)
        print("Synthetic memory observation \(label): process peak RSS \(usage.ru_maxrss) bytes")
    }
    func testAcquisitionSizeMatrixForBothFormats() throws {
        try fixture { root in
            for size in [mib, 16*mib, 16*mib+1, 50*mib, 100*mib] {
                let file = root.appendingPathComponent("size-\(size).pdf"); try pdf(file, size: size)
                for format in [SigningFormat.cades, .pades] {
                    let snapshot = try DocumentSnapshot.capture(source: file, format: format)
                    XCTAssertEqual(snapshot.identity.byteCount, size)
                    XCTAssertEqual(try snapshot.verifiedBytes().count, size)
                    snapshot.close(); XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
                }
                try FileManager.default.removeItem(at: file)
            }
            peak("acquisition matrix through 100 MiB")
        }
    }
    func testUnsupported100MiBPlusOneAnd200MiBAreReportedAsSizeNotModification() throws {
        try fixture { root in
            let file = root.appendingPathComponent("too-large.pdf")
            let fd = Darwin.open(file.path, O_CREAT | O_WRONLY, 0o600); defer { Darwin.close(fd) }
            for size in [100*mib+1, 200*mib] {
                XCTAssertEqual(ftruncate(fd, off_t(size)), 0)
                for format in [SigningFormat.cades, .pades] {
                    XCTAssertThrowsError(try DocumentSnapshot.capture(source: file, format: format)) {
                        XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, .tooLarge)
                        XCTAssertFalse($0.localizedDescription.contains("modificato"))
                    }
                }
            }
        }
    }
    func test100MiBCAdESWorkerVerifiedPublicationAndPartialOutputFailure() throws {
        try fixture { root in
            let signer = try SoftwareSigner(folder: root)
            let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
            let source = root.appendingPathComponent("large-cades.pdf"); try pdf(source, size: 100*mib)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .cades)
            let hash = snapshot.identity.sha256
            let output = root.appendingPathComponent("large.pdf.p7m")
            let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der, destination: output)
            let worker = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
            try job.signCAdES(using: IsolatedPKCS11Client(executable: worker), pin: "synthetic-fixture", operation: SigningOperation())
            let verified = try CAdESVerifier.verify(file: output)
            XCTAssertEqual(verified.originalDocument.count, 100*mib)
            XCTAssertEqual(DocumentSnapshot.digest(verified.originalDocument), hash)
            XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
            let next = try DocumentSnapshot.capture(source: source, format: .cades)
            let failed = root.appendingPathComponent("failed.p7m")
            let second = try SigningJob(snapshot: next, providerPath: mock.path.path, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der, destination: failed)
            var io = SignumFileOutput.OutputIO(), writes = 0
            io.write = { fd, bytes, count in
                writes += 1
                if writes == 1 { return Darwin.write(fd, bytes, min(count, 1024)) }
                errno = ENOSPC; return -1
            }
            XCTAssertThrowsError(try second.executeCAdES(io: io) { try signer.cms(for: $0) })
            XCTAssertFalse(FileManager.default.fileExists(atPath: failed.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: next.fileURL.path))
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: root.path).contains { $0.hasPrefix(".signum-staging-") })
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: source.path)[.size] as? Int, 100*mib)
            peak("100 MiB CAdES verified and partial-write failure")
        }
    }
    func test100MiBPAdESNativeVerifiedPublication() throws {
        guard let helper = ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"] else { throw XCTSkip("Explicit native helper required") }
        try fixture { root in
            let signer = try SoftwareSigner(folder: root)
            let mock = try MockModule(certificate: signer.der, privateKey: signer.rsaPrivateDER(), audit: true)
            let source = root.appendingPathComponent("large-pades.pdf"); try pdf(source, size: 100*mib)
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades)
            let output = root.appendingPathComponent("signed.pdf")
            let job = try SigningJob(snapshot: snapshot, providerPath: mock.path.path, slot: 7,
                certificate: .init(label: "Synthetic", identifier: Data([1])), certificateDER: signer.der, destination: output)
            let operation = SigningOperation()
            try SignumPAdESHelper.sign(job: job, pin: "synthetic-fixture", appearanceName: "Synthetic", field: nil,
                operation: operation, executable: URL(fileURLWithPath: helper))
            XCTAssertEqual(operation.state, .completed)
            XCTAssertGreaterThan(try FileManager.default.attributesOfItem(atPath: output.path)[.size] as? Int ?? 0, 100*mib)
            XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.fileURL.path))
            peak("100 MiB PAdES; helper RSS is separate")
        }
    }
    @MainActor func testLargeBatchKeepsSeparateSessionLimitAndRejectsExcess() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let batch = BatchSigningCoordinator(); defer { batch.reset() }
        for index in 1...3 {
            let source = root.appendingPathComponent("batch-\(index).pdf"); try pdf(source, size: 50*mib)
            await batch.addDocuments([source], format: index == 3 ? .pades : .cades)
        }
        XCTAssertEqual(batch.documents.count, 2)
        XCTAssertTrue(batch.selectionIssues.contains { $0.contains("totale") && $0.contains("128") })
        XCTAssertFalse(batch.isApproved); XCTAssertNil(batch.approval)
        peak("batch 50+50 MiB, third rejected at 128 MiB")
    }
    func testLargeCaptureCancellationAndDeadlineRemovePrivateCopies() throws {
        try fixture { root in
            let source = root.appendingPathComponent("cancel.pdf"); try pdf(source, size: 100*mib)
            for timeout in [false, true] {
                var io = DocumentSnapshot.CaptureIO(), stop = false
                io.clock = { stop && timeout ? 40 : 1 }
                io.read = { fd, p, n in stop = true; return Darwin.read(fd, p, n) }
                XCTAssertThrowsError(try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io,
                    isCancelled: { stop && !timeout })) {
                    XCTAssertEqual(($0 as? DocumentAcquisitionFailure)?.kind, timeout ? .timeout : .cancelled)
                }
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["cancel.pdf"])
            }
        }
    }
}
#endif
