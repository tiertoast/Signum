#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class FileAcquisitionTests: XCTestCase {
    func fixture(_ body: (URL, URL, Data) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("synthetic.pdf")
        let bytes = Data("%PDF-1.4\nSynthetic acquisition fixture\n".utf8) + Data(repeating: 0x53, count: 160_000)
        try bytes.write(to: source)
        try body(root, source, bytes)
    }

    func testMetadataOnlyChangeDoesNotRejectCoherentPDF() throws {
        try fixture { root, source, bytes in
            var io = DocumentSnapshot.CaptureIO(), changed = false
            var sourceFD: Int32 = -1
            io.sourceOpened = { sourceFD = $0 }
            io.read = { fd, pointer, count in
                if !changed {
                    changed = true
                    var before = stat(), after = stat()
                    XCTAssertEqual(fstat(sourceFD, &before), 0)
                    let value: UInt8 = 1
                    XCTAssertEqual(withUnsafePointer(to: value) { fsetxattr(sourceFD, "org.signum.synthetic-test", $0, 1, 0, 0) }, 0)
                    XCTAssertEqual(fstat(sourceFD, &after), 0)
                    XCTAssertEqual(before.st_size, after.st_size)
                    XCTAssertEqual(before.st_mtimespec.tv_sec, after.st_mtimespec.tv_sec)
                    XCTAssertEqual(before.st_mtimespec.tv_nsec, after.st_mtimespec.tv_nsec)
                    XCTAssertTrue(before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec)
                }
                return Darwin.read(fd, pointer, count)
            }
            let snapshot = try DocumentSnapshot.capture(source: source, format: .pades, privateRoot: root, io: io)
            defer { snapshot.close() }
            XCTAssertTrue(changed)
            XCTAssertEqual(snapshot.approvedBytes, bytes)
            XCTAssertEqual(try snapshot.verifiedBytes(), bytes)
            XCTAssertEqual(try Data(contentsOf: source), bytes)
        }
    }
}
#endif
