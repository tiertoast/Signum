#if os(macOS)
import XCTest
@testable import SignumCore

final class CAdESMemoryContractTests: XCTestCase {
    // Frozen pre-14C2 composition: byte-for-byte oracle across DER length
    // boundaries. It deliberately retains the old nested materializations here.
    private func reference(_ document: Data, _ certificate: Data, _ attributes: Data,
                           _ signature: Data, signerCount: Int = 1) throws -> Data {
        let identity = try DER.certificateIdentity(certificate)
        let digest = DER.sequence([DER.sha256OID])
        var implicitAttributes = attributes; implicitAttributes[implicitAttributes.startIndex] = 0xA0
        let signer = DER.sequence([DER.integerOne, DER.sequence([identity.issuer, identity.serial]), digest,
                                   implicitAttributes, DER.sequence([DER.rsaEncryptionOID, DER.null]), DER.octets(signature)])
        let encapsulated = DER.sequence([DER.dataOID, DER.contextExplicit0(DER.octets(document))])
        let signed = DER.sequence([DER.integerOne, DER.set([digest]), encapsulated,
                                  DER.contextImplicit0(certificate), DER.set(Array(repeating: signer, count: signerCount))])
        return DER.sequence([DER.signedDataOID, DER.contextExplicit0(signed)])
    }
    func testReservedCompositionMatchesHistoricalBytesAtLengthAndSignatureBoundaries() throws {
        let certificate = try CertificateEligibilityTests.fixtures.get().der("valid")
        for size in [1,127,128,255,256,65535,65536,1024*1024] {
            let document = Data(repeating: 0xCA, count: size)
            let prepared = try CAdES.Prepared(document: document, certificateDER: certificate)
            for length in [128,256,512,1024] {
                let signature = Data(repeating: 0xAB, count: length)
                let actual = try prepared.finish(signature: signature)
                XCTAssertEqual(actual, try reference(document,certificate,prepared.attributesToSign,signature), "payload=\(size) signature=\(length)")
                XCTAssertTrue(CMSDescription.isSignedData(actual))
                XCTAssertEqual(try CMSDescription.signers(in:actual).count,1)
            }
            for invalid in [0,127,1025] { XCTAssertThrowsError(try prepared.finish(signature:Data(count:invalid))) }
        }
    }
    func testBorrowedReaderRejectsTruncatedNonminimalAndOutOfBoundsLengths() throws {
        let malformed: [[UInt8]] = [[],[0x30],[0x30,0x80],[0x30,0x81],[0x30,0x81,0x7f],
            [0x30,0x82,0,0x80],[0x30,0x85,1,1,1,1,1],[0x30,0x84,0xff,0xff,0xff,0xff], [0x30,4,1,2]]
        for bytes in malformed {
            try Data(bytes).withUnsafeBytes { (view: UnsafeRawBufferPointer) in
                var index = 0
                XCTAssertThrowsError(try DER.read(view,at:&index,limit:view.count))
            }
        }
        let bytes=Data([0x04,0x01,0x42])
        try bytes.withUnsafeBytes { (view: UnsafeRawBufferPointer) in
            for (offset,limit) in [(-1,3),(0,4),(3,3),(0,-1),(0,1)] {
                var index=offset; XCTAssertThrowsError(try DER.read(view,at:&index,limit:limit))
            }
        }
    }
    func testMetadataBorrowAcceptsDataSlicesAndReturnsOwnedStrings() throws {
        let cert=try CertificateEligibilityTests.fixtures.get().der("valid")
        let prepared=try CAdES.Prepared(document:Data(repeating:0x11,count:65536),certificateDER:cert)
        let cms=try prepared.finish(signature:Data(repeating:0xAB,count:256))
        var backing=Data(repeating:0x55,count:7); backing.append(cms)
        var slice=backing[7..<backing.endIndex]
        XCTAssertEqual(slice.startIndex,7)
        XCTAssertTrue(CMSDescription.isSignedData(slice))
        let names=try CMSDescription.signers(in:slice)
        XCTAssertEqual(names.count,1); XCTAssertTrue(names[0].contains("Synthetic"))
        slice.resetBytes(in:slice.startIndex..<slice.endIndex); backing.removeAll()
        XCTAssertTrue(names[0].contains("Synthetic"))
        XCTAssertEqual(try CMSDescription.signers(in:cms),names)
    }
    func testMetadataRejectsEveryTruncationAndTooManySignersWithoutHidingNestedCMS() throws {
        let cert=try CertificateEligibilityTests.fixtures.get().der("valid")
        let prepared=try CAdES.Prepared(document:Data([1]),certificateDER:cert)
        let cms=try prepared.finish(signature:Data(repeating:0xAB,count:256))
        for count in 0..<cms.count {
            let partial=Data(cms.prefix(count))
            XCTAssertFalse(CMSDescription.isSignedData(partial))
            XCTAssertThrowsError(try CMSDescription.signers(in:partial))
        }
        let malformed=DER.sequence([DER.signedDataOID,DER.contextExplicit0(DER.sequence([]))])
        XCTAssertTrue(CMSDescription.isSignedData(malformed),"Malformed nested envelopes must reach verification, not become extracted content")
        XCTAssertThrowsError(try CMSDescription.signers(in:malformed))
        let excessive=try reference(Data([1]),cert,prepared.attributesToSign,Data(repeating:0xAB,count:256),signerCount:33)
        XCTAssertTrue(CMSDescription.isSignedData(excessive)); XCTAssertThrowsError(try CMSDescription.signers(in:excessive))
    }
}
#endif
