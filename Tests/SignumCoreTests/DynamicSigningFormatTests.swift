#if os(macOS)
import XCTest
@testable import SignumCore
@testable import SignumApp

@MainActor final class DynamicSigningFormatTests: XCTestCase {
    func testRepeatedChangesPreserveSnapshotIdentityBytesAndOriginal() async throws {
        try await SigningFormatStabilizationTests().fixture { _,batch,file in
            await batch.addDocuments([file],format:.cades)
            let snapshot=batch.documents[0].snapshot, identity=batch.documents[0].snapshot.identity
            let original=try Data(contentsOf:file)
            for index in 0..<20 {
                let format:SigningFormat = index%2 == 0 ? .pades : .cades
                let previous=batch.revision
                try batch.setFormat(format,for:identity.id)
                XCTAssertEqual(batch.documents[0].format,format)
                XCTAssertNotEqual(batch.revision,previous)
                XCTAssertTrue(snapshot === batch.documents[0].snapshot)
                XCTAssertEqual(snapshot.identity,identity); XCTAssertEqual(snapshot.format,.cades)
                XCTAssertEqual(try snapshot.verifiedBytes(),original)
                XCTAssertEqual(try Data(contentsOf:file),original)
            }
        }
    }
    func testIndividualFormatsReplanNamesAndCollisionsWithoutChangingOtherDocuments() async throws {
        try await SigningFormatStabilizationTests().fixture { root,batch,file in
            await batch.addDocuments([file],format:.cades)
            let other=root.appendingPathComponent("other.pdf")
            var bytes=try Data(contentsOf:file);bytes.append(Data("\n% second".utf8));try bytes.write(to:other)
            await batch.addDocuments([other],format:.cades)
            let existing=root.appendingPathComponent("synthetic-firmato.pdf");try Data("PRESERVE".utf8).write(to:existing)
            try batch.setFormat(.pades,for:batch.documents[0].id)
            XCTAssertEqual(batch.documents.map(\.format),[.pades,.cades])
            let der=try CertificateEligibilityTests.fixtures.get().der("valid")
            let first=try await batch.prepareReview(provider:"/synthetic/provider",slot:7,
                certificate:.init(label:"Synthetic",identifier:Data([1])),der:der,destination:.originalFolders)
            XCTAssertEqual(first.jobs.map(\.format),[.pades,.cades])
            XCTAssertEqual(first.jobs[0].destination.lastPathComponent,"synthetic-firmato (2).pdf")
            try batch.setFormat(.cades,for:batch.documents[0].id)
            XCTAssertNil(batch.review); XCTAssertThrowsError(try batch.freezeReview(first))
            let second=try await batch.prepareReview(provider:"/synthetic/provider",slot:7,
                certificate:.init(label:"Synthetic",identifier:Data([1])),der:der,destination:.originalFolders)
            XCTAssertEqual(second.jobs[0].destination.lastPathComponent,"synthetic.pdf.p7m")
            XCTAssertEqual(second.jobs[1].destination,first.jobs[1].destination)
            XCTAssertEqual(try String(contentsOf:existing),"PRESERVE")
            try batch.freezeReview(second);try batch.confirm(second)
            XCTAssertThrowsError(try batch.setFormat(.pades,for:batch.documents[0].id))
            XCTAssertEqual(batch.approval?.jobs.map(\.format),[.cades,.cades])
        }
    }
    func testFormatChangeDuringPreflightCannotPublishOrApprovePreviousPlan() async throws {
        try await SigningFormatStabilizationTests().fixture { _,batch,file in
            await batch.addDocuments([file],format:.cades)
            let context=SigningReviewContext(revision:batch.revision,provider:"/synthetic/provider",slot:7,
                certificate:.init(label:"Synthetic",identifier:Data([1])),der:try CertificateEligibilityTests.fixtures.get().der("valid"),
                destination:.originalFolders,routeID:"synthetic",discoveryID:UUID())
            let entered=expectation(description:"preflight"), release=DispatchSemaphore(value:0), review=SigningReview()
            let task=Task { await review.prepare(context,batch:batch,validate:{ entered.fulfill(); _=release.wait(timeout:.now()+5) }) }
            await fulfillment(of:[entered],timeout:5)
            try batch.setFormat(.pades,for:batch.documents[0].id)
            release.signal();await task.value
            XCTAssertNil(review.approval);XCTAssertNil(batch.review);XCTAssertFalse(batch.isApproved)
        }
    }
    func testNonPDFCannotBeSelectedAsPAdESAndForgedHeaderCannotReachApproval() async throws {
        try await SigningFormatStabilizationTests().fixture { root,batch,_ in
            let file=root.appendingPathComponent("text.txt");try Data("not a PDF".utf8).write(to:file)
            await batch.addDocuments([file],format:.cades)
            XCTAssertThrowsError(try batch.setFormat(.pades,for:batch.documents[0].id))
            XCTAssertEqual(batch.documents[0].format,.cades)
            batch.reset();try Data("%PDF-1.7\nmalformed".utf8).write(to:file)
            await batch.addDocuments([file],format:.cades)
            try batch.setFormat(.pades,for:batch.documents[0].id)
            do {
                _ = try await batch.prepareReview(provider:"/synthetic/provider",slot:7,
                    certificate:.init(label:"Synthetic",identifier:Data([1])),der:CertificateEligibilityTests.fixtures.get().der("valid"),destination:.originalFolders)
                XCTFail("Malformed PDF cannot be approved")
            } catch {}
            XCTAssertNil(batch.review)
        }
    }
    func testActualCAdESAndPAdESOutputsFollowChangedConfigurationAndStayFrozen() async throws {
        let helper = try FixtureRequirements.helper()
        let worker=Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker")
        for chosen in [SigningFormat.pades,.cades] {
            try await SigningFormatStabilizationTests().fixture { root,batch,file in
                let original=try Data(contentsOf:file), acquisition:SigningFormat = chosen == .pades ? .cades : .pades
                let signer=try SoftwareSigner(folder:root), mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),audit:true)
                await batch.addDocuments([file],format:acquisition)
                let snapshot=batch.documents[0].snapshot
                let previousDestination=BatchOutputDestination.originalFolders.proposedURL(for:snapshot,format:acquisition)
                try batch.setFormat(chosen,for:snapshot.identity.id)
                let plan=try await batch.prepareReview(provider:mock.path.path,slot:7,
                    certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der,destination:.originalFolders)
                try batch.freezeReview(plan);try batch.confirm(plan)
                XCTAssertThrowsError(try batch.setFormat(acquisition,for:snapshot.identity.id))
                try await batch.authorizeNext(pin:"synthetic-fixture") { job,pin,operation in
                    if job.format == .cades { try job.signCAdES(using:IsolatedPKCS11Client(executable:worker),pin:pin,operation:operation) }
                    else { try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"unused",field:nil,operation:operation,executable:URL(fileURLWithPath:helper)) }
                }
                XCTAssertEqual(batch.documents[0].state,.completed,batch.documents[0].result)
                let job=plan.jobs[0], output=try Data(contentsOf:job.destination)
                XCTAssertEqual(job.format,chosen);XCTAssertFalse(FileManager.default.fileExists(atPath:previousDestination.path))
                if chosen == .cades { XCTAssertEqual(try CAdESVerifier.verify(data:output).originalDocument,original) }
                else {
                    XCTAssertTrue(output.starts(with:original))
                    let result=try SignumVerificationService.verify(data:output,name:"synthetic.pdf",helper:URL(fileURLWithPath:helper))
                    XCTAssertEqual(result.format,.pades);XCTAssertEqual(result.signatures.first?.integrity,.verified)
                }
                XCTAssertEqual(try Data(contentsOf:file),original)
                XCTAssertThrowsError(try batch.setFormat(acquisition,for:snapshot.identity.id))
            }
        }
    }
}
#endif
