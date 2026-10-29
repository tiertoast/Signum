#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

extension PAdESStatusIntegrationTests {
    func testS02FinalizeFailureAfterValidSignatureIsNotCompletedV4AndV5() throws {
        for bound in [false,true] {try s02scenario("finalize",bound:bound)}
    }
    func testS02PrimaryVerificationErrorAndFinalizeFailureAreBothPreservedV4AndV5() throws {
        for bound in [false,true] {try s02scenario("compound",bound:bound)}
    }
    func testS02CloseSessionFailureIsExplicitAndNeverRetriedV4AndV5() throws {
        for bound in [false,true] {try s02scenario("closeSession",bound:bound)}
    }
    func testS02BlockedAndCrashedTeardownNeverConfirmCompletionV4AndV5() throws {
        for bound in [false,true] {for scenario in ["timeout","crash"] {try s02scenario(scenario,bound:bound)}}
    }
    private func s02scenario(_ scenario:String,bound:Bool) throws {
        let root=try FixtureFiles.directory("s02-cleanup");defer{try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root)
        let phase=scenario == "closeSession" ? 6:1
        let effect=scenario == "timeout" ? 2:scenario == "crash" ? 3:4
        let mock=try MockModule(certificate:signer.der,privateKey:scenario == "compound" ? nil:signer.rsaPrivateDER(),
            workerPhase:phase,workerEffect:effect,audit:true,faultAfter:scenario == "closeSession" ? 3:0)
        let inspected=try MiddlewareFileSecurity.inspect(mock.path.path,automatic:false)
        let token=SignumToken(slot:7,label:"Signum Mock",manufacturer:"Offline fixture",model:"Synthetic",reader:"Synthetic reader",serial:"SYNTHETIC-0001")
        let binding=bound ? OneShotContextTests().context(path:inspected.canonicalPath,identity:inspected.identity,token:token,der:signer.der):nil
        let source=root.appendingPathComponent("source.pdf"),bytes=try PAdESAppearanceTests().pdf();try bytes.write(to:source)
        let snapshot=try DocumentSnapshot.capture(source:source,format:.pades,privateRoot:root)
        let job=try SigningJob(snapshot:snapshot,providerPath:inspected.canonicalPath,slot:7,
            certificate:.init(label:"Synthetic",identifier:Data([1])),certificateDER:signer.der,
            destination:root.appendingPathComponent("result.pdf"),providerContext:binding)
        let operation=SigningOperation()
        let result=Result{try SignumPAdESHelper.sign(job:job,pin:"synthetic-fixture",appearanceName:"Synthetic",field:nil,
            operation:operation,executable:URL(fileURLWithPath:try FixtureRequirements.helper()),timeout:scenario == "timeout" ? 1:10)}
        switch result {
        case .success:XCTFail("Teardown fault acknowledged as success: \(scenario) bound=\(bound)")
        case .failure(let error):
            guard case SignumError.outputUncertain = error else {return XCTFail("Cleanup fault lost its uncertain outcome")}
            if scenario != "timeout" && scenario != "crash" {
                XCTAssertTrue(error.localizedDescription.lowercased().contains("chiusura"),"Cleanup notice missing: \(scenario)")
            }
            if scenario == "compound" {XCTAssertTrue(error.localizedDescription.lowercased().contains("verifica"),"Primary verification error lost")}
        }
        XCTAssertEqual(operation.state,.outcomeUncertain)
        let ops=((try? String(contentsOf:mock.folder.appendingPathComponent("operations"))) ?? "").split(separator:"\n")
        XCTAssertEqual(ops.filter{$0=="16"}.count,1,"Exactly one attempted Sign")
        XCTAssertEqual(ops.filter{$0=="8"}.count,1)
        XCTAssertEqual(ops.filter{$0=="1"}.count,1,"Finalize attempted once, never retried")
        XCTAssertEqual(try Data(contentsOf:source),bytes)
        // Legacy before-fix helpers may already have published. An uncertain
        // result must preserve that file and its valid signature, never delete it.
        if FileManager.default.fileExists(atPath:job.destination.path) {
            let published=try Data(contentsOf:job.destination)
            let verified=try SignumVerificationService.verify(data:published,name:"published.pdf",helper:URL(fileURLWithPath:try FixtureRequirements.helper()))
            XCTAssertEqual(verified.integrity,.verified)
            XCTAssertThrowsError(try job.requireAvailableDestination())
            XCTAssertEqual(try Data(contentsOf:job.destination),published)
        }
    }
    func testS02PublishedFileRequiresExplicitCleanupConfirmationAndIsPreserved() throws {
        for confirmation: Bool? in [nil,false,true] {
            let root=try FixtureFiles.directory("s02-published");defer{try? FileManager.default.removeItem(at:root)}
            let output=root.appendingPathComponent("output.pdf"),peer=root.appendingPathComponent("peer"),id=UUID()
            var status:[String:Any]=["version":4,"jobID":id.uuidString,"outcome":"published","reason":"none","documentVerified":true,"documentPublished":true]
            if let confirmation {status["cleanupConfirmed"]=confirmation}
            let json=String(decoding:try JSONSerialization.data(withJSONObject:status),as:UTF8.self)
            try Data(("#!/bin/sh\n/bin/cat >/dev/null\nprintf synthetic > \"$1\"\nprintf '%s' '"+json+"'\n").utf8).write(to:peer)
            try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:peer.path)
            var input=Data("synthetic-fixture\n".utf8)
            let outcome=PAdESHelperProcess.run(executable:peer,arguments:[output.path],input:&input,destination:output,expectedJobID:id)
            if confirmation == true {XCTAssertEqual(outcome,.published)}
            else {guard case .uncertain(let message)=outcome else {return XCTFail("Published file hid unconfirmed cleanup")};XCTAssertTrue(message.lowercased().contains("chiusura"))}
            XCTAssertEqual(try String(contentsOf:output),"synthetic")
        }
    }
    @MainActor func testS02CleanupNoticeBlocksTheActualCoordinatorBeforeTheNextDocument() async throws {
        let root=try FixtureFiles.directory("s02-coordinator");defer{try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),workerPhase:1,workerEffect:4,audit:true)
        let helper=URL(fileURLWithPath:try FixtureRequirements.helper())
        let sources=try (1...2).map{pages -> URL in
            let url=root.appendingPathComponent("source-\(pages).pdf")
            try PAdESAppearanceTests().pdf(pages:pages).write(to:url);return url
        }
        let batch=BatchSigningCoordinator(padesHelper:helper);defer{batch.reset()}
        await batch.addDocuments(sources,format:.pades)
        let approval=try await batch.prepareApproval(provider:mock.path.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:signer.der)
        try batch.confirm(approval)
        try await batch.authorizeNext(pin:"synthetic-fixture") {job,pin,operation in
            try SignumPAdESHelper.sign(job:job,pin:pin,appearanceName:"Synthetic",field:nil,operation:operation,executable:helper)
        }
        XCTAssertEqual(batch.documents[0].state,.uncertain)
        XCTAssertTrue(batch.needsOutcomeReview)
        XCTAssertTrue(batch.authenticationNotice.lowercased().contains("chiusura"))
        do {try await batch.authorizeNext(pin:"synthetic-fixture") {_,_,_ in XCTFail("Second job was authorized after unconfirmed cleanup")};XCTFail("Authorization should be blocked")}
        catch { }
        let ops=((try? String(contentsOf:mock.folder.appendingPathComponent("operations"))) ?? "").split(separator:"\n")
        XCTAssertEqual(ops.filter{$0=="16"}.count,1);XCTAssertEqual(ops.filter{$0=="1"}.count,1)
    }

}
#endif
