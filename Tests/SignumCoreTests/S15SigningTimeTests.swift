#if os(macOS)
import XCTest
import CoreGraphics
@testable import SignumCore
@testable import SignumApp

@MainActor final class S15SigningTimeTests: XCTestCase {
    func testPreferenceThroughReviewAndJobMatchesRealAttributesForAllFormats() async throws {
        let root=try FixtureFiles.directory("s15-matrix");defer{try? FileManager.default.removeItem(at:root)}
        let signer=try SoftwareSigner(folder:root),originalFolder=root.appendingPathComponent("original-signer")
        try FileManager.default.createDirectory(at:originalFolder,withIntermediateDirectories:false)
        let original=try SoftwareSigner(folder:originalFolder),payload=Data("S15 synthetic document".utf8)
        let attached=try original.cms(for:payload)
        let mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER())
        let helper=URL(fileURLWithPath:try FixtureRequirements.helper())
        let worker=IsolatedPKCS11Client(executable:Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("SignumPKCS11Worker"))
        let suite="s15-"+UUID().uuidString,defaults=try XCTUnwrap(UserDefaults(suiteName:suite))
        defer{defaults.removePersistentDomain(forName:suite)}
        let preferences=SigningExperiencePreferences(defaults:defaults)
        for format in [SigningFormat.cades,.cadesDetached,.cadesCoSign,.cadesCounterSign,.pades,.xades,.asics,.asice] {
            for include in [false,true] {
                preferences.includeSigningTime=include
                let folder=root.appendingPathComponent(format.rawValue+"-"+String(include))
                try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:false)
                let source=folder.appendingPathComponent(format == .pades ? "input.pdf":format == .xades ? "input.xml":"input.bin")
                let input=format == .pades ? try PAdESAppearanceTests().pdf():format == .xades ? Data("<invoice>S15 synthetic</invoice>".utf8):format == .cadesCoSign || format == .cadesCounterSign ? attached:payload
                try input.write(to:source)
                var sources=[source]
                if format == .asice {let second=folder.appendingPathComponent("second.txt");try Data("second synthetic".utf8).write(to:second);sources.append(second)}
                let batch=BatchSigningCoordinator(padesHelper:helper);defer{batch.reset()}
                await batch.addDocuments(sources,format:format)
                XCTAssertEqual(batch.documents.count,1,batch.selectionIssues.joined(separator:";"))
                if format == .cadesCounterSign {
                    let entry=try XCTUnwrap(batch.documents.first)
                    try batch.selectCounterSignature(try XCTUnwrap(entry.snapshot.cmsSignatureTargets.first?.signatureKey),for:entry.id)
                }
                let review=SigningReview()
                let context=SigningReviewContext(revision:batch.revision,provider:mock.path.resolvingSymlinksInPath().path,slot:7,
                    certificate:.init(label:"Synthetic",identifier:Data([0x53])),der:signer.der,destination:.originalFolders,
                    routeID:"synthetic-route",discoveryID:UUID(),includeSigningTime:preferences.includeSigningTime)
                await review.prepare(context,batch:batch,validate:{})
                let plan=try XCTUnwrap(review.approval,review.issue),job=try XCTUnwrap(plan.jobs.first)
                XCTAssertEqual(job.includeSigningTime,include)
                let attribute=format == .pades ? "PDF /M":format == .xades || format.isASiC ? "XML SigningTime":"CMS signingTime"
                XCTAssertTrue(job.approvalDescription.contains(attribute),"Missing policy in approval: \(format) flag=\(include)")
                XCTAssertTrue(job.approvalDescription.contains("marca temporale"))
                XCTAssertEqual(job.signingTimeDeclaration,SigningTimePolicy.declaration(for:format,includeCMS:include))
                if format == .cades || format.isAdvancedCAdES {
                    XCTAssertTrue(job.signingTimeDeclaration.contains(include ? "incluso":"omesso"))
                } else {XCTAssertTrue(job.signingTimeDeclaration.contains("sempre incluso"))}
                var changed=context;changed.includeSigningTime.toggle()
                XCTAssertFalse(review.matches(changed,batch:batch),"Policy change must invalidate old consent")
                XCTAssertTrue(review.matches(context,batch:batch))
                try batch.freezeReview(plan);try batch.confirm(plan)
                preferences.includeSigningTime = !include
                XCTAssertEqual(job.includeSigningTime,include,"Approved job must stay immutable")
                let operation=SigningOperation()
                if format == .pades {
                    try SignumPAdESHelper.sign(job:job,pin:"synthetic-fixture",appearanceName:"Synthetic",field:nil,operation:operation,executable:helper)
                } else if format == .cades {
                    try job.signCAdES(using:worker,pin:"synthetic-fixture",operation:operation)
                } else {
                    try job.signXAdES(using:worker,pin:"synthetic-fixture",operation:operation,helper:helper)
                }
                XCTAssertEqual(operation.state,.completed)
                let output=try Data(contentsOf:job.destination)
                let report=try SignumVerificationService.verify(data:output,name:job.destination.lastPathComponent,
                    detachedContent:format == .cadesDetached ? payload:nil,helper:helper)
                XCTAssertEqual(report.integrity,.verified)
                let newSignature=try XCTUnwrap(report.signatures.first{$0.signerDER==signer.der})
                if format == .cadesCoSign || format == .cadesCounterSign {
                    let oldSignature=try XCTUnwrap(report.signatures.first{$0.signerDER==original.der})
                    XCTAssertFalse(oldSignature.declaredTime.isEmpty,"Existing signed time must stay intact")
                }
                XCTAssertTrue(newSignature.evidence?.timestampTokens.isEmpty == true,"Declared time is not a timestamp")
                if format == .pades {
                    let pdf=try XCTUnwrap(CGPDFDocument(try XCTUnwrap(CGDataProvider(data:output as CFData))))
                    var form:CGPDFDictionaryRef?,fields:CGPDFArrayRef?,field:CGPDFDictionaryRef?,signature:CGPDFDictionaryRef?,date:CGPDFStringRef?
                    XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(pdf.catalog),"AcroForm",&form))
                    XCTAssertTrue(CGPDFDictionaryGetArray(try XCTUnwrap(form),"Fields",&fields))
                    XCTAssertTrue(CGPDFArrayGetDictionary(try XCTUnwrap(fields),0,&field))
                    XCTAssertTrue(CGPDFDictionaryGetDictionary(try XCTUnwrap(field),"V",&signature))
                    XCTAssertTrue(CGPDFDictionaryGetString(try XCTUnwrap(signature),"M",&date))
                    XCTAssertTrue((CGPDFStringCopyTextString(try XCTUnwrap(date)) as String?)?.hasPrefix("D:") == true)
                } else if format == .xades || format.isASiC {
                    let xmlTime=try format.isASiC ? ASiC.verify(output).signature.declaredTime:XAdES.verify(output).declaredTime
                    XCTAssertNotNil(ISO8601DateFormatter().date(from:xmlTime))
                    XCTAssertEqual(newSignature.declaredTime,xmlTime)
                } else {
                    let attributes=try XCTUnwrap(newSignature.evidence).signedAttributes
                    XCTAssertEqual(attributes.filter{$0.oid=="1.2.840.113549.1.9.5"}.count,include ? 1:0)
                    XCTAssertEqual(newSignature.declaredTime.isEmpty,!include)
                }
                print("S15 matrix: \(format.rawValue) preference=\(include) verified; \(attribute) checked")
            }
        }
    }
}
#endif
