import XCTest
import PDFKit
import CoreText
@testable import SignumApp
@testable import SignumCore
@testable import SignumCertificateValidation
@testable import SignumVerificationReports

final class VerificationReportExportTests: XCTestCase {
    let at=Date(timeIntervalSince1970:1792584000)
    let later=Date(timeIntervalSince1970:1792587600)
    func signature(_ id: Int=0,integrity: CryptographicIntegrity = .verified,parent: String?=nil,name: String="Alex Test - certificato sintetico") -> SignatureVerificationResult {
        var s=SignatureVerificationResult(id:id,integrity:integrity,certificate:.init(subject:name,issuer:"Autorità Test (sintetica)",sha256:String(repeating:"b",count:64)),algorithm:"rsaEncryption / sha256",declaredTime:"Oct 20 07:22:23 2026 GMT",reason:"Integrità: esito individuale del motore.",signedRevisionEnd:nil,laterChanges:false,cmsLayer:1)
        s.counterSignatureOf=parent;s.cmsSignerPath=String(id)
        s.signerDER=Data("SECRET_DER_NOT_FOR_EXPORT".utf8)
        let value=Data("signature-value-\(id)".utf8)
        s.evidence = .init(signatureValue:value,signatureKey:DocumentSnapshot.digest(value),signerIndex:id,signedAttributes:[],unsignedAttributes:[],timestampTokens:[Data("SECRET_TIMESTAMP_TOKEN".utf8)],embedded:[],issue:"")
        return s
    }
    func report(_ signatures: [SignatureVerificationResult],format: VerifiedDocumentFormat = .cades,name: String="Contratto sintetico.pdf.p7m",state: String="signed") -> VerificationReport {
        var r=VerificationReport(id:UUID(),documentName:name,sha256:String(repeating:"a",count:64),format:format,signatures:signatures,documentState:state,issue:state == "signed" ? "":"Struttura non supportata dal motore.",previewPDF:Data("SECRET_ORIGINAL_PREVIEW".utf8),originalContent:Data("SECRET_ORIGINAL_DOCUMENT".utf8))
        if format == .cades && name.hasSuffix(".p7s") {r.detachedContentSHA256=String(repeating:"c",count:64)}
        return r
    }
    func validation(_ id: Int=0,path: CertificatePathState = .verified,revocation: SignatureRevocationState = .good,time: SignatureTimeState = .notProven,q: SignatureQualificationState = .indeterminate,reason: String="Le evidenze disponibili non consentono una conclusione ulteriore.") -> CompleteSignatureValidationResult {
        let p=CertificatePathResult(state:path,evaluatedAt:at,path:[.init(sha256:String(repeating:"b",count:64),subject:"Certificato sintetico")],service:nil,alternativeServices:[],reason:"Percorso X.509 valutato separatamente.")
        let e=SignatureEvidenceValidationResult(signatureID:id,revocation:.init(state:revocation,reason:"Revoca: evidenza del motore.",certificates:[]),time:.init(state:time,declaredSigningTime:"Oct 20 07:22:23 2026 GMT",provenTime:time == .proven ? at.addingTimeInterval(-60):nil,reason:"La data dichiarata non è una prova temporale.",authorities:[]),associations:[])
        let qual=SignatureQualificationResult(signatureID:id,state:q,qualifiedCertificate:.demonstrated,qscd:.indeterminate,evaluatedAt:at,service:nil,reason:reason,statements:nil,evaluationMode:.currentTime,verificationDate:at)
        return .init(signatureID:id,path:p,evidence:e,qualification:qual)
    }
    func document(signatures: [SignatureVerificationResult]?=nil,validations: [CompleteSignatureValidationResult]?=nil) throws -> VerificationReportDocument {
        try .init(report:report(signatures ?? [signature()]),validations:validations ?? [validation()],verificationDate:at,exportedAt:later,productVersion:"0.6 - test sintetico")
    }
    func temporary(_ body: (URL) throws -> Void) throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("signum-reports-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer {try? FileManager.default.removeItem(at:root)};try body(root)
    }
    func testBothFormatsRetainFiveTypedOutcomesReasonsAndDistinctDates() throws {
        let d=try document(),text=d.plainText,pdf=try XCTUnwrap(PDFDocument(data:VerificationReportPDF.data(d))),pdfText=try XCTUnwrap(pdf.string)
        for value in ["Integrità crittografica","Attendibilità X.509","Revoca","Evidenze temporali","Qualificazione eIDAS",String(repeating:"a",count:64),"20/10/2026 07:22:23 UTC",VerificationReportDocument.date(at),VerificationReportDocument.date(later),"Tempo non comprovato","Indeterminata","La data dichiarata non è una prova temporale."] {
            XCTAssertTrue(text.contains(value),value);XCTAssertTrue(pdfText.contains(value),value)
        }
        for secret in ["SECRET_DER","SECRET_TIMESTAMP_TOKEN","SECRET_ORIGINAL_PREVIEW","SECRET_ORIGINAL_DOCUMENT"] {XCTAssertFalse(text.contains(secret));XCTAssertFalse(pdfText.contains(secret))}
        XCTAssertFalse(text.contains("Esistenza comprovata entro:"));XCTAssertGreaterThan(pdf.pageCount,1)
        for i in 0..<pdf.pageCount {XCTAssertTrue(pdf.page(at:i)?.annotations.isEmpty == true);XCTAssertEqual(pdf.page(at:i)!.bounds(for:.mediaBox).width,595.28,accuracy:0.1)}
    }
    func testInvalidRevokedAndUnprovenResultsRemainIndependentWithoutPromotingQES() throws {
        let d=try document(signatures:[signature(integrity:.invalid)],validations:[validation(path:.invalid,revocation:.revoked,time:.invalid)])
        XCTAssertEqual(d.signers[0].outcomes.map(\.state),[CryptographicIntegrity.invalid.description,"Percorso non valido","Revocato","Evidenza temporale non valida","Indeterminata"])
        XCTAssertTrue(d.plainText.contains("Certificato qualificato: Dimostrato"))
        XCTAssertFalse(d.plainText.contains("Qualificazione eIDAS: Firma elettronica qualificata"))
        let missing=try document(validations:[])
        XCTAssertEqual(missing.signers[0].outcomes.dropFirst().map(\.state),Array(repeating:"Non valutata",count:4))
        XCTAssertTrue(missing.plainText.contains("Valutazione incompleta"))
    }
    func testQualificationUsesOnlyTheProvidedTypedClassificationIncludingCurrentWithoutTimestamp() throws {
        for state in [SignatureQualificationState.electronic,.advanced,.qualified,.indeterminate] {
            let d=try document(validations:[validation(q:state,reason:"Verdetto tipizzato specifico.")])
            XCTAssertEqual(d.signers[0].outcomes[4].state,state.description)
            XCTAssertEqual(d.signers[0].outcomes[4].reason,"Verdetto tipizzato specifico.")
            XCTAssertTrue(d.plainText.contains("Tempo non comprovato"))
            XCTAssertFalse(d.plainText.contains("Esistenza comprovata entro:"))
        }
    }
    func testMultipleCoAndCounterSignaturesHaveIndividualResultsAndBoundRelations() throws {
        let root=signature(),second=signature(1,name:"Secondo Test"),counter=signature(2,parent:root.evidence!.signatureKey,name:"Controfirmatario Test")
        let d=try document(signatures:[root,second,counter],validations:[validation(),validation(1,revocation:.revoked),validation(2,path:.notVerifiable)])
        XCTAssertEqual(d.signers.count,3)
        XCTAssertTrue(d.signers[0].fields.contains{$0.value=="Cofirmatari del contenuto CMS: 1, 2"})
        XCTAssertTrue(d.signers[2].fields.contains{$0.value=="Controfirma della firma 1"})
        XCTAssertTrue(d.signers[2].fields.contains{$0.value==root.evidence!.signatureKey})
        XCTAssertEqual(d.signers[1].outcomes[2].state,"Revocato");XCTAssertEqual(d.signers[2].outcomes[1].state,"Percorso non verificabile")
        XCTAssertTrue(try XCTUnwrap(PDFDocument(data:VerificationReportPDF.data(d))?.string).contains("Controfirma della firma 1"))
    }
    func testSupportedFormatsDetachedHashAndNoInventedRelationships() throws {
        for format in [VerifiedDocumentFormat.cades,.pades,.xml,.asic,.unknown] {
            let s=signature()
            let r=report([s],format:format,name:format == .cades ? "documento.p7s":"documento")
            let d=try VerificationReportDocument(report:r,validations:[validation()],verificationDate:at,exportedAt:later)
            XCTAssertFalse(d.format.isEmpty);XCTAssertTrue(d.plainText.contains(d.format))
            if format == .cades {XCTAssertTrue(d.plainText.contains("Contenuto separato SHA-256: "+String(repeating:"c",count:64)))}
            if format != .cades {XCTAssertFalse(d.plainText.contains("Cofirmatari del contenuto CMS"))}
        }
        let empty=try VerificationReportDocument(report:report([],format:.unknown,state:"damaged"),validations:[],verificationDate:at,exportedAt:later)
        XCTAssertTrue(try XCTUnwrap(PDFDocument(data:VerificationReportPDF.data(empty))?.string).contains("Nessun risultato individuale"))
    }
    func testRejectsUnknownDuplicateSignatureIDsAndMismatchedObservationDate() throws {
        XCTAssertThrowsError(try document(validations:[validation(2)]))
        XCTAssertThrowsError(try document(validations:[validation(),validation()]))
        XCTAssertThrowsError(try document(signatures:[signature(),signature()]))
        XCTAssertThrowsError(try VerificationReportDocument(report:report([signature()]),validations:[validation()],verificationDate:later,exportedAt:later))
        XCTAssertThrowsError(try VerificationReportDocument(report:report([signature()]),validations:[],verificationDate:later,exportedAt:at))
    }
    func testControlsAndBidiCannotInjectReportRowsOrHideText() throws {
        let d=try document(signatures:[signature(name:"Test\nQUALIFICATA\u{202e}\u{0000}\u{001b}")])
        XCTAssertTrue(d.plainText.contains("Test\\u{000A}QUALIFICATA\\u{202E}\\u{0000}\\u{001B}"))
        XCTAssertFalse(d.plainText.contains("\u{202e}"));XCTAssertFalse(d.plainText.contains("\u{0000}"))
    }
    func testLongNamesUnicodeReasonsAndUnbrokenStringsPaginateWithinMargins() throws {
        let d=try document(signatures:[signature(name:String(repeating:"Èlodie Müller Ελληνικά ",count:30))],validations:[validation(reason:String(repeating:"Motivazione dettagliata del motore. ",count:100)+String(repeating:"A",count:1500))])
        let layout=try ReportPDFLayout(d);XCTAssertGreaterThan(layout.pages.count,3)
        for page in layout.pages {
            XCTAssertFalse(page.lines.isEmpty)
            for line in page.lines {
                XCTAssertGreaterThanOrEqual(line.x,44);XCTAssertGreaterThanOrEqual(line.y,110)
                XCTAssertLessThanOrEqual(line.y+line.height,776.1)
                let ct=CTLineCreateWithAttributedString(line.text)
                let width=CTLineGetTypographicBounds(ct,nil,nil,nil)-CTLineGetTrailingWhitespaceWidth(ct)
                XCTAssertLessThanOrEqual(line.x+width,552,"Overflow: "+line.text.string)
                if line.x==44,line.height==15,line.ink.r==ReportPDFLayout.Ink.accent.r,
                   let font=line.text.attribute(NSAttributedString.Key(kCTFontAttributeName as String),at:0,effectiveRange:nil),CTFontGetSize(font as! CTFont)==9 {
                    XCTAssertLessThanOrEqual(width,120.1,"Etichetta troppo vicina al valore: "+line.text.string)
                }
            }
        }
        let pdf=try XCTUnwrap(PDFDocument(data:VerificationReportPDF.data(d)))
        XCTAssertEqual(pdf.pageCount,layout.pages.count);XCTAssertTrue(pdf.string?.contains("Motivazione dettagliata") == true)
    }
    func testOutputIsExclusiveAtomicAndRefusesSymlinksAndWrongExtensions() throws {
        try temporary { root in
            let d=try document(),txt=root.appendingPathComponent("rapporto.txt"),pdf=root.appendingPathComponent("rapporto.pdf")
            try VerificationReportExporter.write(d,format:.text,to:txt);try VerificationReportExporter.write(d,format:.pdf,to:pdf)
            XCTAssertEqual(try String(contentsOf:txt,encoding:.utf8),d.plainText);XCTAssertNotNil(PDFDocument(url:pdf))
            let before=try Data(contentsOf:txt)
            XCTAssertThrowsError(try VerificationReportExporter.write(d,format:.text,to:txt));XCTAssertEqual(try Data(contentsOf:txt),before)
            let link=root.appendingPathComponent("link.txt");try FileManager.default.createSymbolicLink(at:link,withDestinationURL:txt)
            XCTAssertThrowsError(try VerificationReportExporter.write(d,format:.text,to:link));XCTAssertEqual(try Data(contentsOf:txt),before)
            XCTAssertThrowsError(try VerificationReportExporter.write(d,format:.pdf,to:root.appendingPathComponent("wrong.txt")))
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath:root.path).contains{$0.hasPrefix(".signum-staging-")})
        }
    }
    func testResourceLimitRejectsRatherThanTruncates() throws {
        XCTAssertThrowsError(try document(validations:[validation(reason:String(repeating:"x",count:VerificationReportDocument.maximumCharacters+1))]))
    }
    func testActualEngineResultsAreExportedWithoutChangingAnyVerdict() async throws {
        let fixture=try XCTUnwrap(Bundle.module.url(forResource:"valid-untrusted",withExtension:"cms",subdirectory:"Fixtures"))
        let helper=URL(fileURLWithPath:try XCTUnwrap(ProcessInfo.processInfo.environment["SIGNUM_TEST_PADES_HELPER"]))
        let r=try SignumVerificationService.verify(file:fixture,helper:helper)
        let date=Date()
        let values=await SignatureQualificationService().validate(r,authenticatedLists:[],mode:.offline,observedAt:date,evaluationMode:.bestAvailable)
        let d=try VerificationReportDocument(report:r,validations:values,verificationDate:date)
        XCTAssertEqual(d.signers.count,r.signatures.count);XCTAssertEqual(d.sha256,r.sha256)
        for (i,signature) in r.signatures.enumerated() {
            let value=try XCTUnwrap(values.first{$0.signatureID==signature.id})
            XCTAssertEqual(d.signers[i].outcomes[0].state,signature.integrity.description)
            XCTAssertEqual(d.signers[i].outcomes[1].reason,value.path.reason)
            XCTAssertEqual(d.signers[i].outcomes[2].reason,value.evidence.revocation.reason)
            XCTAssertEqual(d.signers[i].outcomes[3].reason,value.evidence.time.reason)
            XCTAssertEqual(d.signers[i].outcomes[4].state,value.qualification.state.description)
            XCTAssertEqual(d.signers[i].outcomes[4].reason,value.qualification.reason)
        }
    }
    func testProvenTimestampAndOCSPCRLEvidenceKeepTheirOwnDatesAndReasons() throws {
        let base=validation(revocation:.revoked,time:.proven)
        let proof=at.addingTimeInterval(-60)
        let tsa=TSAAuthorizationResult(state:.authorized,reason:"TSA autenticata dal motore.",tokenTime:proof,earliestTime:proof,latestTime:proof,service:nil,path:nil,certificates:[Data("SECRET_TSA_DER".utf8)])
        let evidence=SignatureEvidenceValidationResult(signatureID:0,revocation:.init(state:.revoked,reason:"Revoca accertata.",certificates:[
            .init(state:.good,kind:.ocsp,evaluatedAt:at,thisUpdate:at.addingTimeInterval(-3600),nextUpdate:later,revokedAt:nil,reason:"OCSP autenticato."),
            .init(state:.revoked,kind:.crl,evaluatedAt:at,thisUpdate:at.addingTimeInterval(-3600),nextUpdate:later,revokedAt:proof,reason:"CRL autenticata con revoca.")
        ]),time:.init(state:.proven,declaredSigningTime:"Data dichiarata distinta",provenTime:proof,reason:"Tempo comprovato dal motore.",authorities:[tsa]),associations:[])
        let value=CompleteSignatureValidationResult(signatureID:0,path:base.path,evidence:evidence,qualification:base.qualification)
        let d=try document(validations:[value])
        XCTAssertTrue(d.plainText.contains("Evidenze temporali: Tempo comprovato"))
        XCTAssertTrue(d.plainText.contains("Esistenza comprovata entro: "+VerificationReportDocument.date(proof)))
        XCTAssertTrue(d.plainText.contains("Istante RFC 3161 1: "+VerificationReportDocument.date(proof)))
        XCTAssertTrue(d.plainText.contains("authorized | TSA autenticata dal motore."))
        XCTAssertTrue(d.plainText.contains("OCSP | stato motore: good"));XCTAssertTrue(d.plainText.contains("CRL | stato motore: revoked"))
        XCTAssertTrue(d.plainText.contains("Revocato dal 2: "+VerificationReportDocument.date(proof)))
        XCTAssertFalse(d.plainText.contains("SECRET_TSA_DER"))
    }
    @MainActor func testWorkspaceRetainsTheAssessmentDateForLaterExport() async throws {
        let input=report([signature()]),date=at
        let workspace=VerificationWorkspace(validationClock:{date})
        await workspace.verify([URL(fileURLWithPath:"/synthetic/session-document.p7m")],using:{_,_ in input})
        let row=try XCTUnwrap(workspace.rows.first)
        XCTAssertEqual(row.verificationDate,date);XCTAssertFalse(row.validations.isEmpty)
        let d=try VerificationReportDocument(report:XCTUnwrap(row.report),validations:Array(row.validations.values),verificationDate:XCTUnwrap(row.verificationDate),exportedAt:later)
        XCTAssertEqual(d.verificationDate,date)
        workspace.cancel()
        XCTAssertEqual(workspace.rows.first?.verificationDate,date)
    }
    func testBurgundyBrandColorAndTextualOutcomesRemainIndependentOfColor() throws {
        let color=ReportPDFLayout.Ink.accent
        XCTAssertEqual(color.r,100.0/255,accuracy:1e-12);XCTAssertEqual(color.g,49.0/255,accuracy:1e-12);XCTAssertEqual(color.b,62.0/255,accuracy:1e-12)
        let d=try document(signatures:[signature(integrity:.invalid)],validations:[validation(path:.notVerifiable,revocation:.indeterminate)])
        let pdf=try XCTUnwrap(PDFDocument(data:VerificationReportPDF.data(d))?.string)
        for label in ["Integrità crittografica non valida","Percorso non verificabile","Indeterminata"] {XCTAssertTrue(pdf.contains(label));XCTAssertTrue(d.plainText.contains(label))}
    }
    func testDeclaredDatesNormalizeGMTISOOffsetsAndFractionsWithoutChangingSource() throws {
        let values=[("Oct 20 07:22:23 2026 GMT","20/10/2026 07:22:23 UTC"),
                    ("Oct  2 07:22:23 2026 GMT","02/10/2026 07:22:23 UTC"),
                    ("2026-10-20T09:22:23+02:00","20/10/2026 07:22:23 UTC"),
                    ("2026-10-20T05:22:23-02:00","20/10/2026 07:22:23 UTC"),
                    ("2026-10-20T07:22:23.999999999Z","20/10/2026 07:22:23 UTC"),
                    ("2026-01-01T00:15:00+01:00","31/12/2025 23:15:00 UTC")]
        for (raw,expected) in values {XCTAssertEqual(VerificationReportDocument.declaredDate(raw),expected)}
        let source=signature();let original=source.declaredTime
        let d=try document(signatures:[source])
        XCTAssertEqual(source.declaredTime,original)
        XCTAssertTrue(d.plainText.contains("Data dichiarata (signingTime): 20/10/2026 07:22:23 UTC"))
        for raw in ["Oct 32 07:22:23 2026 GMT","2026-02-30T10:00:00Z","2026-10-20T07:22:23","2026-10-20T07:22:23Z injected","Oct 20 07:22:23 2026 GMT\n","2026-10-20T07:22:23Z\n"] {
            XCTAssertEqual(VerificationReportDocument.declaredDate(raw),raw+" (formato originale non riconosciuto; non convertito)")
        }
        XCTAssertEqual(VerificationReportDocument.declaredDate(""),"Assente / non disponibile")
    }
    func testServiceStartIsNeverPresentedAsTrustedListUpdate() throws {
        let base=validation()
        let service=CertificateServiceMatch(provider:"Prestatore sintetico",service:"Servizio di prova",country:"IT",status:"granted",statusSince:at.addingTimeInterval(-86400),listSequence:123,historical:false,identitySHA256:String(repeating:"d",count:64))
        let path=CertificatePathResult(state:base.path.state,evaluatedAt:base.path.evaluatedAt,path:base.path.path,service:service,alternativeServices:[],reason:base.path.reason)
        let value=CompleteSignatureValidationResult(signatureID:0,path:path,evidence:base.evidence,qualification:base.qualification)
        let d=try document(validations:[value]),details=d.signers[0].details
        XCTAssertTrue(details.contains{$0.label=="Stato del servizio dal" && $0.value==VerificationReportDocument.date(service.statusSince)})
        XCTAssertTrue(details.contains{$0.label=="Sequenza TL" && $0.value=="123"})
        XCTAssertTrue(details.contains{$0.label=="Aggiornamento Trusted List" && $0.value=="Data non disponibile nei risultati del motore."})
        XCTAssertTrue(details.contains{$0.label=="Dettagli OCSP/CRL" && $0.value.contains("non disponibili")})
    }
    func testWriteSyntheticExamplesForVisualAcceptance() throws {
        guard let path=ProcessInfo.processInfo.environment["SIGNUM_TEST_REPORT_OUTPUT"] else {return}
        let root=URL(fileURLWithPath:path);try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let a=signature(name:"Alex Test - Certificato sintetico"),b=signature(1,parent:a.evidence!.signatureKey,name:"Èlodie Müller - Controfirmataria di prova")
        let base=validation()
        let evidence=SignatureEvidenceValidationResult(signatureID:0,revocation:.init(state:.good,reason:base.evidence.revocation.reason,certificates:[
            .init(state:.good,kind:.ocsp,evaluatedAt:at,thisUpdate:at.addingTimeInterval(-3600),nextUpdate:later,revokedAt:nil,reason:"Risposta OCSP sintetica: stato non revocato, intervallo dell’evidenza disponibile.")
        ]),time:base.evidence.time,associations:base.evidence.associations)
        let first=CompleteSignatureValidationResult(signatureID:0,path:base.path,evidence:evidence,qualification:base.qualification)
        let unresolved=validation(1,path:.notVerifiable,revocation:.indeterminate,time:.invalid,reason:"Qualificazione indeterminata: prove temporali e copertura fiduciaria insufficienti.")
        let second=CompleteSignatureValidationResult(signatureID:1,path:.init(state:.notVerifiable,evaluatedAt:at,path:[],service:nil,alternativeServices:[],reason:unresolved.path.reason),evidence:unresolved.evidence,qualification:unresolved.qualification)
        let d=try document(signatures:[a,b],validations:[first,second])
        try VerificationReportExporter.write(d,format:.pdf,to:root.appendingPathComponent("Signum-rapporto-esempio.pdf"))
        try VerificationReportExporter.write(d,format:.text,to:root.appendingPathComponent("Signum-rapporto-esempio.txt"))
    }
}
