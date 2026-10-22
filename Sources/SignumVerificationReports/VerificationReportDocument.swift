import Foundation
import SignumCore
import SignumCertificateValidation

/// A presentation-only snapshot. It retains no source bytes, DER certificates,
/// private credentials, URLs, raw CMS attributes or OCSP/timestamp tokens.
public struct VerificationReportDocument: Sendable {
    public struct Field: Sendable { public let label: String; public let value: String }
    public struct Outcome: Sendable { public let label: String; public let state: String; public let reason: String }
    public struct Signer: Sendable {
        public let number: Int, identity: String
        public let fiscalCode: String
        public let fields: [Field], outcomes: [Outcome], details: [Field]
    }
    public let documentName, sha256, format, productVersion: String
    public let verificationDate, exportedAt: Date
    public let fields: [Field], signers: [Signer], notes: [String]
    public static let maximumCharacters = 2_000_000
    public enum Failure: Error, LocalizedError {
        case inconsistentSnapshot, resourceLimit, invalidDestination
        public var errorDescription: String? {
            switch self {
            case .inconsistentSnapshot: return "Risultati o date non coerenti con la sessione di verifica. Nessun rapporto esportato."
            case .resourceLimit: return "Il rapporto supera i limiti di testo, pagine o dimensione supportati. Nessun contenuto viene troncato."
            case .invalidDestination: return "Scegli un nuovo file .pdf o .txt: il rapporto non può sostituire un file esistente."
            }
        }
    }
    /// Visible escaping prevents input text from creating new report rows, hiding
    /// output with bidi overrides or injecting terminal/control sequences into TXT.
    static func clean(_ value: String) -> String {
        var result=""
        for scalar in value.unicodeScalars {
            let n=scalar.value
            if CharacterSet.controlCharacters.contains(scalar) || (0x202a...0x202e).contains(n) || (0x2066...0x2069).contains(n) || [0x200b,0x200e,0x200f,0x061c,0x2028,0x2029,0xfeff].contains(n) {
                result += String(format:"\\u{%04X}",n)
            } else { result.unicodeScalars.append(scalar) }
        }
        return result.isEmpty ? "Non disponibile" : result
    }
    public static func date(_ value: Date) -> String {
        let f=DateFormatter();f.locale=Locale(identifier:"en_US_POSIX");f.timeZone=TimeZone(secondsFromGMT:0)
        f.calendar=Calendar(identifier:.gregorian)
        f.dateFormat="dd/MM/yyyy HH:mm:ss 'UTC'";return f.string(from:value)
    }
    /// Presentation only: explicit GMT/ISO offsets, never a guessed local zone.
    /// The requested seconds precision omits fractional digits without rounding.
    static func declaredDate(_ raw: String) -> String {
        guard !raw.isEmpty else { return "Assente / non disponibile" }
        func instant(_ values: [Int], offset: Int=0) -> Date? {
            guard values.count==6,(1...9999).contains(values[0]),(1...12).contains(values[1]),
                  (1...31).contains(values[2]),(0...23).contains(values[3]),
                  (0...59).contains(values[4]),(0...59).contains(values[5]),let zone=TimeZone(secondsFromGMT:offset) else {return nil}
            var calendar=Calendar(identifier:.gregorian);calendar.timeZone=zone
            let c=DateComponents(year:values[0],month:values[1],day:values[2],hour:values[3],minute:values[4],second:values[5])
            guard let date=calendar.date(from:c) else {return nil}
            let back=calendar.dateComponents([.year,.month,.day,.hour,.minute,.second],from:date)
            guard [back.year,back.month,back.day,back.hour,back.minute,back.second].compactMap({$0})==values else {return nil}
            return date
        }
        var parsed: Date?
        if raw.utf8.count<=128 {
            if raw.range(of:#"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT\z"#,options:.regularExpression) != nil {
                let words=raw.split(separator:" ").map(String.init)
                let months=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
                if let month=months.firstIndex(of:words[0]),let day=Int(words[1]),let year=Int(words[3]) {
                    parsed=instant([year,month+1,day]+words[2].split(separator:":").compactMap{Int($0)})
                }
            } else if raw.range(of:#"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})\z"#,options:.regularExpression) != nil {
                let values=String(raw.prefix(19)).components(separatedBy:CharacterSet(charactersIn:"-T:")).compactMap{Int($0)}
                if raw.hasSuffix("Z") {parsed=instant(values)}
                else {
                    let zone=Array(raw.suffix(6))
                    if let hours=Int(String(zone[1...2])),let minutes=Int(String(zone[4...5])),hours<=23,minutes<=59 {
                        parsed=instant(values,offset:(zone[0]=="-" ? -1:1)*(hours*3600+minutes*60))
                    }
                }
            }
        }
        return parsed.map(Self.date) ?? raw+" (formato originale non riconosciuto; non convertito)"
    }
    public init(report: VerificationReport, validations: [CompleteSignatureValidationResult], verificationDate: Date,
                exportedAt: Date=Date(), productVersion: String="Build di sviluppo") throws {
        guard verificationDate.timeIntervalSince1970.isFinite,exportedAt.timeIntervalSince1970.isFinite,
              verificationDate<=exportedAt,report.sha256.count==64,report.sha256.allSatisfy(\.isHexDigit),
              Set(report.signatures.map(\.id)).count==report.signatures.count,
              Set(validations.map(\.signatureID)).count==validations.count,
              validations.allSatisfy({ v in report.signatures.contains{$0.id==v.signatureID} &&
                v.evidence.signatureID==v.signatureID && v.qualification.signatureID==v.signatureID &&
                (v.qualification.verificationDate == nil || v.qualification.verificationDate==verificationDate) }) else { throw Failure.inconsistentSnapshot }
        guard report.signatures.count<=32 else { throw Failure.resourceLimit }
        self.documentName=Self.clean(report.documentName.hasPrefix("/") ? URL(fileURLWithPath:report.documentName).lastPathComponent:report.documentName)
        sha256=report.sha256;self.verificationDate=verificationDate;self.exportedAt=exportedAt
        self.productVersion=Self.clean(productVersion)
        switch report.format {
        case .cades: format=report.detachedContentSHA256 == nil ? "CAdES / CMS attached":"CAdES / CMS detached"
        case .pades: format="PAdES / PDF"
        case .xml: format="XAdES / XML"
        case .asic: format="ASiC / XAdES detached"
        case .unknown: format="Non riconosciuto"
        }
        func field(_ label: String,_ value: String) -> Field { .init(label:label,value:Self.clean(value)) }
        func outcome(_ label: String,_ state: String,_ reason: String) -> Outcome { .init(label:label,state:Self.clean(state),reason:Self.clean(reason)) }
        func evidenceLabel(_ e: QualificationEvidenceState) -> String {
            switch e {case .demonstrated:return "Dimostrato";case .notDemonstrated:return "Non dimostrato";case .indeterminate:return "Indeterminato"}
        }
        func service(_ value: CertificateServiceMatch,_ label: String) -> [Field] {
            [field(label,value.provider+" | "+value.service+" | "+value.country),field("Stato del servizio TL",value.status),
             field("Stato del servizio dal",Self.date(value.statusSince)),field("Sequenza TL",String(value.listSequence)),
             field("Identità del servizio SHA-256",value.identitySHA256)]
        }
        var overview=[field("Documento",self.documentName),field("Formato",format),field("Impronta SHA-256",sha256),
                      field("Data della verifica",Self.date(verificationDate)),field("Firme rilevate",String(report.signatures.count)),
                      field("Esito crittografico",report.summary)]
        if let digest=report.detachedContentSHA256 {overview.append(field("Contenuto separato SHA-256",digest))}
        if !report.issue.isEmpty {overview.append(field("Motivazione del documento",report.issue))}
        fields=overview
        signers=report.signatures.map { signature in
            let number=(report.signatures.firstIndex{$0.id==signature.id} ?? 0)+1
            let value=validations.first{$0.signatureID==signature.id}
            let identity=signature.signerIdentity
            let personalName=Self.clean(identity?.personalName ?? "Non disponibile")
            let fiscalCode=Self.clean(identity?.fiscalCode ?? "Non disponibile")
            var identityFields=[field("Nome e cognome",personalName),field("Codice Fiscale",fiscalCode),
                field("Subject del certificato",signature.certificate?.subject ?? "Certificato non disponibile"),
                field("Emittente",signature.certificate?.issuer ?? "Non disponibile"),
                field("Certificato SHA-256",signature.certificate?.sha256 ?? "Non disponibile"),field("Algoritmo",signature.algorithm)]
            if let parent=signature.counterSignatureOf {
                let matches=report.signatures.filter{$0.evidence?.signatureKey==parent && $0.cmsLayer==signature.cmsLayer && $0.signedRevisionEnd==signature.signedRevisionEnd}
                let index=matches.count==1 ? report.signatures.firstIndex{$0.id==matches[0].id}.map{String($0+1)}:nil
                identityFields.append(field("Relazione",index.map{"Controfirma della firma "+$0} ?? "Controfirma: genitore non univocamente individuato"))
                identityFields.append(field("SignatureValue genitore SHA-256",parent))
            } else if report.format == .cades {
                let peers=report.signatures.enumerated().filter{$0.element.counterSignatureOf==nil && $0.element.cmsLayer==signature.cmsLayer}.map{String($0.offset+1)}
                identityFields.append(field("Relazione",peers.count>1 ? "Cofirmatari del contenuto CMS: "+peers.joined(separator:", "):"Firmatario del contenuto CMS"))
            } else {identityFields.append(field("Relazione","Firmatario del contenuto nel profilo indicato"))}
            if report.format == .cades {identityFields.append(field("Livello CMS",String(signature.cmsLayer)))}
            if let path=signature.cmsSignerPath,!path.isEmpty {identityFields.append(field("Percorso SignerInfo",path))}
            if let revision=signature.signedRevisionEnd {identityFields.append(field("Revisione firmata","Byte 0..."+String(revision)))}
            if signature.laterChanges {identityFields.append(field("Modifiche successive","Presenti; accettabilità non valutata"))}
            identityFields.append(field("Data dichiarata (signingTime)",Self.declaredDate(signature.declaredTime)))
            let missing="Risultato non presente nello snapshot della sessione; valutazione non completata o non disponibile."
            var outcomes=[outcome("Integrità crittografica",signature.integrity.description,signature.reason.isEmpty ? "Esito crittografico restituito dal motore Signum; attendibilità del certificato valutata separatamente.":signature.reason)]
            var details=[Field]()
            if let value {
                let path=value.path
                let pathState: String
                switch path.state {case .verified:pathState="Percorso verificato";case .invalid:pathState="Percorso non valido";case .notVerifiable:pathState="Percorso non verificabile"}
                outcomes.append(outcome("Attendibilità X.509",pathState,path.reason))
                let revocation=value.evidence.revocation
                let revocationState: String
                switch revocation.state {case .good:revocationState="Non revocato - evidenza verificata";case .revoked:revocationState="Revocato";case .indeterminate:revocationState="Indeterminata"}
                outcomes.append(outcome("Revoca",revocationState,revocation.reason))
                let time=value.evidence.time
                let timeState: String
                switch time.state {case .proven:timeState="Tempo comprovato";case .notProven:timeState="Tempo non comprovato";case .invalid:timeState="Evidenza temporale non valida";case .indeterminate:timeState="Indeterminato"}
                outcomes.append(outcome("Evidenze temporali",timeState,time.reason))
                outcomes.append(outcome("Qualificazione eIDAS",value.qualification.state.description,value.qualification.reason))
                details.append(field("Catena X.509 valutata al",Self.date(path.evaluatedAt)))
                for (i,element) in path.path.enumerated() {details.append(field("Certificato del percorso \(i+1)",element.subject+" | SHA-256 "+element.sha256))}
                if let match=path.service {details += service(match,path.state == .verified ? "Servizio del percorso":"Servizio candidato (non attestato)")}
                // Service statusSince is not a TL publication/update timestamp.
                details.append(field("Aggiornamento Trusted List","Data non disponibile nei risultati del motore."))
                if revocation.certificates.isEmpty {details.append(field("Dettagli OCSP/CRL","Evidenze individuali non disponibili nei risultati del motore."))}
                for (i,e) in revocation.certificates.enumerated() {
                    details.append(field("Revoca - evidenza \(i+1)","\(e.kind == .ocsp ? "OCSP":"CRL") | stato motore: \(e.state.rawValue) | valutata al \(Self.date(e.evaluatedAt))"))
                    details.append(field("Motivazione dell’evidenza \(i+1)",e.reason))
                    if let t=e.thisUpdate {details.append(field("thisUpdate \(i+1)",Self.date(t)))}
                    if let t=e.nextUpdate {details.append(field("nextUpdate \(i+1)",Self.date(t)))}
                    if let t=e.revokedAt {details.append(field("Revocato dal \(i+1)",Self.date(t)))}
                }
                if let proven=time.provenTime {details.append(field(time.state == .proven ? "Esistenza comprovata entro":"Istante dell’evidenza (non convalidata)",Self.date(proven)))}
                for (i,authority) in time.authorities.enumerated() {
                    details.append(field("Autorizzazione TSA \(i+1)",authority.state.rawValue+" | "+authority.reason))
                    if let token=authority.tokenTime {details.append(field("Istante RFC 3161 \(i+1)",Self.date(token)))}
                    if let match=authority.service {details += service(match,"Servizio TSA \(i+1)")}
                }
                details.append(field("Modalità di valutazione",value.qualification.evaluationMode == .currentTime ? "Alla data corrente di verifica":value.qualification.evaluationMode == .historical ? "Storica":"Migliore evidenza disponibile (motore)"))
                if let evaluated=value.qualification.evaluatedAt {details.append(field("Istante valutato per eIDAS",Self.date(evaluated)))}
                details.append(field("Certificato qualificato",evidenceLabel(value.qualification.qualifiedCertificate)))
                details.append(field("QSCD",evidenceLabel(value.qualification.qscd)))
                if let match=value.qualification.service {details += service(match,value.qualification.serviceStateFromHistory ? "Servizio eIDAS storico":"Servizio eIDAS all’istante valutato")}
                for (i,association) in value.evidence.associations.enumerated() {details.append(field("Associazione evidenza \(i+1)",association.state.rawValue+" | "+association.reason+" | SHA-256 "+association.sha256))}
            } else {
                for label in ["Attendibilità X.509","Revoca","Evidenze temporali","Qualificazione eIDAS"] {outcomes.append(outcome(label,"Non valutata",missing))}
            }
            return Signer(number:number,identity:personalName,fiscalCode:fiscalCode,fields:identityFields,outcomes:outcomes,details:details)
        }
        var limits=[
            "Gli esiti sono indipendenti e riferiti alla sessione e alle evidenze disponibili. Il rapporto non esegue una nuova verifica e non è una certificazione di validità giuridica.",
            "La data e ora dichiarate (signingTime) non costituiscono una marca temporale certificata. Data della verifica, istante valutato ed eventuale tempo comprovato restano distinti.",
            "Qualificazione e QSCD sono riportati solo come restituiti dal motore. Informazioni insufficienti o profili non supportati non giustificano un esito QES positivo.",
            "Copertura eIDAS Signum: profili diretti CA/QC post-2016 collaudati IT, AT, DE, BE, FR, ES; criteri, cronologie e identità non supportati restano esclusi. XAdES/ASiC e controfirme sono limitati ai sottoinsiemi implementati.",
            "Il PDF e il testo del rapporto non sono firmati né marcati temporalmente. Non attestano LTV, PAdES-LT/LTA o conservazione a lungo termine.",
            "Identità e motivazioni provengono dai risultati del motore; caratteri di controllo e direzionalità sono resi visibili per evitare alterazioni della presentazione. Il rapporto contiene dati identificativi dei certificati: condividilo consapevolmente."
        ]
        if report.format == .pades {limits.append(VerificationReport.revisionScope)}
        if report.signatures.contains(where:{ signature in !validations.contains{$0.signatureID==signature.id} }) {limits.append("Valutazione incompleta: uno o più risultati X.509, revoca, tempo o eIDAS non sono disponibili.")}
        if !report.unassociatedEvidence.isEmpty {limits.append("Evidenze non associate: \(report.unassociatedEvidence.count). Non attribuite automaticamente a un firmatario.")}
        notes=limits
        guard plainText.utf8.count<=Self.maximumCharacters else {throw Failure.resourceLimit}
    }
    public var plainText: String {
        var rows=["SIGNUM", "Digital signatures. Simply native.","RAPPORTO DI VERIFICA", "Signum "+productVersion,
                  "Esportato il: "+Self.date(exportedAt),""]
        rows += fields.map{$0.label+": "+$0.value}
        rows += ["", "SINTESI DEI FIRMATARI"]
        for signer in signers {
            rows += ["Firma \(signer.number) · Nome e cognome: "+signer.identity,"Codice Fiscale: "+signer.fiscalCode]
            rows += signer.outcomes.map { $0.label+": "+$0.state }
        }
        for signer in signers {
            rows += ["","FIRMA \(signer.number)"]+signer.fields.map{$0.label+": "+$0.value}
            for outcome in signer.outcomes {rows += [outcome.label+": "+outcome.state,"Motivazione: "+outcome.reason]}
            rows += signer.details.map{$0.label+": "+$0.value}
        }
        rows += ["","PERIMETRO E LIMITI"]+notes+[""]
        return rows.joined(separator:"\n")
    }
}
