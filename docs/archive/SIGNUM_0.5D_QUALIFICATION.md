# Signum 0.5-D — Qualificazione eIDAS

Baseline `70f8592e38f01558d9ebaa61815b6e08013bfcf5`, stesso branch
`feature/signum-0.5cd-complete-validation`. Implementazione locale nativa;
nessuna modifica alle operazioni di firma, appearance o PKCS#11.

## API e confini

`SignatureQualificationService.validate` esegue una sola valutazione C delle
evidenze del rapporto e consuma i suoi risultati per ciascun SignerInfo/revisione.
Non accetta dal chiamante un risultato temporale arbitrario da applicare a un altro
rapporto. Riusa `SignatureEvidenceValidationService`, `CertificatePathValidator`
e i cataloghi `AuthenticatedTL`; non aggiunge primitive OCSP/CRL/RFC 3161.
I risultati sono cancellabili e calcolati fuori dal main actor. Non esiste un
nuovo processo residente. La GUI Verifica conserva i risultati crittografici Core
e mostra separatamente integrità, catena, revoca, tempo e qualificazione con motivo.
La catena mostrata è valutata all’osservazione; la qualificazione riporta anche il
servizio al tempo comprovato e l’eventuale provenienza dallo storico.

`SignatureQualificationResult` distingue `qualified`, `electronic`, `advanced`,
`indeterminate`, prova di certificato qualificato, prova QSCD, istante di valutazione,
servizio e motivo. `electronic` significa **livello minimo accertato**, non la
prova che tutti i requisiti di firma avanzata siano assenti. `advanced` è riservato:
questa implementazione non lo deduce dal certificato o dalla sola crittografia.
Non si valuta la volontà del firmatario o l’ammissibilità giuridica del documento.

## Profilo positivo e comportamento conservativo

Il profilo positivo QES richiede tutti i seguenti controlli:

- Integrità verificata e certificato effettivo estratto dal SignerInfo.
- Tempo `proven` restituito dalla C, con TSA autorizzata e revoca verificata.
  `provenTime` resta il limite superiore della finestra RFC 3161: non è una data
  esatta di creazione, e `signingTime` non partecipa alla decisione.
- TL italiana autenticata e corrente all’osservazione. Il percorso B deve arrivare
  all’esatta identità CA/QC granted nella finestra comprovata. I nomi non sono ancore.
  Alternative fra servizi, storici ambigui o cambi di stato nella finestra sono
  indeterminati. Emissione (`notBefore`) e prova devono ricadere nello stesso evento
  TL autenticato, con le sue proprie identità ed estensioni.
- Percorso attuale identico a quello al tempo comprovato, per non trasferire a
  un altro percorso il risultato di revoca C. Tutti i suoi risultati devono essere
  good, con thisUpdate non successivo all’inizio della finestra e nextUpdate non
  antecedente all’osservazione. Nessuna retrodatazione ottimistica di una risposta.
- Certificato qualificato per firma: QcCompliance o qualificatore QCStatement
  applicabile, QcType eSig univoco (oppure QCForESig applicabile con tipo assente),
  Key Usage contentCommitment e prova QcSSCD o QCWithQSCD pertinente.

Assenza, conflitti e profili non interpretati non producono QES. QCNoQSCD non viene
ignorato; QCQSCDStatusAsInCert usa soltanto la prova nel certificato e non può
coesistere con gli altri qualificatori QSCD. Una revoca accertata impedisce QES.
Senza prova QSCD si riporta «non dimostrato». Un certificato privo delle attestazioni
qualificate riconosciute viene indicato come non qualificato nel profilo supportato,
con il solo livello minimo elettronico accertato; le policy QCP legacy senza
QcCompliance non sono interpretate come prova negativa o positiva definitiva.
In modalità API `.offline` la qualificazione resta indeterminata anche quando le
singole evidenze locali sono valide. `.online` consente al client C di usare cache
autenticata o rete controllata: non certifica che il computer sia connesso e non
forza una query se le evidenze sono già sufficienti. Rete assente senza evidenze
sufficienti produce indeterminato. Nessuna richiesta è aggiunta dal valutatore D.
Vedere [privacy OCSP](SIGNUM_0.5C_OCSP_PRIVACY.md).

## Parser e qualificatori

`QCStatements.parse(certificate:)` usa un lettore DER limitato a 64 KiB, lunghezze
minime definite, OID e interi senza overflow, estensione singola e statement non
duplicati. Espone QcCompliance, QcType, QcSSCD, QcLimitValue (valuta/importo/esponente),
QcRetentionPeriod e QcPDS (URL/lingua). Limite economico, conservazione e PDS sono
metadati: non si apre l’URL, non si assume rispettato il limite di una transazione.
Le firme e la validità X.509 restano responsabilità del motore B OpenSSL.

TrustCore conserva gli alberi delle ServiceInformationExtensions nei percorsi
assoluti del servizio corrente e di ogni stato storico, mantenendo namespace,
attributi e contenuti. Non cattura estensioni nascoste negli oggetti ds:Signature.
Il parser non le autentica: soltanto `AuthenticatedTL` entra nella qualificazione.
Il vocabolario critico nativo ammette ora i qualificatori implementati dalla D;
estensioni sconosciute restano rifiutate. Nessuna CA viene promossa dal portachiavi.

Supportati: Qualifications/QualificationElement/Qualifiers e CriteriaList annidate
(max 12), assert all/atLeastOne/none, KeyUsage con tutti i bit richiesti e PolicySet
con **tutte** le policy richieste, OIDAsURI `urn:oid:`. QCStatement, NotQualified,
QCForESig/ESeal/WSA, QCWithQSCD/QCNoQSCD/QCQSCDStatusAsInCert sono riconosciuti.
ForeSignatures è interpretato; altre estensioni critiche, criteri o qualificatori
sconosciuti rendono il profilo indeterminato, anche se la TL è autentica.

## Profili non supportati e confronto DSS

DSS non è disponibile offline nei percorsi di sviluppo controllati (workspace,
Applicazioni, cache Maven e download). **Confronto esecutivo DSS non eseguito**;
non sono stati inviati documenti personali al servizio web. Consultata soltanto
la documentazione ufficiale. Nessuna dipendenza Java aggiunta al bundle.

Differenze/limiti del profilo rispetto a DSS:

- Copertura di acquisizione TL limitata all’Italia; altri Paesi indeterminati.
- Nessuna determinazione generale di AdES, sigilli qualificati o QWAC; tipo misto
  o legacy ambiguo resta indeterminato. Regime precedente al 1 luglio 2016 non
  supportato. Nessun fallback QCP/QCP+ o interpretazione universale delle policy.
- Non si ricostruisce l’intera semantica di transizioni storiche, TakenOverBy,
  RootCA-QC, QSCDManagedOnBehalf, SSCD legacy o OtherCriteria (EKU, certificate
  issuance range, criteri nazionali). Nessun borrowing delle estensioni attuali.
  Un servizio ritirato oggi, una catena scaduta o un cambio di percorso possono
  impedire QES anche se la firma potrebbe risultare valida con ulteriori prove.
- QCStatements ulteriori e critiche non gestite, tipi diversi da eSig e criteri
  non risolti impediscono il positivo. QCStatements critiche che OpenSSL non
  riconosce restano non supportate dal percorso B.
- Restano i limiti C: niente revoca storica con POE/archival cutoff, CRL delta o
  indirette, responder ricorsivi senza no-check, document/archive timestamp o
  validazione di conservazione. Non si attesta LTV/PAdES-LT/LTA.
- Nessuna accettazione delle modifiche PDF successive viene dedotta dalla QES
  della singola firma/revisione. Gli esiti rimangono indipendenti.

Questi limiti sono intenzionalmente visibili come motivi degli esiti; non si
rivendica implementazione completa di ogni procedura o conformità DSS/ETSI.

## Riproduzione e Preview

Il generatore C delle evidenze viene riutilizzato con il profilo di fixture D:

```sh
SIGNUM_QUALIFICATION_FIXTURES=1 \
SIGNUM_BINDING_FIXTURE_OUTPUT="$PWD/Tests/SignumCertificateValidationTests/Fixtures/Qualification" \
SIGNUM_FIXTURE_OPENSSL=/percorso/prefix/bin/openssl \
python3 Tools/TrustPoC/generate-evidence-binding-fixtures.py
```

Richiede cryptography 50.0.2, OpenSSL/xmlsec del prefisso di sviluppo. Produce chiavi
casuali temporanee poi eliminate, CMS e PDF a due firme con qualificazioni diverse,
certificato qualificato senza QSCD, OCSP/CRL e TL firmate con stati e qualificatori
differenti. Il manifest SHA-256 registra i byte pubblici commessi e il clock fisso.
Le ancore sintetiche rimangono nei soli test, mai nel catalogo di produzione.
Test mirati: `Tools/TrustPoC/native.sh test --filter QualificationTests` con
SIGNUM_TRUST_NATIVE_PREFIX e SIGNUM_TEST_PADES_HELPER del runner locale.

Build 5: `scripts/build-preview-app.py --build-number 5` riusa il packager e la
chiusura nativa A.3. ID `io.github.tiertoast.Signum.DevelopmentPreview.B5`, cache TL
in Application Support sotto quell’ID e cache revoche in Caches sotto lo stesso
ID. Nessuna sovrascrittura di Beta 0.4, A.3 o Build 4. Il packager Build 5 evita di
ripetere le campagne motore già eseguite dal runner e mantiene audit Mach-O,
rilocazione e firma ad hoc. Il nuovo `scripts/test-preview5-bundle.py` verifica
bundle, rilocazione, avvio e un documento InfoCamere locale, senza copiarlo nel repo.
Tutti i dylib necessari sono incorporati; sono usate soltanto librerie/framework
di sistema e, per il trasporto C, gli strumenti di sistema macOS già documentati.
Homebrew e Java non servono a runtime. Target 13.0, arm64; prove su macOS 27.2.
L’esecuzione su macOS 13 **non è stata verificata**.

Riferimenti primari: [ETSI TS 119 615 V1.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf),
[ETSI TS 119 612 V2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf),
[ETSI EN 319 412-5 V2.5.1](https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.05.01_60/en_31941205v020501p.pdf),
[documentazione DSS](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html).

## Esiti del gate 0.5-D

Campagna normale completa eseguita **una sola volta** con il runner ufficiale:
430 SignumCore, 42 CertificateValidation (34 esistenti + 8 nuovi), 18 TrustCore,
30 Authentication, 5 integrazione TL; tutti superati senza skip. PAdES: 81 Debug
e 81 Release; PKCS#11: 58 casi provider e 2 contratti loader, tutti superati.
Nessun token fisico usato. Le prove nuove includono due SignerInfo CMS e due
revisioni PDF con qualificazioni differenti, QcSSCD e qualificatore TL positivo,
assenza QSCD, revoca, tempi non dimostrati, TL mancanti, ritirati/storici,
conflitti, criteri PolicySet/all/atLeastOne/none, namespace estranei e offline.

ASan e TSan: verdi gli 8 casi di qualificazione, 11 parser TL, 14 autenticazione
XML e un’integrazione workspace. Il primo filtro ASan selezionava anche il modulo
Refresh non modificato: il relativo harness è stato interrotto e ristretto, senza
ripetere la campagna normale. I 14 casi Authentication erano già conclusi verdi;
il completamento mirato ha eseguito qualificazione/workspace e ripetuto i soli
11 parser (circa 0,05 s). TSan è stato eseguito con il filtro ristretto. I log
conservano anche l’invocazione interrotta; nessun errore di memoria o race rilevato.
Le dipendenze esterne OpenSSL/PoDoFo non sono strumentate; detect_leaks=0 per ASan.

Durante lo sviluppo: un errore di compilazione nel nome di un helper di test;
poi errori di schema nelle nuove fixture e vocabolario critico QCNoQSCD non ancora
ammesso dalla base A. Cause distinte, tutte risolte; nessun test è fallito due
volte per la stessa causa. Non rimangono fallimenti XCTest nella campagna conclusa.

Il collaudo preliminare Release della Build 5 ha verificato chiusura delle
librerie, rilocazione, codesign ad hoc, avvio con PATH di sistema e il documento
InfoCamere fornito localmente: integrità e catena verificate, revoca good, tempo
notProven, qualificazione indeterminate. Il documento personale non è commesso
né incluso negli artefatti. Il bundle finale viene prodotto dal commit del gate;
il collaudo finale è registrato nella nota Build 5.
