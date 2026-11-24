# Indagine comparativa DSS 6.5 / Signum

25 ottobre 2026. Base locale 62b0175, branch feature/signum-0.7-ui-redesign, PR #8.
Rapporto preliminare scritto PRIMA delle correzioni. Gli esiti successivi sono
riportati in fondo, senza sostituire le evidenze iniziali.

## Perimetro e provenienza

Input autorizzati: AQST-relazione acclarante 2024.pdf.p7m in Documenti e i tre
rapporti DSS in Download. SHA-256 del CMS:
2757698fea2faf0776f53b8ce300cf8b6f4283527fc98cf63002881c7500754b.
Diagnostic XML: d20cda0015bed764c20811b545f959229c97441ee9bd00054724f8dfb8a50d0a.

Il repository contiene modifiche preesistenti a Package.swift, CXMLSecurity e
componenti PKCS#11/firma, con relativi test e backup. Non fanno parte di questa
indagine e non vengono modificati o inclusi in un commit dell’indagine.
Materiali personali, DER reali e risposte OCSP restano in .build/dss-investigation,
ignorata da Git. Solo fixture sintetiche vengono aggiunte ai test del repository.
Nessun documento è stato inviato a DSS o ad altri servizi. Due richieste OCSP
esplicite sono state inviate al solo endpoint AIA InfoCamere, con CertID; nessun
contenuto del documento, CMS o PIN viene trasmesso.

## Risultati DSS e riscontri indipendenti

DSS dichiara TOTAL_PASSED/QESig, CAdES-BASELINE-B, validazione/best-signature-time
2026-10-25T15:24:26Z e nessuna marca temporale. Il signingTime dichiarato è
2026-10-24T12:41:52Z. Nel diagnostico OCSP thisUpdate/producedAt sono
15:24:27Z, nextUpdate 16:24:27Z. Il responder è delegato, con OCSP no-check.
Questi valori sono affermazioni del rapporto, non sostituti di una verifica DER.
Il diagnostico non contiene l’intero DER OCSP: non si afferma un replay binario
della stessa risposta usata da DSS.

Riscontri locali indipendenti:
- La firma CMS del file originale supera openssl cms -verify, senza disattivare
  firma o digest; -noverify separa esclusivamente il giudizio sulla catena.
- Il CMS incorpora soltanto il certificato del firmatario. La CA viene reperita
  nella TL italiana; la catena è verificata dalle primitive Signum.
- La copia della cache originale EU/IT viene riautenticata dal SignumTrustProbe
  distribuito nella Build 8: LOTL EU 397, IT corrente con scadenza 2027-03-24.
- Due risposte live del 25 ottobre, alle 15:35:59Z, entrambe GOOD: CertID SHA-256
  e SHA-1. La primitiva C Signum accetta entrambe, con firma, delega, no-check,
  associazione certificato/emittente e validità temporale. L’ipotesi di un
  responder InfoCamere incompatibile con CertID SHA-256 è quindi smentita.

## Cause individuate

### 1. Estensione di servizio combinata non supportata — riproduzione confermata

TLQualificationRules.evaluateImpl accetta AdditionalServiceInformation soltanto
per ForeSignatures. Il servizio CA/QC InfoCamere contiene due estensioni critiche
valide: ForeSignatures E ForeSeals. La seconda produce nil; HistoricalQualification
riporta quindi un generico errore di continuità/qualificatori, anche se identità,
stato granted, QCStatements e QSCD sono coerenti.

Replay locale del CMS originale, TL riautenticate e risposta OCSP autenticata:
integrity=verified, chain=verified, revocation=good, time=notProven,
qualification=indeterminate. Motivo preciso: “Transizione di identità, stato o
qualificatori fra emissione e istante valutato: evidenze storiche insufficienti.”
L’evento reale rilevante è granted dal 2020-07-09: non si è individuata una
rotazione del certificato CA che richieda di ignorare la continuità storica.

Intervento proposto: interpretare esplicitamente l’insieme dei tipi di servizio
noti. ForeSignatures insieme a ForeSeals non è un conflitto. Per questo profilo
eSig, ForeSeals da solo non autorizza QES. Namespace errati, estensioni critiche
sconosciute, criteri ambigui e QCStatements insufficienti rimangono fail-closed.
Non rimuovere i controlli di storia, revoca, QSCD, certificato o integrità.

### 2. Istante iniziale precedente all’evidenza appena acquisita — lacuna riprodotta

RevocationSession avanza l’ora durante la richiesta, ma SignatureQualificationService
confronta thisUpdate con observedAt iniziale. Un OCSP acquisito durante la verifica
può essere valido al ricevimento e successivo all’istante iniziale: il secondo
controllo lo respinge. Il rapporto DSS mostra proprio un secondo di differenza.
Inoltre il tempo impiegato nel caricamento delle TL può non essere incluso nella
base passata alla sessione di revoca.

Prova sulla stessa risposta reale: la primitiva C dà stale a thisUpdate-1 secondo
e good a thisUpdate e thisUpdate+1. È corretto rifiutare evidenza futura rispetto
all’istante valutato: NON si propone di aggiungere tolleranze o accettare futuro.

Intervento proposto: dopo l’acquisizione online, fissare un istante di valutazione
corrente successivo usando il tempo monotono trascorso; rieseguire offline le
stesse primitive con i DER acquisiti, senza seconda richiesta. Ricalcolare percorso,
revoca e qualificazione allo stesso istante. Nessuna promozione del signingTime
in tempo provato; rivalutare anche scadenze TL, certificati e responder. Conservare
il comportamento offline e storico, e il vincolo di binding per documento/firma.

### 3. Evidenze alternative non selezionate — ulteriore difetto di aggregazione

checkPath conserva nell’elenco usato dalla qualificazione anche risposte CRL/OCSP
scadute o non supportate, pur avendo trovato una prova GOOD valida per ciascun
certificato. Il successivo allSatisfy(good) può annullare quel risultato.
Intervento proposto: selezionare una prova autenticata pertinente per certificato,
con la copertura richiesta; una revoca autenticata ha sempre precedenza. Una
risposta non valida non diventa attendibile e non può sostituire una revoca.
Questo difetto è distinto dal caso concreto ForeSeals e sarà coperto da fixture.

## Confronto dei cinque punti richiesti

1. OCSP/CRL: Signum controlla firma e coppia cert/emittente; supporta responder
   delegati con EKU autorizzato e no-check. Non implementa la revoca ricorsiva del
   responder senza no-check. CRL dirette complete, massima età 31 giorni; delta,
   indirette e issuingDistributionPoint non interpretati restano indeterminati.
   Non è giustificato bypassare questi limiti per ottenere il risultato DSS.
2. Certificati/TL: nessuna CA da nome o store generico; identità CA/QC proveniente
   da TL autenticata. Nel caso concreto non manca l’intermedio: emissione diretta
   da CA InfoCamere presente in TL. Il responder supera le verifiche native.
3. Cache/tempo: cache separata TL/revoca; ogni lettura riautentica DER e scadenze,
   conserva revoca autenticata contro sostituzioni GOOD, rifiuta scritture ostili.
   Il problema osservato riguarda il riferimento temporale, non la fiducia in cache.
4. QES senza timestamp: la GUI già usa bestAvailable e può qualificare corrente
   con prove sufficienti. Non serve una marca temporale per quella sola valutazione.
   Il tempo dichiarato non prova quando la firma è stata apposta. Il profilo storico
   richiede invece POE/TSA e copertura; rimane distinto. Il vecchio comando diagnostico
   evidence mantiene un default storico: non è la stessa policy della GUI.
5. DSS: Basic/Long-Term validation e qualificazione al best-signature-time corrente
   non attestano automaticamente una firma storicamente valida alla data dichiarata
   né un livello LT/LTA. Signum ha copertura più stretta: CA/QC diretta, sei Paesi
   collaudati, algoritmi/criteri/CRL limitati e nessuna promozione automatica ad AES.
   TOTAL_PASSED non viene importato come booleano affidabile.

## Piano di verifica prima di dichiarare risolta la discrepanza

Test sintetici deterministici: scopi TL combinati/solo sigillo/sconosciuti;
risposta durante la richiesta, evidenza ancora futura al completamento, scadenza
durante la verifica, revocato, firma alterata, cache assente, annullamento e offline.
Replay reale prima/dopo con la stessa risposta conservata e TL riautenticate.
Build Debug/Release e regressioni locali pertinenti. Nessuna Action, merge o release.
HalleyMac intatto. Nessuna modifica al redesign Build 9.

## Fonti primarie

- [DSS 6.5 AdditionalServiceInformation](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/eu/europa/esig/dss/enumerations/AdditionalServiceInformation.html)
- [ETSI TS 119 612 V2.4.1, D.5.5](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf)
- [DSS: validation et best-signature-time](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html)
- [RFC 6960: OCSP, delega e date](https://www.rfc-editor.org/rfc/rfc6960.html)

## Esiti dopo gli interventi — completati il 25 ottobre 2026

Il rapporto preliminare è stato salvato prima della correzione. SHA-256:
`b05cc771aeb25a0b9f89b3269c6a0c1a6e2fe640b88037f3bfc28e2b4894be28`.

### Correzioni applicate

- TLQualificationRules interpreta esplicitamente ForeSignatures + ForeSeals come
  scopi compatibili dello stesso servizio CA/QC. ForeSeals da solo, namespace
  errati e scopi sconosciuti rimangono insufficienti per il profilo eSig. Non si
  aggiungono qualificatori QC/QSCD impliciti; storia, granted e certificato restano
  indispensabili. Il controllo di continuità storica NON è stato rimosso.
- L’acquisizione online conserva al massimo otto risposte DER nella singola
  invocazione. Dopo le richieste si fissa l’istante corrente e si ripete offline
  l’intera valutazione di percorso, revoca, responder, tempo e qualificazione.
  Le date della seconda verifica sono congelate: producedAt/thisUpdate futuri
  restano rifiutati. Si include anche il tempo di acquisizione del catalogo TL.
  Non serve una cache persistente per completare questa rivalutazione.
- Per ciascun certificato viene selezionata una prova GOOD autenticata con la
  copertura richiesta. Evidenze alternative non valide non la mascherano. Una
  revoca autenticata ha sempre precedenza, anche da cache o CRL alternativa.
- La data mostrata/esportata dal workspace coincide con la data della valutazione
  finale. Nessun redesign UI, nessuna modifica a firme, PIN o middleware.

Le primitive C di firma OCSP, delega/no-check, binding, algoritmi e finestre
restano identiche; nessuna nuova tolleranza temporale o regola di fiducia implicita.

### Riproduzione del caso reale

Correlazione verificata: SHA-256 del contenuto firmato e DER del firmatario del
CMS coincidono con i digest nel diagnostico DSS. Non ci si basa sul solo nome.

| Caso | Integrità/catena | Revoca | Qualificazione | Tempo di apposizione |
|---|---|---|---|---|
| Prima: stesso CMS/TL/OCSP conservato | verificate | GOOD | indeterminata per estensioni TL | non provato |
| Dopo: replay della stessa risposta, acquisizione simulata | verificate | GOOD | QES corrente, valutata 15:36:00Z | non provato |
| Dopo: nuova interrogazione online con trasporto di produzione | verificate | GOOD | QES corrente, valutata 15:55:31Z | non provato |
| Dopo: replay con policy storica esplicita | verificate | GOOD | indeterminata | non provato |

Tutte le date in tabella sono UTC del 25 ottobre 2026. La qualificazione positiva
è relativa all’istante corrente esplicito della valutazione, non al signingTime
24 ottobre e non è una prova storica/LTV. Il replay usa la risposta acquisita da
Signum, non un booleano DSS. La verifica online ripete autonomamente la catena di
controlli; la risposta DSS originale non è disponibile in DER nei rapporti.

La causa TL della qualificazione indeterminata è confermata direttamente. Il
vecchio esito di revoca indeterminata non è attribuibile con certezza a un unico
errore di rete/tempo senza il log e i DER di quella specifica invocazione. Sono
però riprodotte le lacune temporali e di aggregazione descritte, ora corrette.

### Test e build

126 test distinti superati: 107 CertificateValidation e 19 TrustCore, esclusi i
rerun dal conteggio. Il test ForeSignatures + ForeSeals falliva prima della
correzione; passa dopo. Nuovi casi deterministici, senza rete o attese artificiali:
acquisizione che attraversa producedAt, assenza di cache, nessuna seconda richiesta,
risposta ancora futura, scadenza durante l’acquisizione, dati alterati/revocati,
CRL alternativa non interpretabile, precedenza di revoca e annullamento.

Le regressioni coprono anche timestamp, qualificazione storica, CA/intermedi,
cache/rifiuto sostituzioni, TL/LOTL, XAdES/ASiC e report esportati. Debug e Release
locali riuscite. Le build comprendono le modifiche locali preesistenti del checkout:
i loro file sono stati confrontati tramite hash e risultano invariati. Non si
presenta il checkout come una build pulita di soli commit dell’indagine.

### Materiali e limiti residui

`.build/dss-investigation/Results.json` e log relativi contengono gli esiti; la
stessa cartella conserva il rapporto preliminare, hash, probe, risposte e cache
TL copiate, senza modificare la cache personale originale. I dati reali non sono
inclusi nei fixture/commit; le nuove regressioni utilizzano solo dati sintetici.
La cartella è materiale locale riservato, non un pacchetto da pubblicare.

Restano intenzionalmente non supportati responder senza no-check che richiedano
revoca ricorsiva, CRL indirette/delta/ristrette, profili e Paesi non collaudati e
policy avanzate DSS esterne alla copertura Signum. L’assenza di POE continua a
impedire un’affermazione storica. Il vecchio comando evidence mantiene la policy
storica predefinita: il confronto corrente deve richiedere bestAvailable/currentTime.

Nessuna nuova Build 9, installazione, GitHub Action, merge o release. HalleyMac
non modificato. Le modifiche preesistenti PKCS#11/Package/CXMLSecurity non sono
state incluse nell’intervento. STOP con diagnosi e correzioni locali.
