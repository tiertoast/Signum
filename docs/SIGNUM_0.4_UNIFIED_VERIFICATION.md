# Signum 0.4-C — Verifica unificata

18 ottobre 2026. Branch `codex/signum-0.4-pades-verification`.
B è stata completata, testata, committata (`9f7684b`) e impacchettata in build 7
prima di iniziare C; evidenze e bundle nel relativo rapporto. Base build 6,
Alpha, main e PR #3 preservati. Nessuna prova hardware/PIN reale o rete documentale.

## Funzionalità e architettura

Sezioni principali **Firma**, **Verifica**, Impostazioni. Apri documenti o drop
multiplo, riconoscimento dal contenuto, coda sequenziale fino a 32 documenti,
risultati indipendenti, annullamento, riepilogo e dettagli per firma. Nessun
provider, token, certificato personale o PIN nell'API o nell'interfaccia Verifica.
La normale discovery della sezione Firma resta indipendente e non è necessaria
alla verifica. Nessun cambiamento a Secure Batch PIN/CAdES e PAdES per documento.

`SignumCore/UnifiedVerification.swift`: servizio condiviso GUI/CLI, formati e
integrità tipizzati, certificato, revisione, livello CMS, hash documento e limiti.
`SignatureFormatDetector` fornisce soltanto indizi bounded; l'autorità sul formato
è il parser isolato, che ignora l'estensione. Un CMS con PDF incorporato resta
CAdES: la struttura CMS ha precedenza sul magic PDF contenuto nella busta.
CMS di tipo diverso da SignedData è non supportato, non dichiarato corrotto.
XML è soltanto riconosciuto come candidato non supportato, senza parsing XAdES.

L'entry point privato `signum-pades-local --verify-stdin-v1` precede ogni gestione
di provider, PIN, lease e firma. Riutilizza il parser PDF e il verificatore SG-03;
per CMS usa OpenSSL 3 già incorporato nel motore nativo, senza un nuovo parser
ASN.1. Gli stessi controlli `CMS_SignerInfo_verify` e
`CMS_SignerInfo_verify_content` usati internamente da `CMS_verify` vengono
valutati separatamente per firmatario, dopo binding ai certificati incorporati e
calcolo del digest mediante `CMS_dataInit`. Una firma alterata non trasforma
artificialmente l'altra in valida/non valida. Catene/trust store non interrogati.

Il precedente `CAdESVerifier` con OpenSSL di sistema resta invariato per firma,
CLI legacy e regressioni; serve anche da riferimento indipendente nei test.
Il nuovo backend condiviso risiede nel processo nativo per isolare anche il
parsing e restituire metadati per firmatario. È richiesto lo helper nel bundle,
non l'installazione di OpenSSL/Homebrew/CMake da parte dell'utente.

CAdES: SignedData attached, payload qualsiasi, fino a cinque livelli annidati,
32 firmatari totali e 64 certificati per busta. RSA/EC e SHA-256/384/512 nei
controlli di integrità locali; algoritmi fuori policy, certificato assente e
contenuto detached non fornito restano **non verificabili**, con motivo. Nessuna
ricerca automatica di certificati o contenuti esterni. Payload restituito solo
quando tutte le firme incontrate sono verificate; nessuna estrazione automatica.

PAdES: signature dictionary raggiungibili dall'AcroForm corrente, ByteRange e CMS
propri, fino a 32 firme. Riusa le verifiche SG-03 su gap `/Contents`, intervalli,
attributi, digest e firma. Il suo profilo conservativo resta: `Type=Sig`,
`Filter=Adobe.PPKLite`, `SubFilter=ETSI.CAdES.detached`, SHA-256, un firmatario CMS
per dictionary. Altri profili/algoritmi vengono segnalati non verificabili;
non si dichiara supporto universale dei PDF di terzi o conformità ETSI completa.
Un valore `/V` malformato non viene confuso con un campo vuoto/non firmato.

La fine del ByteRange individua la revisione coperta. Byte successivi presenti
sono segnalati separatamente: una revisione precedente può mantenere integrità
verificata. Non si approvano modifiche successive. Nessuna analisi DocMDP,
FieldMDP, cronologia completa degli xref, firme rimosse/nascoste dall'AcroForm
corrente o trasformazioni consentite. Il riepilogo non è un giudizio globale di
validità giuridica del PDF.

## Stati e interfaccia

Integrità **verificata / non valida / non verificabile / assente**; formato non
supportato e documento danneggiato distinti, con il motivo preciso disponibile.
Nome documento, formato, numero firme e stato sintetico; dettagli espandibili
con subject/emittente/fingerprint SHA-256, algoritmo, data dichiarata se presente,
revisione/livello CMS ed errori. La data dichiarata non è una marca qualificata.
Trust, revoca e qualificazione hanno stati autonomi **non valutati**, sia per il
report sia per ciascuna firma. Nessuna icona/etichetta di validità legale.

Anteprima PDFKit opzionale e in memoria, sorgente immutabile. Il parser isolato
controlla anche struttura e limite pagine del PDF incorporato nel CMS prima di
abilitare la preview. La vista mostra una thumbnail statica navigabile per pagina:
nessun link, azione, script o allegato cliccabile. Non salva il PDF rielaborato.
PDFKit effettua il rendering della preview nel processo UI: non è una sandbox né
una garanzia di memoria dei framework; preview complesse vanno ancora collaudate.

Conservata l'estrazione **esplicita** del contenuto CAdES verificato, anche non
PDF, con NSSavePanel e `SignumFileOutput.writeNew`: staging privato, no-overwrite,
nessuna riapertura dell'originale e nessuna esecuzione del file estratto. Un export
per volta, fuori dal main actor. Il budget di 128 MiB limita insieme preview e
payload trattenuti nel workspace; i risultati restano se il contenuto non viene
conservato. Il payload PDF e la preview condividono gli stessi byte.

CLI nel bundle: `Contents/Helpers/SignumCLI verify documento`, senza provider.
Stampa risultati e limiti, non salva allegati. `verify-cades` ed estrazione legacy
restano disponibili. L'exit code di `verify` indica l'esecuzione del controllo,
non sostituisce lo stato di integrità stampato.

## Limiti di sicurezza

Input regolari locali fino a **132 MiB** per verificare anche output di firma;
limite di firma sempre **100 MiB**, immutato. Lettura su descriptor pinned mediante
`CAdESVerifier.readInput`: no leaf symlink, no riapertura, identità del percorso e
modifiche controllate. Il report si riferisce ai byte acquisiti e al loro hash.
Non esiste rete/OCSP/CRL, trust store o apertura di percorsi indicati dal CMS.

Trasporto stdin/stdout nonblocking supervisionato: deadline monotona 30 s,
annullamento, limite input/output e metadati 256 KiB, massimo otto processi,
terminazione/escalation, niente retry. Il processo nativo termina se muore il
parent; core dump disabilitati, CPU 25 s, file output regolari proibiti tramite
RLIMIT_FSIZE. Nessun percorso sorgente/destinazione trasmesso al parser.

macOS su questo host rifiuta RLIMIT_DATA/AS/RSS finiti: prova locale conservata
nella cronologia del lavoro, nessun limite OS di memoria dichiarato falsamente.
Il parent campiona RSS ogni 5 ms e uccide il parser sopra **1 GiB**; errore se un
processo vivo resta inosservabile. Uscita/zombie distinti per evitare falsi errori
alla fine del lavoro. È una soglia campionata, può avere overshoot e non limita
la memoria totale del processo UI né le librerie di sistema. Input, output,
numero di firme/certificati, profondità campi (16), budget campi (1024) e pagine
(1000) sono limitati; non è un parser formalmente verificato o sandbox completo.

Un test da 100 MiB ha dimostrato il collo di bottiglia della pausa fissa dopo
ogni scrittura da 16 KiB: superava 30 s senza errore crittografico. La supervisione
ora attende eventi della pipe con `poll`, mantenendo deadline e cancellazione.
Default e limiti dei comandi di autenticazione invariati; regressioni PKCS#11,
worker, no-retry, crash e consenso rieseguite.

## Test e risultati

Fixture esclusivamente sintetiche. 15 nuovi metodi XCTest coprono: CAdES attached
non PDF e riconoscimento senza estensione; riferimento OpenSSL di sistema;
alterazione; certificati/hash; payload PDF annidato; detached/certificato assente/
SHA-1 non supportato; data dichiarata; due firmatari indipendenti e uno alterato;
CMS malformato e ContentInfo non supportato; XML/sconosciuto/PDF troncato;
PAdES non firmato/invisibile/grafico/multifirma incrementale; revisioni precedenti
con byte successivi; ByteRange sovrapposto/alterato; CMS PDF malformato/missingcert/
SHA-384 fuori profilo SG-03; file da 100 MiB; no symlink e limite 132 MiB; originali
invariati; crash/timeout/cancel/RSS; batch, drop nativo multiplo e budget memoria.
L'audit del provider sintetico resta identico prima/dopo verifica: nessuna login
o operazione PKCS#11 richiesta dalla verifica.

Controllo indipendente dei quattro veri PDF PAdES delle prove B: estratti CMS e
contenuto ByteRange, tutti verificati con `/usr/bin/openssl cms -verify -binary
-noverify`; non è verifica di trust. Raster indipendente Poppler già nel rapporto B.
Log locali in `.build/reliability/evidence/04c-*`. I log iniziali conservano i
fallimenti corretti: riconoscimento CMS/PDF, strozzatura del trasporto, race di
monitoraggio durante uscita e fixture CMS oltre la riserva (guard corretta, senza
cambiare la riserva delle firme reali). Non vengono presentati come run passati.

## Collaudo manuale e perimetro residuo

Da eseguire dall'utente sulla candidata, senza assumere esiti già ottenuti:

1. Aprire Verifica senza token; aprire/trascinare più PDF e p7m sintetici, anche
   rinominati, e controllare risultati separati, dettagli, annullamento e preview.
2. Esportare un originale verificato in un nuovo file; ripetere sul nome esistente
   e controllare il rifiuto. Nessuna estrazione nella cartella origine al drop.
3. Controllare il messaggio per XML, PDF non firmato, documenti alterati e profili
   non supportati. Nessun messaggio di fiducia/revoca/validità legale verificata.
4. Firma PAdES con PNG/JPEG/alpha/testo, prima/ultima pagina, CropBox, rotazioni,
   zoom/scroll/drag; controllare PDF finale in visualizzatori differenti. Questi
   collaudi interattivi completi e nuovo hardware richiedono una prova separata.
5. Provare runtime macOS 13/14, middleware differenti e PDF eterogenei; questo host
   è macOS 27.2 arm64, SDK 27.0. Minimo Mach-O 13.0 non prova quei runtime.

Rinviati: ulteriori profili PDF e algoritmi, detached con contenuto selezionato,
Trusted Lists, OCSP/CRL, eIDAS, timestamp qualificati/LTV, XAdES operativo, sandbox
più restrittivo, ricerca storica di firme non raggiungibili e DocMDP/FieldMDP.
Nessuna estensione Secure Batch PIN a PAdES; nessun Developer ID/notarizzazione,
DMG, distribuzione, Windows, integrazione esterna o protocollo pubblico.


## Checkpoint C prima dei bundle

| Controllo locale | Risultato realmente eseguito |
| --- | --- |
| Swift completo, helper esplicito | **317/317**, zero skip/fallimenti |
| Nuove suite e ultime fixture scroll/pagine differenti | **24/24** |
| PKCS#11 sintetico | **40/40** |
| PAdES Debug / Release | **63/63** ciascuna |
| Test unit packaging | **10/10** |
| Build SignumApp Debug / Release | Passate |
| ASAN mirato, incluso helper nativo strumentato | **54/54**, zero errori |
| TSAN Swift mirato | **54/54**, zero race segnalate |
| Native ASAN | **63/63** |

ASAN con leak detection disabilitata, librerie terze/framework non interamente
strumentati. Run precedenti anche 24/24 con entrambi i processi ASAN; le ultime
fixture di geometria sono state rafforzate dopo il run sanitizer e rieseguite
normalmente, senza cambiamenti successivi al codice applicativo. Warning storico
su risultato non usato in `ProviderSelectionTests`, nessun nuovo errore compiler.
Picco RSS osservato nel runner Swift completo circa **1.15 GiB** (include tutte
le fixture da 100 MiB e le cache, non soltanto la verifica); la soglia 1 GiB è
specificamente del processo parser separato, non del runner/UI.

Evidenze finali `04c-delivery-*`, `04c-final-geometry-tests.log`,
`04c-independent-cms.log`, `04c-rlimit-probe.log`. La fonte avanza a
**0.4.0/build 8**. Il commit di implementazione che aggiunge questo rapporto è
il checkpoint C; i manifest dei successivi bundle registrano il suo hash.

## Correzione diagnostica prima della consegna finale

Checkpoint iniziale C **`89dfb14`**, bundle Debug/Release **build 8** verificati
in `.build/04bc-bundles/delivery-{debug,release}/Signum.app`, manifest clean,
firma ad hoc/hash/minimo 13.0 e rilocazione passati. Con gli helper impacchettati:
**39/39** integrazioni; CLI verificata su **15/15** esempi sintetici. Build 8
conservata come checkpoint, superata dalla candidata build 9.

L'ultimo controllo avversariale ha sostituito soltanto l'OID dell'algoritmo di
firma CMS con `1.2.840.113549.1.1.99`, lasciando digest e chiave RSA/SHA-256.
OpenSSL rifiuta l'operazione non supportata; la prima versione la presentava
impropriamente come digest/firma non corrispondente. La policy ora controlla anche
l'OID di firma, compatibilità con chiave RSA/RSA-PSS/EC e digest coerente, prima
della verifica matematica. Gli OID sconosciuti sono **non verificabili**, non
attribuiti a un'alterazione dimostrata. Regressione eseguita sia in CAdES sia
all'interno del CMS PAdES: suite dedicata **15/15** passata.

Il timeout di trasporto/parser non è una garanzia di cancellazione di una lettura
filesystem bloccata dal sistema operativo: acquisizione locale e hash avvengono
fuori dal main actor, ma non sono coperti da una scadenza I/O OS indipendente.

Correzione rieseguita prima del commit: Swift **317/317**, build SignumApp
Debug/Release passate, PKCS#11 **40/40**, PAdES Debug/Release **63/63** ciascuna,
packaging **10/10**, ASAN e TSAN mirati **54/54** ciascuno, native ASAN **63/63**.
Questi ultimi sanitizer includono anche le fixture rafforzate di geometria e
OID sconosciuti; zero skip/errori finali. Evidenze `04c-build9-*`. Nessun
cambiamento alle primitive di firma o agli invarianti delle milestone precedenti.
