# Signum 0.4-A.4 — Batch Authentication & Signing Workspace

## M1 — Baseline

18 ottobre 2026. HEAD effettivo build 4 `51e9d22`, codice candidato `daca4cf`.
Nuovo branch `codex/signum-0.4-batch-auth`. Tracciati puliti, review non tracciata
preservata (SHA-256 `2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`).
Worktree verificati senza aprire altri checkout; main resta `be84a1e`.
Nessun accesso a HalleyMac. Il collaudo di sette CAdES DigitalDNA/Bit4id/DS3
riusciti sulla build 4 è riferito dall'utente, non eseguito qui.

Baseline locale: Swift **240/240**, PKCS#11 **40/40**, PAdES Debug/Release
**63/63** ciascuno; build Swift Debug/Release passate. Helper esplicito, fixture
solo sintetiche; log `.build/reliability/evidence/04a4-baseline-*`.
Alpha e candidati precedenti preservati. Nessun PIN reale/hardware/CI remoto.

## M2 — Analisi e confine architetturale

Riferimento funzionale aggiunto dall'utente: InfoCamere consente più documenti
con un solo inserimento PIN, sia DigitalDNA sia CNS. Evidenza d'uso, non prova
di sessioni PKCS#11, cache PIN, servizi o protocolli interni. Nessuna attribuzione
di un meccanismo a InfoCamere o capability dedotta da marca/label.

Riferimento normativo: [OASIS PKCS#11 3.1, C_Login e CKA_ALWAYS_AUTHENTICATE](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).
USER e CONTEXT_SPECIFIC hanno ruoli distinti; ALWAYS_AUTHENTICATE true richiede
autenticazione per uso dopo SignInit. Il riuso di una sessione USER non autorizza
a saltarla. Un login già esistente non prova la verifica del PIN appena fornito.

Il percorso attuale avvia SignumPKCS11Worker per ogni job, acquisisce lease,
Initialize/OpenSession, verifica DER/policy, login USER, FindObjects/SignInit,
eventuale login CONTEXT_SPECIFIC, Sign, CloseSession e Finalize. Nessun Logout
indiscriminato. Registry in-process distingue ownership Initialize, ma non unisce
processi. Il lease provider/slot coordina solo processi Signum cooperanti.

Decisione: prototipo **CAdES** con worker dedicato al batch e protocollo interno
incorniciato/bounded. Manifesto immutabile di job e attributi CMS, nessun documento
o percorso input/output nel worker. Padre conserva snapshot, verifica RSA/CMS e
pubblicazione atomica. Un job successivo viene richiesto soltanto dopo il commit
verificato del precedente: nessuna pre-firma della coda e nessun retry di Sign.

Primo PIN autentica USER e il primo job. Attributo leggibile false, identità
token stabile, inizializzazione posseduta e sessione valida consentono il riuso.
True richiede CONTEXT_SPECIFIC per il primo job e chiusura, poi percorso one-shot
con un nuovo PIN per ogni documento; attributo sconosciuto conserva il percorso
conservativo. PIN non mantenuto per le richieste successive. Errori/disconnessione/
timeout/crash interrompono il canale; nessun fallback automatico di un job incerto.

PAdES usa un altro processo/lease e non può condividere un handle PKCS#11.
Deferita la modifica del protocollo PoDoFo; batch PAdES e misti restano one-shot,
con spiegazione esplicita. Nessuna promessa di ottimizzazione universale o di
compatibilità hardware prima del collaudo autorizzato.

## M3 — Prototipo worker persistente

Protocollo interno v2 a frame da 4 byte + JSON (richiesta <=128 KiB, risposta
<=64 KiB, massimo 32 job e attributi <=4096 byte). Manifesto fissato prima del
login: batch/job/snapshot/hash, provider/identità file, slot/seriale, DER e attributi.
Comandi successivi non contengono PIN o nuovi attributi. Sequenza e identificativi
impediscono richieste duplicate o fuori ordine. Nessun protocollo pubblico.

Worker conserva hardening parent-death/core dump/vendor stdout/stderr del percorso
one-shot, limite condiviso di otto processi e lease per tutto il batch, compresa
chiusura verificata. Timeout per scambio, idle worker 60s, durata batch 600s,
teardown bounded con terminazione/reaping; nessuna chiamata Finalize concorrente
a un'operazione bloccata. Il padre verifica RSA con la chiave DER approvata.

Shim C: sessione dedicata, USER fresco obbligatorio, controllo token/DER/policy e
stato USER a ogni firma. Attr false noto e Initialize posseduta abilitano riuso;
true/unknown chiudono dopo la prima firma. True effettua CONTEXT_SPECIFIC dopo
SignInit con il PIN del primo job. Nessun Logout; chiusura delle sole sessioni
possedute, poi Finalize secondo ownership. Seriali sono indizi di continuità,
non attestazioni crittografiche di identità fisica; DER/firma restano vincolanti.

Test prototipo e regressioni worker/lifecycle **18/18**: tre firme/un USER,
true/CONTEXT, attributo sconosciuto, login preesistente rifiutato, duplicati/ordine,
login fallita senza retry. Prima esecuzione: tre assert usavano il numero errato
per Finalize nel solo audit sintetico (2 anziché 1); corretti rispetto all'enum
mock, ripetuti positivi. Nessuna riduzione delle verifiche del prodotto.

## M4 — Integrazione CAdES

BatchCAdESSession contiene solo piano e canale, mai PIN. Il primo invio del campo
autentica il primo job; la continuazione Core non ha parametro PIN e usa solo
questa capability legata all'approval ID. Firma RSA verificata nel padre, poi
motore CMS, verifica staging e pubblicazione Foundation esistenti. Solo dopo il
commit viene chiesta la firma successiva. Skip espliciti per job approvati ma
annullati non effettuano Sign. Nessun inserimento di nuovi job nel manifesto.

Fine normale: sessione e provider chiusi con conferma prima di pubblicare l'ultimo
output. Per errori/cancellazione, revoca immediata e teardown off-main; nessuna
prosecuzione automatica dopo fallimento. Crash/timeout senza firma verificabile
diventano esito incerto, non un tentativo da ripetere. Chiusura non confermata
resta visibile e richiede controllo dell'utente. PAdES e misti invariati one-shot.

Le prove integrate hanno individuato un blocco di Foundation waitUntilExit quando
launch e chiusura avvengono su thread pool differenti. Stack campionato, runner
sintetico bloccato interrotto; eliminata l'attesa bloccante dal nuovo canale.
Ora osservazione bounded dello stato terminato e reaping automatico Foundation;
slot conservato se il sistema non termina il figlio. Regresso anche il teardown
su thread diverso, senza attese vendor/MainActor. Nessuna modifica al supervisore
one-shot oltre alla condivisione del contatore dei processi.

M4: **36/36** test mirati, zero skip/fallimenti nel run finale; primo run
intermedio aveva due skip per helper non esplicito e tre assert legacy dovuti
alla guard di authorizeNext durante l'estrazione dell'esecutore interno. Ripetuto
con helper esplicito e semantica pubblica preservata. Test integrati: tre CAdES
verificati/un PIN; true/tre USER e CONTEXT; annullamento in coda/in Sign; collisione
secondo output; snapshot corrotto; crash/timeout/errore secondo Sign; perdita
sessione e device removed; seriale/modulo cambiati prima del login; lease fra due
batch distinti; nessun PIN nei comandi successivi, nessun retry dopo errore.

## M5 — Impostazioni e flusso GUI

Preferenza persistente «Autenticazione nella firma multipla»: Automatica, quando
supportata / Richiedi PIN per ogni firma. Default automatico **condizionale**;
valori sconosciuti degradano alla seconda modalità. Nessun dato sensibile nelle
preferenze. Modalità scelta fissata al clic di approvazione, non riletta durante
il batch. Prima del PIN la GUI spiega che il supporto sarà verificato e può
richiedere altre autenticazioni; PAdES/misti/seriale indisponibile usano one-shot.

Dopo il primo job riutilizzabile, continuazione senza segreto e senza ulteriori
popup; PIN nascosto mentre il batch prosegue. In caso true/unknown, prima sessione
già chiusa e nuovo PIN esplicito per i documenti restanti. Non tentata nuovamente
la modalità persistente nello stesso batch dopo un rifiuto. Nuova sessione,
cancellazione e scomparsa della finestra revocano la capability; attese e chiusura
restano off-main. Nessuna attribuzione di capability al nome del dispositivo.

Test M5: preferenza isolata/persistenza/valore invalido e assenza credenziali,
policy CAdES/PAdES/misti/identità sconosciuta, regressioni auth/UI/PIN. Il caso
seriale/modulo cambiato, aggiunto dopo il run M4, è verificato qui prima del login.

M5: **27/27** test mirati, più **1/1** specifico per identità modulo/seriale.
Quest'ultimo era inizialmente annidato per errore in un altro metodo e quindi
non scoperto da XCTest: corretto lo scope, eseguito esplicitamente e contato
soltanto dopo l'esecuzione. Il run finale completo lo include.

## M6 — Workspace compatto

Intestazione unica Documenti, conteggio, barra e riepilogo degli esiti. Riga
principale: indicatore semantico, nome troncabile/tooltip, formato e stato breve.
Prima del consenso restano visibili le destinazioni effettive già pianificate;
poi i percorsi vengono mostrati solo espandendo. Dettagli per documento: origine,
destinazione, dimensione/hash, verifica, certificato/fingerprint, provider/slot,
ID job/snapshot ed errore integrale. Azioni Rimuovi/Annulla nei dettagli; Apri
cartella e Nuova sessione nell'intestazione. Nessun Finder avviato dai test.

Riepilogo separa successi, fallimenti, annullamenti e risultati da verificare.
PDFKit e approvazione degli snapshot restano invariati. Campo PIN fuori dallo
scroll laterale, nascosto durante continuazione automatica. Nessun redesign,
animazione o Liquid Glass. Candidato portato a **0.4.0/build 5**, target 13 invariato.

**31/31** test mirati finali auth/workspace/PIN, inclusi teardown bloccato visibile
e Initialize non posseduta (nessun Finalize/riuso). Aggiornato un solo assert sul
test interazione per il nuovo testo richiesto «3 documenti firmati correttamente»;
prima esecuzione lo segnalava come differenza, invarianti PIN/firme mantenuti.
Modello riepilogo coperto da due nuovi test; terzo test nativo aggiunto per errore
visibile, nessun PIN e nessun output. Rendering propri NSHostingView/NSWindow
ispezionati: lista 32 documenti/PIN raggiungibile a 650 punti, errore distinguibile
e pannello PDFKit conservato. PNG `.build/04a4-ui`. Versione dei PNG è quella
dell'host XCTest (16.0/build 25229), non del bundle. Rendering GPU del contenuto
PDF non interamente acquisito: verificati documento/pageCount e binding snapshot,
non dichiarata completa accettazione visiva/interattiva.

Ultimo controllo layout dopo le sole etichette singolare/formato nuovi documenti:
**5/5** (riepilogo e viste native). Nessun popup o interazione hardware nei test.

## M7 — Validazione e consegna

Codice finale **`7596f50`**, 18 ottobre 2026, host macOS 27.2 arm64 / Swift 6.4.
L'ultimo hardening impedisce di inviare un PIN durante la continuazione già
autenticata e conserva l'annullamento prima delle operazioni private. Aggiunto
un override **solo nei test** per verificare esattamente il worker impacchettato;
nessun flag di test introdotto nel prodotto.

| Verifica realmente eseguita | Esito finale |
| --- | --- |
| Suite Swift completa | **265/265**, zero fallimenti o skip (baseline 240) |
| Suite nativa PKCS#11 | **40/40** casi sintetici |
| PAdES Debug e Release | **63/63** per configurazione; ripetuti su helper nel bundle e copia rilocata |
| Test packaging Python | **10/10** |
| Address Sanitizer, suite mirata | **64/64**, nessun errore segnalato; leak detection disabilitata |
| Thread Sanitizer, stessa selezione | **64/64**, nessuna race segnalata |
| Auth/integrazione con worker esatto del bundle Release | **20/20** |
| Build Swift Debug e Release | Passate |
| Creazione/verifica bundle Debug e Release | Passata, firma ad hoc stretta, hash componenti e rilocazione |
| Audit dei due bundle | 0.4.0/build 5, source `7596f50` pulito alla build, cinque Mach-O con minimo 13.0, dipendenze portabili |
| CLI impacchettata → worker → discovery provider sintetico | Passata su entrambi i bundle |

ASAN/TSAN comprendono i nuovi componenti auth, coordinatore, workspace, lifecycle,
worker e coordinamento processi; **non** sono una seconda esecuzione dell'intera
suite. Verificati anche i simboli di strumentazione dello shim C nei due scratch.
Il provider simulato compilato separatamente e i middleware reali non sono
strumentati. Nessun test hardware, PIN personale, documento reale o upload.
Le verifiche PAdES complete Swift usano l'helper build 4 esplicitato; il nuovo
helper è verificato dalle suite native nei due nuovi bundle e nelle copie rilocate.

Evidenze locali in `.build/reliability/evidence/`: `04a4-final-swift.log`,
`04a4-final-pkcs.log`, `04a4-final-asan.log`, `04a4-final-tsan.log`,
`04a4-final-packaging-tests.log`, `04a4-final-build-{debug,release}.log`,
`04a4-package-{debug,release}.log`, `04a4-bundled-auth.log`,
`04a4-bundle-audit.log`. I fallimenti intermedi e le correzioni sono descritti
nelle rispettive milestone; gli esiti sopra appartengono ai runner finali.

### Candidata e stato Git

**0.4.0/build 5**, arm64, firma locale ad hoc, nessuna notarizzazione/distribuzione:

- Release: `.build/04a4-bundles/final-release/Signum.app`.
- Debug: `.build/04a4-bundles/final-debug/Signum.app`.

Percorsi relativi a `/Users/andreaoregioni/Developer/Signum-Reliability`.
Build 4 in `.build/04a31-bundles/delivery-{debug,release}/Signum.app`, Alpha e
candidati precedenti preservati. Il commit documentale finale è successivo al
codice `7596f50` registrato nel manifesto del bundle; non è una build differente.

Commit locali sul branch `codex/signum-0.4-batch-auth`:

| Milestone | Commit |
| --- | --- |
| M1 baseline | `c780af7` |
| M2 analisi | `7cc6154` |
| M3 prototipo worker | `61564f1` |
| M4 integrazione CAdES | `a3f7a98` |
| M5 impostazioni | `0fc91a5` |
| M6 workspace e regressioni | `379b790` |
| M7 hardening preflight/continuazione | `4faaf4e` |
| M7 regressioni worker impacchettato | `7596f50` |
| M7 rapporto e progresso | commit che contiene questa consegna |

Main invariato `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70`; branch build 4 invariato
`51e9d22a9d26e50fcc7665247e9495a5e6402da8`. File di review non tracciato
preservato con l'impronta indicata in M1. Nessun push/merge/tag/release, CI remoto,
installazione globale o accesso a HalleyMac. Il solo residuo Git intenzionale è
quella review non tracciata.

### Limiti e interventi rinviati

- Ottimizzazione dimostrata **con provider sintetico CAdES**, non ancora su
  DigitalDNA, CNS, Bit4id o OpenSC reali. Il risultato InfoCamere riferito
  dall'utente resta il riferimento funzionale, non prova del meccanismo interno.
- True, attributo illeggibile, inizializzazione non posseduta o identità
  insufficiente impediscono il riuso. Un errore dopo l'invio di una richiesta
  privata senza firma verificabile è conservativamente incerto, anche quando
  il provider potrebbe aver fallito prima di Sign: nessun retry/fallback del job.
- PAdES e misti rimangono interamente one-shot. Una futura condivisione richiede
  un protocollo interno diverso: handle process-local e lease attuale non possono
  essere condivisi mantenendo semplicemente aperto questo worker. Non iniziata.
- Lease e limiti coordinano processi Signum cooperanti, non altre applicazioni.
  Nessun utilizzo di login altrui; nessuna deduzione dal nome del certificato.
- Canale: scambio massimo 120s, idle worker 60s, vita batch 600s; finish 5s e
  osservazione uscita 3s, poi terminazione supervisionata. Se il kernel non
  termina un figlio, lo slot resta occupato fino all'uscita e la chiusura non
  confermata richiede controllo. Nessun Finalize concorrente a una chiamata appesa.
- Nessun PIN conservato nel coordinatore, preferenze, manifesto persistente,
  richieste successive, argv/env o log. Le copie transitorie Swift/String e la
  memoria del middleware non consentono una garanzia forense di azzeramento.
- Limiti Foundation invariati: 100 MiB/documento, 128 MiB/sessione, output 132 MiB.
  Nei frame del worker viaggiano attributi CMS, non documenti.
- Minimo macOS 13 verificato in metadata/Mach-O/packaging; runtime macOS 13/14,
  Mac pulito e accettazione completa interattiva della nuova GUI non eseguiti.
  Rendering nativi e PDFKit verificati nei limiti descritti in M6.

### Riproduzione software locale

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
SIGNUM_TEST_PADES_HELPER="$PWD/.build/04a31-bundles/delivery-release/Signum.app/Contents/Helpers/signum-pades-local" swift test --scratch-path .build/reliability
SIGNUM_TEST_BATCH_WORKER="$PWD/.build/04a4-bundles/final-release/Signum.app/Contents/Helpers/SignumPKCS11Worker" swift test --scratch-path .build/reliability --filter 'BatchAuthenticationTests|BatchAuthIntegrationTests'
scripts/test-pkcs11-local.sh
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build --scratch-path .build/reliability -c debug
swift build --scratch-path .build/reliability -c release
```

Per ripetere PAdES e packaging insieme utilizzare `scripts/build-beta-app.py`
con `--configuration debug` e `release`, prefisso privato
`--native-prefix .build/pr2-native-macos13/prefix` e `--output` **nuovo** per ogni
bundle. Il packager configura/compila/verifica la suite nativa e il bundle
rilocato. Non sovrascrivere i candidati consegnati. I run sanitizer usano
`swift test --sanitize=address` e `--sanitize=thread` in scratch separati;
selezione: `BatchAuthenticationTests|BatchAuthIntegrationTests|BatchAuthenticationPreferenceTests|BatchWorkspaceSummaryTests|BatchSigningTests|SigningInteractionTests|SigningWorkspaceTests|PKCS11LifecycleIntegrationTests|PKCS11WorkerTests|ProcessCoordinationTests`.
Per ASAN impostare `ASAN_OPTIONS=detect_leaks=0`; esplicitare anche l'helper
PAdES come sopra per non saltare le integrazioni.

### Collaudo manuale preparato, non eseguito

Demo fresca `.build/04a4-demo`: tre `.txt` e PDF sintetici, certificato valido
sette giorni e modulo software `.build/04a4-demo/synthetic-provider.dylib`.
Solo discovery CLI eseguita; nessuna apertura della GUI o firma hardware.
Istruzioni della fixture in `.build/04a4-demo/DEMO.txt`. Rigenerare dopo la
scadenza con `scripts/prepare-batch-demo.py --output` in directory nuova.

1. Per una prova **solo software**, scollegare i token reali, aprire esattamente
   `final-release/Signum.app`, scegliere il modulo sintetico e il suo certificato.
   Non utilizzare PIN personali: il mock accetta una stringa fittizia non vuota.
2. Modalità Automatica: aggiungere tre `.txt`, controllare destinazioni pronte,
   approvare una volta e inserire una sola stringa fittizia. Attendere tre output
   verificati e il riepilogo; provare dettagli, Apri cartella e Nuova sessione.
3. Modalità PIN per ogni firma: nuova sessione e destinazioni libere, verificare
   tre richieste. PDF PAdES e batch misti devono conservare richieste individuali.
   Errori/risultati incerti devono restare distinguibili; nessun retry automatico.
4. **Solo dopo autorizzazione hardware esplicita**, ripetere con DigitalDNA e poi
   CNS, documenti sintetici e cartella nuova. Discovery automatica, certificato
   idoneo, tre CAdES in Automatica: annotare numero effettivo di richieste e
   messaggio di policy, senza registrare PIN. Un attributo true/unknown può
   legittimamente richiedere altri PIN; non dedurne la causa dal produttore.
5. In sessioni separate confrontare PIN per firma, tre PAdES e un batch misto;
   controllare output con il verificatore abituale. Su errore/incertezza fermarsi,
   conservare solo dettagli non sensibili e non ripetere il job automaticamente.
6. Con ulteriori batch sintetici verificare annullamento, finestra chiusa e nuova
   sessione: nessuna prosecuzione dei job revocati e nuova autenticazione per
   il nuovo batch. Il collaudo precedente di sette documenti non valida questi
   cambiamenti né sostituisce questo controllo.

M1–M7 concluse per il perimetro software concordato. Nessuna nuova fase avviata;
collaudo reale e accettazione interattiva restano separati dalla consegna.
