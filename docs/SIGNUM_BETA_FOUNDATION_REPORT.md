# Signum — Beta Foundation

## Unità 1 — Analisi e design (prima delle modifiche al codice)

17 ottobre 2026. Workspace `~/Developer/Signum-Reliability`.
Fetch origin eseguito; `origin/main` è `96facb971bb01c1be146173a6728ffaff4b75bf1`,
merge della Foundation fino a `e328fbf`, inclusa la regressione deny-delete.
Creato da lì `codex/signum-beta-foundation`. Il riferimento del branch precedente
non cambia; `main` locale non viene modificato. La review non tracciata è preservata.
I collaudi DigitalDNA/DS3 e InfoCamere riusciti sono evidenze comunicate dall'utente,
non nuove verifiche hardware eseguite in questa sessione.

### Architettura rilevata

GUI: selezione → clone CoW privato/hash SHA-256 → PDFKit dagli stessi byte →
selezione certificato/idoneità locale → destinazione → approvazione del job →
PIN già inserito nel SecureField → firma su worker GCD → verifica → commit atomico.

- Discovery e certificati: `SignumWindow.load/readCertificates` chiamano
  `PKCS11Module` nel processo GUI, fuori dal main thread.
- CAdES GUI/CLI: `SigningJob` verifica snapshot e certificato, il Core costruisce
  gli attributi CMS, chiama il provider, verifica RSA con Security, verifica CMS
  con OpenSSL, pubblica con il writer Swift.
- PAdES: la GUI usa il helper PoDoFo v3 esterno con UUID/hash/certificato approvati.
  Il helper rilegge e controlla il documento privato, firma, verifica con
  CoreGraphics/OpenSSL e pubblica con il writer C++. Il trasporto ha deadline
  120 secondi e TERM→KILL; un file presente dopo errore viene conservato come
  esito incerto. Non c'è annullamento utente generale.
- CLI: le operazioni PKCS#11 sono sincrone e in-process; `sign-cades` richiede
  approvazione FIRMA prima del PIN tramite terminale. Nessun retry di firma.
- SG-02: registro in-process per modulo canonico/inode; ownership di Initialize,
  riferimenti e mutex per transazione; gestione login condiviso conservativa,
  sessioni chiuse e provider in quarantena sugli errori. Nessuna esclusione
  tra GUI, CLI e helper separati.

### Inventario delle chiamate potenzialmente bloccanti

Nel bridge `Sources/CPKCS11/pkcs11_shim.c`: caricamento `dlopen`, funzione esportata
`C_GetFunctionList`, `C_Initialize`, `C_Finalize`, `dlclose`; discovery
`C_GetSlotList`, `C_GetTokenInfo`, `C_GetSlotInfo`; sessioni `C_OpenSession`,
`C_CloseSession`, `C_GetSessionInfo`; ricerca `C_FindObjectsInit/FindObjects/
FindObjectsFinal`, letture `C_GetAttributeValue`; autenticazione `C_Login` USER
ed eventualmente CONTEXT_SPECIFIC; `C_SignInit` e `C_Sign`. Anche attesa dei mutex
SG-02 e distruttori vendor può restare bloccata. Non viene chiamato Logout per
interrompere operazioni; non vengono ripetuti automaticamente i PIN.

Il rilascio Swift avviene su coda dedicata: protegge il main thread, ma non impone
una deadline alla finalizzazione. OpenSSL nel verificatore CAdES usa
`waitUntilExit()` senza limite. Il blocco del driver non viene risolto cancellando
una Task Swift. Un crash in codice vendor può terminare l'app che lo carica.

### Valutazione e strategia

| Riscontro | Evidenza/gravità | Intervento e prove |
|---|---|---|
| Driver che non ritorna lascia un job busy | Limite dimostrato dai mock SG-02, disponibilità alta; nessun nuovo attacco hardware dimostrato | Vendor in processo sacrificabile, deadline monotona, TERM/KILL, nessun retry; mock in Initialize/lettura/firma/Finalize |
| Crash vendor nel processo GUI | Rischio plausibile, impatto alto; nessun crash reale osservato qui | Discovery, certificati e firma fuori dalla GUI; test SIGABRT/SIGKILL e GUI/main queue viva |
| OpenSSL senza deadline | Limite statico dimostrato, disponibilità media | Supervisione del verificatore, test processo che non termina |
| Cancellazione e commit concorrenti | Miglioramento necessario, non bypass accertato | Stati espliciti e punto oltre cui la pubblicazione non è più annullabile; test prima/durante/dopo |
| Registri separati tra processi | Limite dimostrato, collisione hardware plausibile | Unità distinta per lock cooperativi e backend mock condiviso; non attribuire protezione dai client terzi |
| Bundle dipende dal checkout | Limite packaging dimostrato | Unità dedicata: incorporare dylib, riscrivere rpath, firma ad hoc e audit locale; nessuna installazione |

### Design scelto per SG-06

Un processo worker per richiesta pubblica di discovery/certificati o operazione
privata. Non riutilizzare un processo che ha fallito. Il parent non carica il
middleware: il client GUI/CLI comunica via pipe private con richieste/risposte
versionate, limitate e vincolate a UUID. Nessun servizio di rete o protocollo
pubblico di integrazione.

Per CAdES, il parent conserva snapshot e commit: costruisce gli attributi già
previsti da Signum, invia soltanto attributi/certificato approvato al worker e
riceve la firma RSA. Security verifica sul certificato approvato; CMS e writer
restano sotto controllo del parent. Il worker non riceve destinazione o percorso
originale. Questo riduce TOCTOU e l'incertezza sul file finale quando muore il
worker. PAdES conserva il helper nativo e il suo commit, quindi conserva anche
l'esito incerto dopo possibile pubblicazione.

PIN soltanto nel canale stdin privato, mai argv/env/file/log. Bounded transport
non bloccante in entrambe le direzioni, nessuna diagnostica vendor mostrata o
registrata come protocollo. La memoria Swift/vendor non è una cassaforte né
zeroizzabile in modo completo. L'isolamento di processo protegge da crash/blocchi;
non è sandbox contro middleware ostile con gli stessi privilegi dell'utente.

Ogni richiesta ha deadline; l'attesa dell'utente per l'approvazione/PIN precede
il lancio. Nessun kill di thread in-process e nessun Finalize usato per spezzare
una C_Sign. Stati previsti: idle, preparing, waitingForAuthentication, signing,
verifying, completed, failed, cancelled, outcomeUncertain. Non dichiarare
completed se manca la verifica/publicazione. Una richiesta privata interrotta
non viene ripetuta automaticamente, anche se non ha pubblicato un file.

### Dipendenze e packaging analizzati

`Package.swift` e Info.plist dichiarano macOS 13; il helper locale esaminato ha
`LC_BUILD_VERSION minos 27.0` e un LC_RPATH assoluto nella `.build/native-prefix`.
PoDoFo è `@rpath/libpodofo.4.dylib`; questa build ha dipendenze di sistema
libxml2/z/libc++/libSystem. OpenSSL/FreeType sono presenti nel prefisso nativo;
la loro inclusione effettiva va calcolata dal grafo Mach-O del candidato.
SwiftUI, PDFKit, Security, CoreGraphics e CoreFoundation sono framework di sistema.

Lo script esistente `scripts/build-app.sh` scrive `build/Signum.app`, copia solo
il helper e non incorpora il grafo dylib: non va usato per sovrascrivere l'Alpha.
La fase packaging deve produrre una directory nuova ed esclusiva, firmare prima
librerie/helper e poi app, verificare codesign e assenza di riferimenti al checkout.
Firma ad hoc offline non equivale a Developer ID/notarizzazione. OpenSC/Bit4id,
configurazioni vendor e servizi smart card restano installazioni esterne:
non vengono copiati automaticamente né esaminati fuori da Signum.

## Avanzamento

- **IMPLEMENTATO:** unità 1, analisi/design; baseline preservata sul nuovo branch.
- **TESTATO:** risultati della baseline e degli incrementi riportati sotto.
- **NON TESTATO:** hardware, UI manuale, macOS minimo/Mac pulito, Developer ID/notarizzazione.
- **PIANIFICATO:** unità 2 infrastruttura SG-06, unità 3 instradamento completo e
  cancellazione/stati, unità 4 coordinamento multiprocesso, unità 5 packaging locale.

Le unità successive verranno dichiarate completate solo con codice e regressioni
passate; nessuna funzionalità è dichiarata isolata solo perché esiste un helper.

### Verifica unità 1

Baseline sul nuovo branch: Swift **116/116**, PKCS#11 **40/40**, PAdES Debug e
Release **61/61**, build SignumApp Debug/Release riuscite. Log locali ignorati:
`.build/reliability/evidence/beta-unit1-{swift,pkcs11,pades-debug,pades-release,app-debug,app-release}.log`.
Nessuna modifica al codice in questa unità; niente percentuali di coverage dedotte
dal numero di casi. Le build native restano build di sviluppo, non distribuzione.
