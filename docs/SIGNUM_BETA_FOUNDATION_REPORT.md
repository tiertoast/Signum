# Signum — Beta Foundation

Aggiornamento successivo: [correzioni della review PR #2](PR2_REVIEW_CORRECTIONS.md).
I checkpoint sotto restano storici. La consegna aggiornata corregge i due P2 e
la versione UI e mantiene il target di build macOS 13 con ricompilazione nativa
e controlli Mach-O; il collaudo runtime su macOS 13/14 rimane da eseguire.

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

- **IMPLEMENTATO:** unità 1–5: analisi, isolamento attivo GUI/CLI, supervisione e
  cancellazione, lease multiprocesso, packaging locale ad hoc arm64.
- **TESTATO:** risultati della baseline e degli incrementi riportati sotto.
- **NON TESTATO:** hardware, UI manuale, macOS minimo/Mac pulito, Developer ID/notarizzazione.
- **PIANIFICATO:** collaudo manuale middleware, matrice macOS/Mac pulito,
  Developer ID/hardened runtime/notarizzazione e revisione delle licenze prima
  di una distribuzione. Nessun Trust Engine o claim eIDAS/ETSI.

I checkpoint sotto descrivono gli incrementi realmente verificati; le note
«non ancora attivato» delle unità precedenti sono riferite a quel checkpoint.

### Verifica unità 1

Baseline sul nuovo branch: Swift **116/116**, PKCS#11 **40/40**, PAdES Debug e
Release **61/61**, build SignumApp Debug/Release riuscite. Log locali ignorati:
`.build/reliability/evidence/beta-unit1-{swift,pkcs11,pades-debug,pades-release,app-debug,app-release}.log`.
Nessuna modifica al codice in questa unità; niente percentuali di coverage dedotte
dal numero di casi. Le build native restano build di sviluppo, non distribuzione.

## Unità 2 — Worker PKCS#11 e trasporto minimo

**IMPLEMENTATO e TESTATO:** eseguibile `SignumPKCS11Worker`, client Core
`IsolatedPKCS11Client`, protocollo JSON interno a richiesta singola e
`SupervisedProcess`. Richiesta massima 128 KiB, risposta massima 2 MiB, certificati
aggregati entro 1 MiB; UUID/versione/azione controllati. PIN solo nella pipe stdin;
stdout/stderr vendor deviati a `/dev/null`, risposta sul descriptor riservato
CLOEXEC. Core dump disabilitato nel worker. Nessuna diagnostica vendor propagata.

Deadline 30 s per operazioni pubbliche e 120 s per firma, monotona, configurabile
solo dal chiamante Core. Pipe nonblocking bidirezionali; TERM poi KILL dopo 250 ms.
Se il sistema non conferma la morte entro altri due secondi, il chiamante ritorna
`terminationPending`, conserva il processo per reaping e ne mantiene occupato uno
degli otto slot: niente attesa illimitata del chiamante o crescita illimitata di
worker. Il codice usa un solo tentativo. Finalizzazione verificata prima della
risposta: anche un Finalize bloccato resta nel figlio, sotto la stessa deadline.
Il modulo può essere chiuso sincronicamente solo dal dispatcher a proprietario
singolo; l'API ordinaria conserva il lifetime SG-02 precedente.

La firma ricevuta è verificata con Security sugli attributi e DER approvati nel
parent. Una firma falsa o un reply con identità diversa non è un successo.
I mock aggiuntivi sono compilati con macro di test, mai controllati da env/argv
nel prodotto; l'audit sintetico contiene solo numeri delle operazioni. La prova
negativa verifica un solo Login e un solo Sign nel figlio, nessuno nel parent.

Nuovi test: **15**, inclusi firma RSA/CMS software valida, discovery, certificati,
Init/Finalize/Login/Sign che non ritornano, ritardi, crash/errori, rumore vendor,
versioni/bounds/UUID errati, pipe piena, figlio che ignora TERM, cancel e SIGKILL.
Regressioni: Swift **131/131**, PKCS#11 **40/40**, PAdES Debug/Release **61/61**;
build di tutti i prodotti Swift Debug/Release riuscite.
Log: `.build/reliability/evidence/beta-unit2-*.log`.

**NON ANCORA ATTIVATO a questo checkpoint:** instradamento della GUI/CLI verso
il worker. L'esistenza dell'infrastruttura non chiude SG-06; il processo GUI usa
ancora il percorso precedente finché l'unità 3 non viene completata e provata.
Cancellazione del trasporto non equivale ancora alla policy di cancellazione
prima/dopo il commit del job. Multiprocesso e packaging portabile restano pianificati.

## Unità 3 — Flussi attivi, stati e cancellazione

**IMPLEMENTATO:** GUI e CLI non costruiscono più `PKCS11Module`. Discovery,
lettura DER e operazioni private passano dal worker. Il parent crea gli attributi
CAdES, verifica la firma RSA col DER approvato, costruisce/verifica CMS e conserva
l'atomic commit. Il worker non riceve documenti o destinazione. Il metodo Core
in-process precedente resta disponibile per test/compatibilità: non è la via dei
client GUI/CLI e non acquisisce magicamente l'isolamento.

`SigningOperation` è distinto da `SigningJob`: stato e cancellazione protetti da
lock, callback fuori dal lock e stati terminali senza transizioni tardive. Prima
il job può essere annullato senza autenticazione; dopo la risposta verificata
può essere annullata la pubblicazione. La breve barriera prima del rename rende
non più accettabile la cancellazione quando il commit comincia, senza mantenere
un lock durante chiamate vendor, verifica o fsync. Un'interruzione dopo l'invio
di una richiesta privata e prima di una firma verificabile è conservativamente
`outcomeUncertain`, senza output pubblicato dal job e senza retry. Gli stati
rappresentano fasi del client, non telemetria precisa interna a ogni C_Login/C_Sign.

GUI: pulsante Annulla per discovery/firma, stato leggibile e nessun risultato
pubblico tardivo dopo cancel. Chiusura della vista richiede cancel. CLI: SIGINT
cooperativo durante le chiamate worker; approvazione/PIN interattivi mantengono
la gestione terminale precedente. Se il parent muore, il worker rileva il cambio
di parent e termina senza tentare di interrompere una chiamata vendor con Finalize.

PAdES usa il supervisore comune: deadline/cancel/TERM/KILL e diagnostica scartata.
Il helper nativo conserva SG-03/14 e il proprio commit; un file presente dopo
interruzione rimane incerto e preservato. Un successo verificato già pubblicato
prevale su una cancellazione tardiva. Il parent non può impedire retroattivamente
il commit del helper. Il watchdog di parent death introdotto qui riguarda il
worker Swift: l'equivalente nativo e il coordinamento vanno consolidati nell'unità 4.

OpenSSL CAdES è ora supervisionato con deadline 30 s per livello e cancellazione,
senza file diagnostici o log vendor; verificatore GUI con Annulla. I limiti del
filesystem e chiamate kernel non interrompibili non vengono dichiarati risolti
con un timeout di processo. La rimozione fisica del token e la sua eventuale
operazione già eseguita restano fatti da collaudare manualmente.

**TESTATO:** sette nuovi test di job/stato/main queue/CLI parent death e due nuovi
casi PAdES di cancel pre-avvio/post-commit. Swift **140/140**; PKCS#11 **40/40**,
PAdES Debug/Release **61/61**; TSAN PKCS#11 **40/40**. Build di tutti i prodotti
Swift Debug/Release riuscite. Log `.build/reliability/evidence/beta-unit3-*.log`.
Il test positivo usa un vero CMS software; quello negativo conta un solo Login e
Sign nel figlio, senza output finale e con snapshot eliminato. Non è un test della
GUI manuale né un collaudo del middleware installato.
ASAN Swift completo: **140/140**, nessuna segnalazione nel runner; leak detection
disabilitata (`ASAN_OPTIONS=detect_leaks=0`). I canali diagnostici dei figli sono
intenzionalmente scartati; i casi positivi richiedono risposta/uscita valide.

## Unità 4 — Lease cooperativa tra processi

**IMPLEMENTATO e TESTATO:** `CProcessCoordination` condiviso da worker Swift e
helper PAdES. Identità provider tramite device/inode del percorso canonico
(anche alias hardlink), lock provider condiviso + slot esclusivo; discovery
esclusiva sul provider. Ordine dei lock fisso, attesa monotona limitata a 10 s
(default, massimo 30 s), errore «dispositivo occupato» prima di Initialize/Login.
Lease posseduta dal figlio fino al teardown: uccidere il parent non libera il
lock prima che il figlio sia morto. Crash/exit rilasciano i descriptor nel kernel.
Directory per utente 0700 e file vuoti 0600, senza ACL estese, no symlink; i file
lock non vengono rimossi per evitare di sostituire inode ancora in uso.

Il watchdog nativo comune ora copre anche PAdES e sostituisce quello Swift:
controllo del parent ogni 250 ms, exit senza Finalize concorrente al vendor.
Cancellare un'attesa termina il worker; nessun nuovo tentativo PIN. Un busy noto
prima di Initialize è un fallimento ordinario, non una firma di esito incerto.

Sei nuovi test Swift verificano esclusione multiprocesso, slot distinti,
alias, discovery, crash del proprietario, cancellazione e nessun Login quando
occupato. Due nuovi casi nativi provano il helper v3 completo con chiave RSA e
certificato sintetici, PDF verificato e un solo Login/Sign; con lease occupata
il helper non inizializza il provider e non pubblica output.

**TESTATO:** Swift **146/146**, PKCS#11 **40/40**, PAdES Debug e Release **63/63**
ciascuna; build di tutti i prodotti Swift Debug/Release riuscite. ASAN Swift
**146/146** e PAdES **63/63**, leak detection disabilitata; TSAN Swift mirato a
coordinamento/job **13/13**, senza segnalazioni nei runner. Log locali:
`.build/reliability/evidence/beta-unit4-*.log`.

**LIMITI:** protocollo cooperativo per utente e stesso provider/inode + slot.
Richiede slot ID stabili fra processi; non identifica universalmente due slot
logici della stessa carta o moduli vendor differenti dello stesso dispositivo.
Non coordina applicazioni terze né la vecchia API Core in-process. Aggiornamenti
in-place del modulo, rimozione amministrativa della directory temporanea e codice
ostile nello stesso account non sono risolti da flock. I lock vuoti persistono;
non contengono percorsi, documenti, identificativi certificati o credenziali.
Nessuna verifica hardware o prova con middleware installato è stata eseguita.

## Unità 5 — Packaging locale autonomo

**IMPLEMENTATO e TESTATO:** `scripts/build-beta-native.py` ricompila offline
OpenSSL 3.5.4, FreeType 2.13.3 e PoDoFo 1.1.2 dai tre archivi già presenti,
verificati con SHA-256 fissato nella ricetta. Nuovo albero esclusivo
`.build/beta-native-v1`; nessuna modifica a `.build/native-prefix` o alle Alpha.
Nessun download/installazione globale. Toolchain Apple e CMake locale già presente.
Le ricerche Homebrew/registri CMake e codec opzionali esterni sono disabilitate.
Zlib/libxml2 sono di sistema, FreeType/OpenSSL statici, PoDoFo dylib incorporata.

OpenSSL viene compilato da percorso sorgente relativo, con prefix logico usato
solo in DESTDIR: nessuna installazione in `/signum-native`. La ricetta beta usa
`no-shared no-tests no-module no-engine`: provider default incorporato,
configurazione `/etc/ssl`, nessun engine/provider dinamico OpenSSL richiesto.
Questo è distinto dai moduli **PKCS#11** vendor, che rimangono caricabili nei figli.
Non cambia RSA/SHA-256/CMS utilizzato da Signum; gli end-to-end software PAdES con
questa precisa build passano. Engine OpenSSL e configurazioni software diverse
non sono stati validati. Non è una build FIPS.

`scripts/build-beta-app.py` compila tutti i prodotti Swift e il helper nativo in
scratch separati Debug/Release, con file/debug prefix map. Copia GUI, CLI e worker,
calcola la chiusura delle dylib, accetta solo librerie di sistema o del prefisso
beta, incorpora PoDoFo in Frameworks e riscrive i riferimenti con `@loader_path`.
Rimuove rpath locali e simboli debug; rifiuta riferimenti al checkout, directory
Developer utente e Homebrew anche nelle stringhe binarie, non soltanto in otool.
Firma ad hoc nell'ordine dylib → helper/CLI → eseguibile → app, poi verifica
`codesign --verify --deep --strict`. Manifest sigillato con versioni/hash sorgenti,
commit del codice, configurazione e hash del codice annidato; l'integrità del main
è protetta dalla firma del bundle, evitando un hash autoreferenziale.

La destinazione deve essere nuova (anche symlink pendenti rifiutati); staging in
una directory appena creata, pubblicazione `renamex_np(RENAME_EXCL)`, cleanup
staging anche su errore. I precedenti bundle non vengono cancellati o sostituiti.
Identifier distinto `io.github.tiertoast.Signum.BetaFoundation`. Info.plist locale
0.3.3/build 1, min OS derivato dal massimo dei minos Mach-O: **14.0** in questa
build, arm64. Nessuna promessa di funzionamento su macOS 14 basata sul solo minos.
Il manifesto non contiene percorsi assoluti di sviluppo. La ricetta riproduce
il procedimento; timestamp e firme non implicano identità bit per bit.

**TESTATO:** sette test Python di parser Mach-O, bounds dei percorsi caricati,
evidenza loader obbligatoria, rejection di percorsi compilati e di destinazioni
esistenti/symlink, commit esclusivo che preserva una destinazione concorrente.
Swift **146/146**, PKCS#11 **40/40** dopo l'incremento. Build Swift e PAdES
Debug/Release riuscite contro il prefisso beta; PAdES **63/63** per configurazione.
Sia il bundle sia una copia rilocata superano avvio helper senza richiesta,
discovery CLI→worker con mock, audit DYLD (PoDoFo caricata dentro il bundle),
e suite PAdES **63/63** usando il helper incorporato, incluso v3 con firma RSA
software verificata. Nessun modulo installato viene caricato in queste prove.

Bundle finali di questa verifica:
- `.build/beta-bundles/debug-v3/Signum.app`
- `.build/beta-bundles/release-v3/Signum.app`

I loro manifesti indicano `c4c4f6f`, commit del codice applicativo già consolidato;
la ricetta di packaging viene committata nell'unità 5. Log locali ignorati
`.build/reliability/evidence/beta-unit5-*.log`, incluse build native, suite,
audit/firma e test sui bundle rilocati. I precedenti candidati v1/v2 sono build
di sviluppo superate, non la consegna da collaudare.

**NON TESTATO / APERTO:** avvio interattivo GUI, middleware reale nel nuovo
lifetime per richiesta, prestazioni/timeout con DigitalDNA, macOS minimo e Mac
privo di strumenti di sviluppo. CAdES usa ancora `/usr/bin/openssl` di sistema per
la verifica; il mock positivo CAdES è coperto dalla suite Swift, non da un click
GUI nel bundle. OpenSC/Bit4id e i relativi driver/servizi restano installazioni
utente, non inclusi o ispezionati qui. Nessuna modifica alle integrazioni esterne.

Nessuna credenziale Apple Developer è stata usata: firma **ad hoc**, senza
Developer ID, hardened runtime, notarizzazione, Gatekeeper o DMG. Prima di una
release serviranno identità/provisioning e una policy di library validation
limitata ai figli che caricano middleware terzi. I notices disponibili sono
incorporati; la verifica completa degli obblighi di distribuzione/licenze e
delle sorgenti da rendere disponibili resta un gate separato. Non distribuire
questi candidati come Beta pubblica già qualificata.

## Chiusura: commit, comandi e ripresa

Commit locali, tutti sopra `origin/main` verificato `96facb9`:

| Unità | Commit | Contenuto |
|---|---|---|
| 1 | `0729819` | Analisi prima del codice |
| 2 | `d1fc3a2` | Worker isolato, IPC limitato, supervisore e mock |
| 3 | `8c133c1` | GUI/CLI attive, stati/cancel, OpenSSL supervisionato |
| 4 | `c4c4f6f` | Lease interprocesso e watchdog comune |
| 5 | `b88fd7a` | Ricette native/bundle e test packaging |

Un successivo commit di sola documentazione registra questa consegna.
`main` locale resta `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70` e il branch
`codex/reliability-foundation` resta `e328fbf1a2b4ed05018f2346c2aa48ccebd569d4`.
La review originale non tracciata resta tale, SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
Nessun push, merge, tag, release o CI remoto; nessun accesso ad altri repository.

### Comandi ripetibili, esclusivamente sintetici

Dal checkout corrente, con Xcode e il CMake locale già presenti:

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
swift test --scratch-path .build/reliability
scripts/test-pkcs11-local.sh
scripts/test-pades-local.sh
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build -c debug --scratch-path .build/reliability
swift build -c release --scratch-path .build/reliability
```

Per ricostruire anche le dipendenze, scegliere directory **nuove**. Questi nomi
non sono stati usati dalla verifica sopra; se già esistono, usare altri nomi:

```sh
/usr/bin/python3 scripts/build-beta-native.py --output .build/beta-native-rebuild
/usr/bin/python3 scripts/build-beta-app.py --configuration debug --native-prefix .build/beta-native-rebuild/prefix --output .build/beta-bundles/rebuild-debug/Signum.app
/usr/bin/python3 scripts/build-beta-app.py --configuration release --native-prefix .build/beta-native-rebuild/prefix --output .build/beta-bundles/rebuild-release/Signum.app
```

Ogni invocazione del packager esegue PAdES **63** casi contro le nuove dipendenze,
audit completo, firma/verifica, discovery mock e prove PAdES anche dopo rilocazione.
Non esegue la GUI né legge il middleware installato. Per il candidato già pronto:

```sh
/usr/bin/codesign --verify --deep --strict --verbose=2 .build/beta-bundles/release-v3/Signum.app
/usr/bin/plutil -p .build/beta-bundles/release-v3/Signum.app/Contents/Info.plist
```

Sanitizer effettivamente eseguiti durante gli incrementi (prefissi della baseline,
non le dipendenze beta ricompilate con sanitizer). Per ripeterli:

```sh
ASAN_OPTIONS=detect_leaks=0 swift test --scratch-path .build/reliability-asan --sanitize address
swift test --scratch-path .build/beta-tsan --sanitize thread --filter 'ProcessCoordinationTests|SigningOperationTests'
.build/native-tools/cmake/data/bin/cmake --build .build/signum-pades-hardening-asan --parallel 6
ASAN_OPTIONS=detect_leaks=0 .build/native-tools/cmake/data/bin/ctest --test-dir .build/signum-pades-hardening-asan --output-on-failure --verbose
.build/native-tools/cmake/data/bin/cmake --build .build/pkcs11-tests-tsan --parallel 6
.build/native-tools/cmake/data/bin/ctest --test-dir .build/pkcs11-tests-tsan --output-on-failure --verbose
```

I due ultimi build tree sono già configurati nel workspace: C/C++
`-fsanitize=address -g -O1` o `-fsanitize=thread -g -O1` e relativo linker sanitizer.
Le librerie di terze parti non sono interamente strumentate. Nessuna deduzione di
assenza universale di race/leak dalla sola riuscita dei runner.

### Collaudo hardware futuro — istruzioni, NON ESEGUITO

Questa sessione si ferma prima dell'hardware. Il prossimo passo è un collaudo
manuale esplicitamente avviato dall'utente sul candidato **release-v3**, preservando
l'Alpha. Non usarlo ancora come sostituzione stabile o in integrazioni esterne.

1. Aprire quella precisa copia di `Signum.app`; verificare certificato e documento
   sintetico in anteprima. Il nuovo identifier evita di sovrascrivere le preferenze
   dell'Alpha, ma la configurazione middleware deve essere controllata manualmente.
2. Con DigitalDNA/DS3, provare un CAdES e un PAdES su documenti sintetici e destinazioni
   nuove. Inserire il proprio PIN solo nel campo previsto, mai in comandi/log/report.
   Verificare separatamente con InfoCamere e confrontare contenuto approvato/output.
3. Provare cancellazione prima dell'invio; poi una singola operazione manuale durante
   attesa. In caso di timeout/esito incerto non ripetere automaticamente il PIN;
   controllare eventuale file preservato e stato del dispositivo prima di proseguire.
4. Collaudare due finestre/client Signum sullo stesso slot, distinguendo discovery
   esclusiva e token differenti. I client terzi non partecipano alla lease.
   Rimozione token e prompt vendor richiedono cautela e osservazione manuale;
   nessuno script di questa consegna li esegue.
5. Annotare solo versione OS/middleware, tempi/fase, formato e risultato, senza PIN,
   documenti personali o log vendor grezzi. Rilevare eventuali incompatibilità del
   nuovo Initialize/Finalize per richiesta e adeguare timeout dopo evidenza reale.

**Rischi residui prioritari:** compatibilità e costo del lifecycle per richiesta;
slot ID non stabili/alias fisici, middleware con servizi condivisi; cancellazione
PAdES dopo un possibile commit; chiamate kernel non interrompibili, pur con
numero di worker limitato; segreti in memoria Swift/vendor non azzerabili con
certezza; niente sandbox contro codice vendor ostile. SG-06 copre i flussi attivi
GUI/CLI e il helper supervisionato, non rende isolata l'API legacy in-process.

**Ripresa consigliata:** raccogliere il collaudo manuale senza ulteriori cambi
crittografici, poi matrice macOS/driver e packaging su Mac pulito; successivamente
Developer ID/notarizzazione, library validation e adempimenti di distribuzione.
Non iniziare Trust Engine o nuove integrazioni prima di questi riscontri.
