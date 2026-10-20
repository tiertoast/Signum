# SIGNUM 0.4 — Hardening 14-C.1

Digital signatures. Simply native.

Rapporto aggiornato il **20 ottobre 2026**. Esito complessivo: **validazione parziale, gate ASAN nativo aperto**. I timestamp dei log rimangono quelli originali del sistema che li ha prodotti.

## Baseline e conservazione

Workspace autorizzata `/Users/andreaoregioni/Developer/Signum-Reliability`, repository `tiertoast/Signum`. Branch locale `codex/signum-0.4-hardening-b14c1` creato dall'HEAD completo della 14-B **`3b5eeb17ef9605592321d71aa5b5aa62bad9fe8e`**, incluso il rapporto dopo il codice `276585c`. Nessuna modifica tracciata iniziale. Sono rimasti non tracciati e identici per SHA-256 i quattro rapporti originari: review 0.3.3, code quality 0.4, invariants 0.4 e diagnosi performance PAdES.

Verificati ref, worktree, documenti richiesti, script, bundle precedenti e prerequisiti locali. Il checkout main è stato solo identificato dai metadati Git. Main `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70`, B13 `c45bb006b8ab00c5f80bcb03a25232abf002e2e6`, 14-A `8869330` e 14-B `3b5eeb1` preservati. Nessun altro checkout locale aperto o compilato; nessun accesso a HalleyMac, PR #3, rete Git, Actions, hardware, middleware installati, PIN o documenti personali.

Prodotto invariato **0.4.0 / Build 13**, arm64, deployment target macOS 13, package tools 5.9/language mode 5. Nessun avanzamento a Build 14, installazione, distribuzione, push, merge, tag o release. Il perimetro comprende soltanto CQ-08/12/14; CQ-10 e CQ-11 non affrontati.

## Metodo e riproduzione iniziale

La build strict Debug iniziale è un `git archive` pulito di 3b5eeb1, con scratch nuovo e `-Xswiftc -strict-concurrency=complete`, prima delle modifiche. Exit 0, **9 posizioni sorgente**: DocumentAcquisition 7, SupervisedProcess 27, BatchCAdESSession 65, PAdESRenderCoordinator 50, UnifiedVerificationPane 199, CAdESVerificationPane 5/144/170 e main 744. Il log conserva tutte le 12 occorrenze diagnostiche primarie, inclusi duplicati di compilazione e suggerimento preconcurrency; non sono 12 difetti distinti. Nessun uso di quel suggerimento per sopprimere warning.

L'ispezione segue il percorso GUI: main → pane PAdES identificata dalla generazione del workspace → PDFView/overlay corrente; Verifica → workspace indipendente → sheet statica. Le annotazioni grafiche legacy restano compilate, ma non sono scambiate per l'overlay attivo. La dipendenza tra `verifiedBytes` e `close` sullo stesso NSLock è confermata sul codice iniziale; lo script storico copia solo app/helper facoltativo e non include il worker. Non è stato eseguito lo script precedente, che avrebbe modificato `build/Signum.app`.

Milestone separate: analisi, invarianti, patch locale, test mirati e commit; controlli finali su esportazione sorgente pulita. Il runner rimane **scripts/test-local.py**. Le invocazioni supplementari strict/packaging riusano il watchdog `Run.command` dello stesso runner; `final_actions.py` nelle evidenze contiene soltanto le azioni fissate per questa milestone. Nessun secondo runner generico nel prodotto.

## CQ-08 — invalidazione e preparazione

`DocumentSnapshot` separa il lock breve del lifecycle da quello che serializza lseek/read sul descriptor. Ogni lettore acquisisce una lease sotto il lock del lifecycle, poi esegue I/O, confronto dei byte e SHA-256 fuori da quel lock. Un close marca subito lo snapshot chiuso e rifiuta nuove letture; i lettori già presenti mantengono vivi descriptor e directory, osservano chiusura/cancellazione ai checkpoint e rilasciano la lease. Soltanto chi reclama l'ultima lease chiusa può eliminare le risorse. Nessun doppio close, seek concorrente, unlink prematuro o riapertura dell'originale.

I chiamanti MainActor del coordinatore usano `retire`: anche senza lettori, unlink e close sono accodati fuori main con ownership forte fino al termine. Il close sincrono delle API esistenti conserva la pulizia immediata quando non ci sono lettori; non aspetta più un lettore attivo. Il deinit è un fallback idempotente. La pulizia rimane best effort e legata all'identità: se il filesystem rifiuta unlink, il file privato resta chiuso/inutilizzabile e recuperabile dalla recovery esistente alla prossima acquisizione. Il test con flag immutable riproduce e recupera proprio questo percorso; nessuna promessa di secure erasure.

`PDFPreviewPreparation` rilegge/verifica lo snapshot e prepara i dati con un CGPDFDocument posseduto dalla singola invocazione off-main. Restituisce solo Data e contatori; rifiuta il risultato se lo snapshot è stato ritirato durante la preparazione. La sheet Verifica rasterizza una sola pagina alla volta con un proprio documento PDFKit esclusivo del worker e restituisce un PNG bounded a 1000×1000; il body SwiftUI non genera più thumbnail PDFKit. La scelta PNG/JPEG esegue lettura, limiti e decode ImageIO nel worker; in attesa dell'immagine l'appearance non diventa approvabile. Errori e cancellazione non pubblicano il risultato precedente.

Le Task SwiftUI `.task(id:)` possiedono i worker attesi e propagano cancellazione; documento/pagina/immagine nuovi revocano le richieste precedenti. Il render coordinator trattiene la callback sul MainActor e trasferisce soltanto configurazione, DER, artwork precedente e token di cancellazione. Conservati renderID, generazioni, un render attivo/un pending, riuso del contenuto durante orientamento e nessuna rigenerazione/rasterizzazione dell'artwork nel drag.

**Confine intenzionale:** il PDFDocument utilizzato dal PDFView viene ancora costruito e usato sul MainActor, dopo la preparazione dei dati. Non è stato dichiarato Sendable né passato tra executor. Non è disponibile un contratto Apple verificato che autorizzi la condivisione arbitraria di quel grafo PDFKit con il viewer. Per CoreGraphics, Apple raccomanda un documento separato per thread: [CGPDFDocument initializer](https://developer.apple.com/documentation/coregraphics/cgpdfdocument/init(_:)-gbq6). Questo è il modello usato dai nuovi worker. Restano il costo UI di installazione/layout/zoom e l'inizializzazione lazy PDFKit: le misure sotto riguardano soltanto le fixture e le parti modificate, non garantiscono una latenza massima per ogni PDF.

Tredici nuovi XCTest: 5 snapshot retirement e 8 preparazione preview. Coprono lettore bloccato e lettori accodati, close ripetuto, remove/reset immediati, cancellazione e integrità mantenuta, cleanup fallito/recovery, PDF ordinario/80.000 operazioni vettoriali/1001 pagine, raster bounded, input corrotto, immagine 2048² e decode error, due/tre richieste, parser non cooperativo terminato dopo retirement, chiusura/cancellazione e risultato obsoleto. Le barriere hanno deadline; nessuna assertion di velocità dipende dalla macchina. Le regressioni già presenti coprono configurazione/orientamento, viewport/drag/resize, job approvato e firma/verifica finale. Primo gruppo mirato finale 47/47; gruppo incrociato 36/36 dopo esplicitazione dell'helper di test.

## CQ-12 — un solo packager

`scripts/build-app.sh` è ritirato: termina sempre con exit 2 e indica il comando ufficiale prima di costruire o modificare file, anche se invocato con vecchi argomenti o --help. `scripts/build-beta-app.py` è la sola implementazione supportata. Prima dello staging controlla che app, CLI, worker e helper siano presenti ed eseguibili; la risoluzione delle dipendenze rifiuta file mancanti, percorsi non supportati e riferimenti esterni al prefix privato.

Conservati staging privato, pubblicazione esclusiva in percorso nuovo, dipendenze @loader_path, hash annidati, manifest, arm64, minimo Mach-O 13.0, codesign ad hoc/deep/strict e smoke prima/dopo rilocazione. CLI inclusa come da contratto. Tre nuovi test Python, 17/17 complessivi: vecchio script senza effetti; componenti mancanti/non eseguibili; dipendenza assente/esterna senza fallback. Ulteriori quattro controlli su copie dei bundle nuovi rimuovono worker o PoDoFo: startup e codesign rifiutano entrambe le configurazioni. Gli originali restano integri.

Bundle diagnostici nuovi in `work/hardening14c1/bundles/Signum-14C1-checked-{debug,release}.app` nella workspace della chat, prodotti dal commit pulito **`5919caacb74da0afd3625b7c0c7fcdf1d77e5873`**. Nessun bundle storico sovrascritto, nessun avvio della GUI o discovery di provider installati. I test impacchettati usano esclusivamente i componenti di questi bundle e provider software sintetici.

## CQ-14 — ownership e isolamento

Valori realmente immutabili: DocumentAcquisitionFailure.Kind e risultati/livelli CAdES ora Sendable; nessun cambiamento al parser o alla crittografia CMS. IsolatedPKCS11Client passa da unchecked a conformance verificata: memorizza soltanto URL/UInt immutabili e crea trasporti per chiamata. PKCS11Module perde la conformance Sendable generale: batchSession/closedInWorker appartengono al worker singolo, non sono resi condivisibili dal lock nativo del provider.

Tutti gli unchecked produttivi sono stati esaminati; il numero non è una metrica di correttezza. I due nuovi proprietari ristretti hanno protezioni reali, non sostituiscono lock con annotazioni.

| Tipo | Stato e protezione | Owner, accessi e rilascio |
| --- | --- | --- |
| DocumentSnapshot | byte/identità/descriptor immutabili; closed/readers/cleanupClaimed sotto lock; I/O sotto readLock | lettori trattengono self/lease; unico cleanup dopo ultima lease; retire UI fuori main; deinit idempotente |
| SigningOperation | phase/cancelled/publishing sotto NSLock; id/callback immutabili | callback ora @Sendable, fuori lock, rientrabile; nessuna risorsa vendor nel deinit |
| BatchCAdESSession | connection/factory/began sotto ioLock; stopped/reusable/cleanupFailed sotto state | nessun state lock mentre si attende ioLock; factory di test impostabile solo prima del primo uso; stop conserva esito incerto |
| ConnectionOwner | value protetto dallo stesso ioLock usato dalla sessione | deinit trasferisce l'owner alla coda, non l'existential non protetto; finish/abort serializzati; owner trattenuto sino al ritiro |
| SupervisedProcess.Capacity | active privato sotto NSLock, static let owner | slot trattenuto fino al reaping, incluso quello differito; nessuna attesa/process callback sotto lock |
| PKCS11Module.RetiredContext | pointer immutabile, trasferimento esclusivo | ultimo context consegnato una volta a releaseQueue; nessun utilizzatore del modulo rimane; sg_close fuori main |
| FileDropResolution | values/received/completion sotto NSLock; completion @Sendable | finish una volta e callback fuori lock; callback tardive ignorate; collector trattenuto fino a callback/deadline |
| FileDropResolution.Cancellation | cancelled/result sotto NSLock | registra cancel prima dell'avvio, chiama finish fuori lock; nessuna risorsa vendor |

NSItemProvider rimane sul MainActor per registrazione dei loader e chiamate loadItem; solo URL/Data attraversano i callback nel collector protetto. Il workspace dichiara il loader MainActor, senza rendere AppKit Sendable. Il renderer non cattura più l'intera Request contenente la callback UI nel worker. Nessun @preconcurrency, nonisolated(unsafe), disabilitazione di warning o cambio di language mode introdotto.

Tre nuovi test di capacità/rilascio concorrente, launch fallito e terminal callback reentranti/esattamente una volta. Le osservazioni mutabili dei callback fixture ora usano un vero lock e riferimenti rilasciati esplicitamente, invece di variabili catturate modificabili. Mirati finali 26/26. Il filtro sanitizer del runner è ampliato a snapshot, render/overlay, processi e cancellazione; non è un nuovo runner. La futura migrazione Swift 6 resta separata: richiederà controllo anche dei consumatori raw/fixture, degli SDK e dei sistemi minimi, senza dedurla da una build strict in language mode 5.

## Correzioni e prove intermedie

Conservati i tentativi non verdi: iniziale errore di compilazione della closure non-escaping del nuovo snapshot; fixture PNG chiamata senza isolamento MainActor; macro XCTest che inferiva una closure throwing dentro concurrentPerform. Corrette le cause, ricompilato e ripetuto. Il primo gruppo incrociato ha evidenziato un'assertion storica che pretendeva unlink sincrono subito dopo remove: ora verifica prima revoca logica/stato e poi attende la pulizia fisica con deadline. Nello stesso tentativo due test richiedevano l'helper non esplicitato: sono errori di setup, non test verdi. La ripetizione intermedia usa l'helper sintetico precedente con sorgenti native immutate; il completo finale prepara invece i propri helper nuovi da zero. I log iniziali restano tali e non si usano vecchi binari dopo build fallita come prova del sorgente nuovo.

Il primo runner completo sul checkpoint 1058243 ha eseguito 425 casi, 424 passati e uno fallito: il test nativo del workspace cercava il PDFView mantenendo occupato il MainActor con RunLoop sincrono. La Task della preview non poteva completare durante quella verifica. Nessun viewer è stato sostituito: il test ora cede realmente l'executor, attende PDFView/document/pageCount con deadline di 5 s e conserva le assertion su snapshot, viewport e assenza di accesso all'originale. Riproduzione e ripetizione 5/5 workspace positive, commit f34ee60. Il run iniziale resta fallito, senza sanitizer eseguiti. Tutto il runner viene ripetuto da zero su f34ee60; anche packaging/strict sono rifatti in nuove directory, con bundle iniziali conservati. Il filtro sanitizer include ora questi workspace e richiede WindowServer anche se invocato come gruppo separato.

Il checkpoint successivo f34ee60 ha passato Swift 425/425 e Python 17/17, ma è stato ritirato all'avvio ASAN (exit -15, non run completo verde) perché una nuova regressione visiva ha dimostrato che il primo raster CoreGraphics ometteva le annotazioni. Il test confronta una vera annotazione blu serializzata con la thumbnail PDFKit precedente: prima zero pixel blu, dopo contenuto preservato. La correzione 4f86da3 usa thumbnail PDFKit in un unico scope sincrono off-main e autoreleasepool: documento, pagina e NSImage privati, nessuna view/delegate/custom subclass, nessuna condivisione o trasferimento del grafo PDFKit. Esce solo Data PNG bounded a 1000 px. La [guida Apple sui thread](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/ThreadSafetySummary/ThreadSafetySummary.html) consente creazione/disegno di un NSImage privato su thread secondario; l'ownership esclusiva evita la condivisione mutabile. Il documento del PDFView resta distinto sul MainActor. Questa correzione locale preserva l'aspetto precedente senza introdurre un parser/rendering di annotazioni alternativo. I 13 test preview/workspace passano dopo la correzione; il completo finale riparte su 4f86da3 con 426 casi distinti, nuovi bundle e scratch. I due checkpoint intermedi e tutti i loro log sono conservati.

Audit anche dei quattro unchecked nelle fixture: `DeferredDrop` protegge con NSLock il completion handler NSItemProvider registrato e lo invoca dopo averlo copiato fuori lock; il test controlla esplicitamente la consegna tardiva. `ControlledDrop` protegge callback @Sendable e deadline con NSLock; count è immutabile e l'aspettativa XCTest è configurata prima dell'uso concorrente. `MockModule` ha soltanto campi Swift let (path, handle, puntatori a funzione); i controlli nativi di certificati/statistiche/barriere usano il mutex/condition pthread del mock. Le closure trattengono la fixture durante le chiamate; deinit chiude l'handle di controllo e rimuove soltanto la propria directory. Rimane il teardown checked dei due test raw sincroni introdotto in 14-B, prima di rilasciare l'handle. `FixtureLocked` serializza tutte le osservazioni mutabili; gli usi di questa milestone sono array di valori e riferimenti a SigningOperation già protetti/Sendable, con riferimenti opzionali azzerati per evitare cicli nei callback. Nessun contenitore generico di fixture è esportato come API produttiva.

Il checkpoint 4f86da3 ha poi passato Swift 426/426 e Python 17/17. Il log pulito della compilazione test ha evidenziato un warning introdotto dal default del predicato della fixture workspace (lettura di subviews da closure di tipo non isolato), oltre a un risultato inutilizzato preesistente in ProviderSelectionTests. Il callback ready/verify è ora esplicitamente MainActor e il risultato viene scartato esplicitamente; nessuna modifica produttiva. Mirati 15/15 senza warning. Il run precedente è conservato come interrotto intenzionalmente durante ASAN (non completo verde). Tutti i controlli finali vengono ripetuti sull'esportazione pulita 5919caa, con prodotto identico a 4f86da3 e fixture corrette, senza usare quei conteggi intermedi come prova finale.

## Misure circoscritte alla reattività

Campioni diagnostici Debug della suite Swift finale, framework già utilizzati da altre fixture; nessuna soglia di successo basata sui tempi. Le durate delle API async includono scheduling, non isolano il solo costo CPU del parser. La preparazione CoreGraphics enumera pagine e box; non forza il rendering di tutti gli operatori vettoriali o sostituisce il parsing lazy del viewer.

| Misura sintetica | Risultato osservato |
| --- | --- |
| Snapshot + validazione struttura/pagine PDF ordinario, 1 pagina / 2.127 byte | 0,213 ms fuori main |
| Snapshot + validazione struttura/pagine PDF complesso, 4 pagine / 80.000 rettangoli / 370.499 byte | 0,332 ms fuori main |
| Snapshot + validazione struttura/pagine PDF 1001 pagine / 368.323 byte | 3,266 ms fuori main |
| Costruzione PDFDocument del viewer sul MainActor, stesse fixture | 0,087 / 0,110 / 0,250 ms, framework caldo |
| Load/validazione ImageIO appearance 2048² | 0,320 ms; non equivale al costo finale di disegno dell'artwork |
| Thumbnail verifica, pagina vettoriale, incluso encode e attesa worker | 6,612 ms fuori main |
| Close logico con lettore trattenuto dalla barriera | 0,0005 ms nel campione; verifica logica avviene prima di rilasciare il lettore |
| Cache overlay, 120 spostamenti con immagini 0/1024/2800 px | 0 rasterizzazioni durante drag in tutti i tre scenari |

Un precedente campione diagnostico della prima costruzione PDFKit aveva circa **36 ms**: i numeri caldi non lo cancellano e non dimostrano un limite massimo del lavoro UI. Non è stato effettuato un benchmark prima/dopo dell'intera app. Le fixture non rappresentano ogni contenuto complesso, disco lento o sistema macOS minimo. I test con barriere dimostrano soprattutto l'assenza della dipendenza sincrona tra invalidazione UI e rilettura in corso, senza dedurre fps dai microsecondi.

Compromessi: la preview statica riparsa il documento a ogni pagina per mantenere il grafo PDFKit esclusivo del worker; TIFF/PNG sono intermedi transitori. Non si trasferiscono oggetti UI e non si introduce una cache globale. RSS totale e latenza di tutti i PDF reali non profilati; nessuna conclusione di ottimizzazione generale della memoria, nessuna eliminazione di riletture/hash d'integrità o modifica del serializer CMS. CQ-10 resta alla 14-C.2.

## Verifiche finali effettive

Checkpoint di sorgenti/test/tooling: **5919caacb74da0afd3625b7c0c7fcdf1d77e5873**, esportazione pulita; confrontati byte per byte i file tracciati in Sources/Tests/Tools/scripts/Resources e Package.swift con il repository. Codice produttivo finale 4f86da3c0de1556513a7aa1fe2b761e8c36e733a. **16 nuovi XCTest distinti, 3 nuovi test Python, 0 nuovi casi nativi**; ripetizioni e diagnostica non sommati. Versione 0.4.0/Build 13.

| Controllo | Esito osservato | Durata comando | Log nell'allegato evidence |
| --- | --- | --- | --- |
| Swift completo senza filtro | 426/426; 0 failure/skip | 215,913 s (test 189,397 s) | final-run/swift.log |
| PKCS#11 Debug | 58/58 | 3,251 s | final-run/pkcs11-debug.log |
| PAdES Debug | 79/79 | 3,142 s | final-run/pades-debug.log |
| PAdES Release | 79/79 | 2,563 s | final-run/pades-release.log |
| Python packaging | 17/17 | 0,132 s | final-run/packaging.log |
| Swift ASAN mirato | 208/208; 0 failure/skip | 113,635 s (test 78,478 s) | final-run/swift-asan.log |
| Swift TSAN mirato | 208/208; 0 failure/skip; nessun warning TSAN | 303,335 s | final-run/swift-tsan.log |
| **PKCS#11 ASAN standard** | **FAIL, CTest exit 8, crash/report annidato; suite non completata nel runner** | **0,638 s** | **final-run/pkcs11-asan.log** |
| PAdES ASAN, run separato | 79/79 | 2,746 s | final-remaining-native/pades-asan.log |
| PKCS#11 TSAN, run separato | 58/58 | 5,666 s | final-remaining-native/pkcs11-tsan.log |
| PAdES TSAN supplementare | 79/79 | 25,055 s | checked-final-additional-checks/pades-tsan.log |
| Strict Debug pulita | 0 warning | 18,294 s | checked-final-additional-checks/strict-debug.log |
| Strict Release pulita | 0 warning | 29,953 s | checked-final-additional-checks/strict-release.log |
| Nuovo bundle Debug + integrazione | package passato; 10/10 contratti | 27,361 + 1,014 s | checked-final-additional-checks/package-debug.log; packaged-debug.log |
| Nuovo bundle Release + integrazione | package passato; 10/10 contratti | 44,972 + 0,959 s | checked-final-additional-checks/package-release.log; packaged-release.log |
| Copie bundle incomplete | 4/4 rifiuti attesi | vedi log | checked-negative-bundles.log |

Le durate dei comandi nativi escludono configure/build, registrati separatamente nei JSON; i comandi Swift includono compilazione. Ambiente: arm64, macOS 27.2, Swift 6.4 con language mode 5, Apple Clang 21.0.0 (clang-2100.3.34.2), SDK 27, target macOS 13; prefix privato preesistente con PoDoFo 1.1.2/OpenSSL 3.5.4/FreeType 2.13.3, CMake e Poppler locali già presenti. ASAN usa detect_leaks=0. Strict prima: 9 posizioni / 12 occorrenze; dopo: 0 Debug e 0 Release da scratch. Anche la compilazione finale dei test Swift non contiene warning.

Il `results.json` del completo resta **failed**, con un comando finale fallito; non viene trasformato in passed aggregando i run supplementari. L'esecuzione fail-fast non ha avviato PAdES ASAN e PKCS#11 TSAN, poi completati separatamente sugli stessi sorgenti con il watchdog ufficiale. Non ci sono skip negli XCTest effettivamente eseguiti; i run precedenti interrotti restano incompleti, e l'ASAN nativo intermittente non è presentato come suite verde. `evidence/test-results.json`, `TEST_RESULTS.md`, manifest e `source-consistency.json` distinguono gli esiti.

I manifest Debug/Release riportano commit 5919caa, sourceTrackedDirty=false, 0.4.0/13, arm64 e minimo 13.0. Hash dei codici annidati ricalcolati e codesign --verify --deep --strict ripetuto. I bundle restano soltanto in scratch, non installati. Il codice dei runner supplementari e i comandi dei processi sono inclusi nelle evidenze; i rapporti storici e i bundle precedenti sono preservati.

## Gate nativo ASAN aperto

Il runner completo ufficiale sul checkpoint **5919caa** è **FAILED**, non verde: `pkcs11-asan`, CTest exit 8 dopo 0,638 s. Il processo stampa `AddressSanitizer:DEADLYSIGNAL` e `nested bug in the same thread`. Non è stato possibile ottenere un rapporto ASAN completo; il gate resta non soddisfatto. Nessuna modifica al C PKCS#11 o al relativo harness fra 14-B e questo checkpoint.

Diagnostica conservata in `evidence/native-asan-investigation/`:

- Ripetizioni con output su file, simbolizzazione disabilitata e CTest riproducono il crash. Anche il binario ASAN storico 14-B lo riproduce nell'ambiente attuale. Una serie finale di quattro invocazioni standard dello stesso binario restituisce **0, 1, 0, 1**: due completamenti da 58 casi e due crash. Le ripetizioni non sono casi nuovi né annullano il fallimento ufficiale.
- Con TTY, sotto LLDB e con `report_globals=2` sono osservati completamenti da 58 casi. Queste condizioni cambiano scheduling/layout/diagnostica e non dimostrano correttezza del percorso standard. La prova con `report_globals=0` è soltanto un controllo diagnostico che disabilita una classe di controlli: **esclusa dai risultati di validazione**.
- Un'esecuzione diagnostica con `handle_segv=0` ha lasciato uno stack OS: ASAN entra da `__asan_report_load8` in `complete_api`/`sg_open`, poi il reporting va in fault in `__asan::GetGlobalsForAddress`. Il file OS è stato consultato soltanto per il processo di test generato qui; l'estratto è `evidence/native-asan-os-crash.json`. Questa opzione non è un workaround adottato dal runner.
- Una copia strumentata, solo in scratch, verifica lo shadow prima della lettura: il primo byte e tutta la tabella da 552 byte di un modulo attualmente identificabile con `dladdr` risultano marcati `f9` (global redzone). Esce deliberatamente 88 prima del reporting annidato; nessun codice diagnostico è entrato nel repository o nei bundle.
- `loader-reproducer/repro-threads.cpp` carica/scarica copie del mock con `dlopen`/`dlclose` e 12 future, senza collegare o chiamare **alcun codice prodotto Signum**, né `sg_open`, firme o registry. Iterazione 0: tabella non poisoned; iterazione 1: tabella poisoned, exit 5. Il semplice loader sequenziale completa 100 iterazioni. Il controllo che disattiva soltanto il dead stripping delle globali ASAN riproduce ancora l'anomalia; non è stato applicato al progetto. Un modulo C ancora più piccolo, con una tabella e padding, **non riproduce** il problema in tre serie da 100 iterazioni: il riproduttore ridotto dipende ancora dal layout del mock.

Questi dati orientano verso l'interazione loader/runtime ASAN e lo scaricamento delle immagini strumentate, ma **non certificano la causa esatta** e non escludono automaticamente un errore di lifetime. La [documentazione Clang](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-fsanitize-address-destructor) descrive il ruolo dei distruttori ASAN nella deregistrazione delle globali durante `dlclose`; non costituisce una diagnosi di questo crash. Non è stato assunto come confermato alcun bug upstream trovato tramite ricerca.

Non adottati: rimozione di `dlclose`, pinning sistematico dei provider, esclusione del mock da ASAN, unpoison manuale, soppressioni, retry del test fino al verde, cambio toolchain/installazioni o modifiche al motore per accomodare il sanitizer. Debug 58/58 e TSAN 58/58 sono completati, ma non sostituiscono ASAN. PAdES ASAN 79/79 e PKCS#11 TSAN 58/58, saltati dal fail-fast del completo, sono stati eseguiti separatamente con lo stesso `Run` ufficiale e gli stessi sorgenti; PAdES TSAN 79/79 è un controllo supplementare. Tutti i log conservano il proprio esito originario.

**Condizione per chiudere il gate:** riprodurre e risolvere la causa su un ambiente/toolchain verificato, oppure una correzione locale dimostrata che mantenga i controlli ASAN e il contratto di unload; poi ripetere il percorso nativo standard tramite il runner ufficiale. Il checkpoint software è consegnato con questo residuo esplicito, senza dichiarare conclusa positivamente l'intera milestone.


## Regressioni incrociate e invarianti

Le famiglie del completo, rieseguite dopo le modifiche, mantengono questi collegamenti:

1. Snapshot → preview → cambio documento/formato → job approvato → firma e verifica: SigningWorkspace/DynamicFormatWorkspace, SigningJob, PAdESDefaultSigning e integrazioni dei bundle. Originale modificato dopo acquisizione non cambia i byte approvati.
2. Appearance/orientamento/drag/resize → firma → verifica: PAdESOrientation/Default/Placement/SignaturePlacementOverlay e confronti Poppler. Risorse e coordinate restano quelle del job; la preview di verifica conserva ora anche le annotazioni.
3. Remove/reset durante lettura: SnapshotRetirementTests verifica revoca e stato prima del rilascio della barriera, descriptor valido fino all'ultimo lettore e cleanup successivo.
4. Reset/cancel durante preflight: SigningReview/FileAcquisition/PAdESSourcePreflight conservano ownership, cancellazione del lavoro pubblico supervisionato e rifiuto delle generazioni obsolete.
5. Drop Verifica → picker/nuovo drop/reset/chiusura: VerificationDropLifecycle conserva deadline, una risoluzione, callback duplicate/tardive ignorate e niente pubblicazione vecchia.
6. Worker pubblico lento/cambio certificato: SigningReview, OneShotContext e PostLoginCertificate mantengono binding/ritiro ed esito distinto da indisponibilità.
7. Secure Batch PIN sintetico: suite batch/native/cleanup mantengono consenso, manifesto immutabile, USER/CONTEXT, teardown incerto e assenza di retry. Nessuna semantica PIN modificata.
8. Build pulita → bundle completo → dipendenze/manifest/hash → rilocazione/codesign: packager unico, controlli positivi e copie incomplete rifiutate.
9. PDF grande/cancel: LargeDocumentTests mantiene matrice fino a 100 MiB, rifiuti dimensionali e acquisizione cancellata con cleanup; le nuove barriere verificano cancel/remove/reset con lettura/preparazione in corso senza subordinare l'invalidazione MainActor all'I/O.

SG-01/14 e CQ-05: writer, readback, directory approvata e pubblicazione esclusiva invariati. SG-02 e CQ-02: lease, ritiro, esito incerto e nessun retry preservati. SG-03/04 e INV-01/02: stessi algoritmi, policy certificati/DER e binding prima/dopo autenticazione, verifica finale obbligatoria. SG-05: byte originali del CoW snapshot, configurazioni/approvazioni/job immutabili, generazioni correnti. SG-06: vendor nel worker/helper, contatore protetto e slot fino al reaping. Nessuna correzione 14-A/14-B rimossa.

## Registro finding e commit

| Finding | Stato | Test | Commit | Residuo |
| --- | --- | --- | --- | --- |
| CQ-08 | Implementato; gate complessivo ASAN nativo aperto | 13 nuovi XCTest, barriere, confronto annotazioni, workspace reale, completo e sanitizer | b312392, 4f86da3; fixture f34ee60/5919caa | PDFKit del viewer resta MainActor; costo freddo/layout non garantito su ogni PDF; cleanup filesystem best effort/recovery |
| CQ-12 | Corretto | 3 nuovi Python, 17 complessivi, bundle Debug/Release, 20 integrazioni e 4 fault su copie | 605bee0 | Packager locale arm64/ad hoc; niente distribuzione o notarizzazione |
| CQ-14 | Contratti espliciti e strict produttivo pulito; validazione complessiva condizionata | 3 nuovi XCTest, concorrenza/capacità/callback, strict Debug/Release da zero, sanitizer ampliati | 1058243, 5919caa | Linguaggio Swift 5; SDK/dipendenze non integralmente strumentati; runtime minimi da collaudare; anomalia ASAN nativa ancora da risolvere |

Sei commit di codice/test/tooling, più il commit di questo rapporto. Codice produttivo finale 4f86da3; checkpoint completo verificato di codice/test/tooling **5919caa**. HEAD finale comprensivo della documentazione in `evidence/git-final.json`, per evitare un hash auto-riferito nel documento versionato. Nessun rapporto originale aggiunto all'index. Progresso aggiornato appendendo una nuova voce, senza riscrivere lo storico.

## Residui e collaudi non eseguiti

Non eseguiti: hardware e middleware reali, PIN personali, GUI click-test umano completo/accessibilità, runtime macOS 13/14, Intel, notarizzazione/Developer ID, installazione/distribuzione e UBSAN. ASAN/TSAN Swift sono selezioni mirate (208 casi), non i 426 casi completi strumentati. Dipendenze native precompilate e framework Apple non sono integralmente strumentati; i mock compilati runtime Swift non equivalgono a middleware reali. ASAN con `detect_leaks=0` non prova assenza di memory leak. Nessun profilo RSS generale o promessa di assenza di blocchi del kernel.

Prima di distribuire: provare manualmente con fixture grandi il cambio ripetuto di documento e formato, immagine/orientamento durante render, zoom/drag/resize, rimozione/reset/cancel e chiusura finestra durante preparazione; verificare stamp visibile sia nel viewer di firma sia nella preview di verifica. Provare drop lento/picker e fine sessione con esito incerto, senza retry. Ripetere sui sistemi/hardware che si intende dichiarare supportati, con autorizzazione dedicata. CQ-10 (memoria) e CQ-11 (legacy) rimangono esplicitamente aperti per la 14-C.2.

## READY FOR HARDENING 14-C.2?

**CONDITIONAL.** CQ-08/12/14 sono implementati e i controlli Swift/strict/packaging pertinenti sono passati; la validazione complessiva della 14-C.1 **non è interamente verde**. Prima di considerarla chiusa e procedere alla 14-C.2 occorre risolvere il gate nativo PKCS#11 ASAN instabile e ripetere il percorso standard senza ridurre i controlli. Le prove diagnostiche suggeriscono l'interazione loader/runtime ma non dimostrano la causa definitiva. Non è stata introdotta una riscrittura del provider per ottenere un pass. **14-C.2 non avviata**. Nessun push, merge, tag, release, installazione o modifica della PR #3.
