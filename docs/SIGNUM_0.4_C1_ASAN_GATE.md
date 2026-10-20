# SIGNUM 0.4 — C1 Native ASAN Gate Resolution

Digital signatures. Simply native.

Rapporto del 20 ottobre 2026. La risoluzione riguarda il gate nativo della 14-C.1; la 14-C.2 non è stata avviata. Le decisioni finali sono riportate alla fine, separando il test standard dal difetto residuo del reporting del runtime.

## Baseline e conservazione

Repository autorizzato `/Users/andreaoregioni/Developer/Signum-Reliability`, `tiertoast/Signum`. Il branch `codex/signum-0.4-hardening-b14c1-asan-gate` nasce dall'HEAD completo **14b2e4d88c0d2d86bfe931c192a8e3230c821d88**, incluso il rapporto documentale dopo il checkpoint 5919caacb74da0afd3625b7c0c7fcdf1d77e5873. Inizialmente index e file tracciati puliti, quattro rapporti originali non tracciati. Nessun AGENTS.md applicabile trovato nei percorsi controllati.

Letti integralmente il rapporto 14-C.1 e LOCAL_TESTING; disponibili e conservati diagnosis.json, loader-reproducer, pkcs11-asan.log e results.json failed del completo precedente. Le cinque baseline standard nuove usano un'esportazione git archive pulita di 14b2e4d, non un binario storico. La build ASAN viene generata dal metodo native del runner ufficiale. Cinque processi CTest prefissati: **0, 8, 0, 0, 0**. Ogni completamento comprende i 58 casi originari; il tentativo exit 8 produce DEADLYSIGNAL/nested bug. Non è una ripetizione fino al primo verde. Il controllo non strumentato dello stesso archivio iniziale ricompila ed esegue i 58 casi originali: CTest exit 0, 58/58 (evidence/baseline-debug-control), senza il ponte o i nuovi contratti.

Il rapporto originario della 14-C.1, i quattro rapporti originali, i bundle e le evidenze precedenti restano invariati. Main/B13/14-A/14-B/14-C.1 preservati. Nessun altro checkout locale aperto, nessun accesso a HalleyMac, middleware installati, hardware, PIN o documenti personali. Nessun push, merge, tag, release, PR #3, Actions o installazione globale. Prodotto ancora **0.4.0 / Build 13 / arm64 / macOS minimo 13**, Swift language mode 5.

## Ambiente, flag e runtime

Host arm64, macOS 27.2 build 26B5112a; Apple Clang 21.0.0 (clang-2100.3.34.2), Swift 6.4, SDK 27.0. Runtime ASAN effettivo del compilatore Apple in `XcodeDefault.xctoolchain/usr/lib/clang/21/lib/darwin/libclang_rt.asan_osx_dynamic.dylib`; percorsi assoluti, hash e versioni sono in evidence/runtime-inventory.json. SHA-256 runtime 21: `574d685cb2c75ba6b3563395461d39bea8d6ddc2b921a5287773eb736f58f7b2`.

Flag standard del runner: C e C++ `-fsanitize=address -fno-omit-frame-pointer`, Debug `-g`; il modulo mock è Mach-O bundle. CTest verbose con deadline 60 s per target, watchdog ufficiale 120 s, output su file. Unica opzione ASAN standard: **detect_leaks=0**. Nessuna variabile ASAN/TSAN/DYLD ereditata inattesa. Non disabilitati globali, accessi, unload o controlli. Le dipendenze native preesistenti non sono installate né ricostruite globalmente.

Confronti diagnostici, distinti dal gate: il flag frontend -fregister-global-dtors-with-atexit non cambia il distruttore ASAN legacy emesso; il flag backend LLVM proposto -lower-global-dtors-via-cxa-atexit=true è rifiutato da Apple Clang 21, quindi non adottato. Il mock compilato con target minimo 13 presenta lo stesso shadow residuo. La toolchain CLT 17.0.0 già presente compila con il proprio SDK, ma il suo loader ASAN non produce output entro 40 s: tentativo terminato dal timeout, non controllo verde e non base di una diagnosi comparativa definitiva. Nessuna selezione globale della toolchain cambiata.

## Lifecycle e ipotesi

Nel harness originale Provider possiede un handle di controllo del mock. sg_open acquisisce l'handle del provider owner; i contesti si limitano a trattenere quell'owner. Le future sono attese prima di ritirare i contesti; la finalizzazione checked dell'ultimo contesto chiude soltanto il suo riferimento, mentre il controllo resta vivo. Il distruttore Provider esegue l'ultimo dlclose e rimuove soltanto la propria directory. Gli stati intenzionalmente quarantinati/restanti dopo teardown incerto conservano il contratto esistente. Non è stato cambiato quel codice.

Nel riproduttore loader, separato dal prodotto, l'handle principale resta aperto mentre dodici future effettuano coppie dlopen/dlclose; tutte le future vengono completate prima dell'ultimo close. La function table viene letta soltanto mentre esiste un handle. Le nuove verifiche post-close passano un indirizzo numerico all'API shadow ASAN e interrogano RTLD_NOLOAD; non dereferenziano dati o puntatori a funzione scaricati.

| Ipotesi | Evidenza e conclusione |
|---|---|
| A: lifetime errato del mock | Il nuovo controllo trova unload reale dopo ultimo handle, senza uso successivo della tabella; l'errore si riproduce anche con un modulo C di due righe. Non è necessaria una violazione di lifetime del mock per riprodurlo. |
| B: dlopen/dlclose concorrenti | Favoriscono il riuso degli indirizzi nel vecchio riproduttore; il nuovo controllo shadow riproduce il difetto già al primo unload seriale. La concorrenza non è necessaria alla mancata deregistrazione. |
| C: tabella statica invalida | Tabella viva valida e non poisoned alla prima apertura; ASAN applica la redzone del vecchio modulo alla collocazione della tabella nuova. Non cambiato storage o contenuto. |
| D: globali ASAN | **Confermato:** registrazione eseguita, deregistrazione assente; la redzone rimane nello shadow dopo unload verificato. |
| E: loader/runtime | **Confermato nell'ambiente osservato:** il distruttore ASAN è in __mod_term_func; il percorso __cxa_atexit esegue invece la stessa deregistrazione prima dell'unmap. |
| F: ownership scorretta dei puntatori nei test | Nessuna evidenza nel percorso che riproduce il falso errore: join e handle owner coprono tutte le letture; il minimo non contiene PKCS#11 o codice Signum. Non si deduce da questo l'assenza universale di bug nel prodotto. |
| G: reporting ASAN | Difetto distinto residuo: un accesso deliberatamente invalido dopo unload viene rilevato, ma il runtime può fallire nella formattazione del rapporto. Non è presentato come corretto da questa patch. |

## Causa confermata e riproduttori separati

1. **Target standard originale:** CTest intermittente con DEADLYSIGNAL/nested bug. Lo stack OS storico entra da complete_api/sg_open in __asan_report_load8, poi GetGlobalsForAddress durante il reporting.
2. **Mock originale senza prodotto:** una copia LLVM IR solo in scratch instrada le chiamate ASAN verso probe che delegano al runtime, annotando flag, thread e base immagine. Si osserva REGISTER 0→1, nessun UNREGISTER dopo dlclose; l'immagine successiva è caricata a una base diversa. Non modificato lo shim produttivo per la diagnostica.
3. **Geometria dello shadow:** nel campione probe/run-0.log, base vecchia 0x1021a4000. certificate_bytes è a offset 0xd000, corpo 65.536 byte e redzone 16.384 byte: redzone **[0x1021c1000, 0x1021c5000)**. La tabella nuova è a **0x1021c4100**, dentro quell'intervallo. LLVM IR e nm del mock documentano dimensioni/offset. La nuova registrazione avvelena le proprie code ma non elimina lo shadow rimasto dall'immagine precedente. Il falso load8 in complete_api è quindi spiegato dall'indirizzo riutilizzato, non da una tabella letta dopo il suo close. Calcolo verificato in address-causality.json.
4. **Minimo indipendente:** minimal_module.c contiene soltanto un array statico di otto byte e un getter. minimal_loader.cpp verifica corpo accessibile/redzone attiva, chiude l'unico handle, conferma RTLD_NOLOAD nullo e consulta lo shadow senza accedere alla memoria scaricata. Prima: **5,5,5**, redzone residua. Con la correzione di teardown: **0,0,0**, shadow ritirato. Non ci sono PKCS#11, worker, registry, firme o thread in questo minimo. Il vecchio minimo non riproduceva la tabella nuova poisoned perché cercava un sintomo dipendente dal layout; il nuovo controlla direttamente l'invariante violato al primo unload.
5. **Correzione scratch tracciata:** sedici cicli del loader contract mostrano sedici coppie REGISTER/UNREGISTER con lo stesso flag per immagine, 1→0 prima dell'unload, redzone viva preservata. Il riproduttore storico con dodici future passa tre serie prefissate di 100 caricamenti; la ripetizione sui binari finali è registrata separatamente.

Le fonti primarie spiegano il contratto, mentre i log dimostrano il comportamento locale: [LLVM ASAN image lifecycle](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-17.0.6/compiler-rt/lib/asan/asan_globals.cpp) controlla il flag per rendere idempotente la deregistrazione; [Apple dyld finalization](https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/dyld/DyldRuntimeState.cpp) chiama i finalizzatori registrati prima di rimuovere le immagini, sotto il lock loader. La [modifica Clang sui distruttori frontend](https://reviews.llvm.org/D45578) descrive la registrazione via __cxa_atexit. Il sorgente pubblico non è assunto identico al binario privato Apple: nm, sezioni Mach-O, flag e traccia dell'esecuzione sono le verifiche effettive.

## Correzione implementata

Commit codice/test **bd4f81c18cca7c49211abe0b935e61b455cebe9c**, `test(native): retire ASAN image globals at mock unload`.

Solo tre file in Tools/PKCS11Tests:

- CMakeLists.txt collega asan_image_teardown.c al solo modulo mock e aggiunge un secondo eseguibile/target CTest per i contratti loader.
- asan_image_teardown.c è una translation unit distinta senza globali strumentate proprie. Soltanto con Apple + address_sanitizer registra un normale distruttore C che passa **il flag originale del compilatore ___asan_globals_registered** a **__asan_unregister_image_globals**, la stessa API usata dal distruttore ASAN generato. Non modifica a mano shadow o puntatori, non chiama API vendor, non anticipa l'ultimo dlclose e non possiede handle. Il flag 1/0 assicura idempotenza anche se un loader esegue pure il distruttore legacy. In Debug/TSAN il corpo è escluso e non fa chiamate ASAN.
- loader_contract_tests.cpp aggiunge **due contratti distinti**, seriale e concorrente, otto round ciascuno. La tabella e la redzone devono essere valide mentre il modulo è caricato, l'handle principale protegge tutti i thread, l'ultimo close deve scaricare davvero il modulo e lo shadow della redzone deve essere ritirato. Nessuna soglia prestazionale. I 58 casi provider esistenti e le loro assertion restano invariati.

La soluzione è un adattamento di compatibilità della **sola infrastruttura di test**, basato sull'ABI immagine LLVM ASAN Mach-O, non un cambiamento al motore o una soppressione. I simboli sono risolti al link; una toolchain incompatibile deve fallire link o regressione, non proseguire con copertura ridotta. Il default globals dead stripping del runner resta attivo. Un file separato evita che la dichiarazione esterna del flag interferisca con la sua generazione nel TU del mock.

Non modificati Sources/, Package.swift, mock_provider.c, lifecycle_tests.cpp, signing, Initialize/Finalize, sessioni, checked teardown, Secure Batch PIN, binding dei certificati/contesti, protocolli, retry o worker isolation. Non aggiunti pinning, RTLD_NODELETE, esclusioni del provider, unpoison manuale, retry fino al verde, variabili che disabilitano controlli o un secondo runner generico. Gli script scratch fissano soltanto le prove di questa diagnosi e usano il watchdog del runner ufficiale.

## Validazione prima/dopo

Il runner completo ufficiale è **passed, exit 0**, sul sorgente pulito **bd4f81c18cca7c49211abe0b935e61b455cebe9c**. Nessun failure/skip XCTest e nessun warning di compilazione Swift; i comandi nativi standard non contengono diagnostiche ASAN/TSAN.

| Controllo | Risultato | Durata comando | Log evidence |
|---|---|---|---|
| Swift completo | 426/426 | 210.378 s | final-complete/swift.log |
| Swift ASAN mirato | 208/208 | 117.000 s | final-complete/swift-asan.log |
| Swift TSAN mirato | 208/208 | 306.984 s | final-complete/swift-tsan.log |
| PKCS#11 Debug | 58 provider + 2 loader; CTest 2/2 | 4.855 s | final-complete/pkcs11-debug.log |
| PKCS#11 ASAN | 58 provider + 2 loader; CTest 2/2 | 5.621 s | final-complete/pkcs11-asan.log |
| PKCS#11 TSAN | 58 provider + 2 loader; CTest 2/2 | 7.629 s | final-complete/pkcs11-tsan.log |
| PAdES Debug | 79/79 | 2.405 s | final-complete/pades-debug.log |
| PAdES Release | 79/79 | 2.086 s | final-complete/pades-release.log |
| PAdES ASAN | 79/79 | 2.681 s | final-complete/pades-asan.log |
| Python packaging/tooling | 17/17 | 0.149 s | final-complete/packaging.log |
| Strict Debug da zero | 0 warning | 15.242 s | additional/strict-debug.log |
| Strict Release da zero | 0 warning | 27.057 s | additional/strict-release.log |
| Packaging Debug reale | pass | 24.108 s | additional/package-debug.log |
| Bundle Debug integrazione | 10/10 | 0.890 s | additional/packaged-debug.log |
| Packaging Release reale | pass | 39.110 s | additional/package-release.log |
| Bundle Release integrazione | 10/10 | 0.876 s | additional/packaged-release.log |
| PAdES TSAN supplementare | 79/79 | 25.342 s | additional/pades-tsan.log |

Le durate dei comandi Swift includono compilazione; quelle CTest escludono configure/build, registrati separatamente. Il completo finale è un singolo run ufficiale verde: non è ottenuto sommando componenti di esecuzioni fallite. Le prove supplementari restano separate.

Cinque processi CTest ASAN finali indipendenti, prefissati, restituiscono **0,0,0,0,0** su una build nuova; il completo aggiunge un sesto pass da una seconda build pulita del medesimo commit. Ogni processo passa 58 provider + 2 loader, con redzone attive/unload/shadow verificati. Il riproduttore storico su quel mock finale passa **3 × 100 round**, senza table poisoned. Non ci sono TTY, debugger, opzioni diagnostiche che riducano controlli o retry fino al verde in questi gate.

Bundle nuovi `work/asan-gate/bundles/Signum-C1-ASAN-final-{debug,release}.app` nella workspace della chat. Manifest bd4f81c, sourceTrackedDirty=false, 0.4.0/13, arm64 e minimo 13.0; hash dei componenti ricalcolati e codesign --verify --deep --strict ripetuto. Nessun bundle precedente sostituito né app installata. Le 20 integrazioni usano soltanto questi bundle e provider sintetici.


Le ripetizioni non sono nuovi casi: **58 provider + 2 loader**, non 600 test. Swift resta 426 casi e Python 17; nessun nuovo caso Swift/Python in questo follow-up. Dieci CTest preparatori passano su due build ASAN pulite del candidato; erano prima del commit con una sola differenza successiva nei commenti del ponte. Le prove finali usano invece git archive pulito del commit bd4f81c e non riutilizzano quel build. Comandi, exit code, tempi, percorsi e configurazioni sono nei JSON/log. I fallimenti baseline, l'errore iniziale di setup Python (tarfile filter non supportato; nessun test avviato), il timeout CLT17 e i controlli intermedi restano conservati.

## Limite residuo del reporting e copertura

Un canary diagnostico separato provoca intenzionalmente un overread di una globale dopo aver caricato/scaricato il mock corretto. L'accesso ASAN viene intercettato e il processo esce 1; il runtime stampa ancora DEADLYSIGNAL/nested bug invece del rapporto completo. **Non è un pass della suite né una prova di reporting risolto.** È incluso con il suo codice volutamente invalido, fuori dal repository. La correzione ripristina il normale teardown richiesto al compilatore/runtime; non ripara la struttura interna del reporter e non garantisce una diagnosi completa dopo ogni unload.

Il gate conserva la capacità di fallire sugli accessi invalidi e verifica esplicitamente redzone vive a ogni caricamento. ASAN con detect_leaks=0 non è una verifica delle perdite. Framework Apple e dipendenze precompilate non sono integralmente strumentati; i mock compilati runtime dalla suite Swift mantengono la copertura preesistente, distinta dal modulo del target nativo completamente strumentato.

La dipendenza dall'ABI privata LLVM è un residuo reale, confinato ai test: ripetere i due contratti a ogni cambio toolchain/runtime e rimuovere il ponte soltanto dopo aver verificato che il distruttore generato venga eseguito correttamente. Non certificati macOS 13/14 reali, Intel o tutte le toolchain future. Nessun collaudo hardware, middleware reale, GUI umano, PIN personale, notarizzazione o distribuzione. Non è stata cambiata la toolchain globale per ottenere il verde.

## Git finale e consegna

La sola patch di codice/test è bd4f81c; segue il commit documentale di questo rapporto, LOCAL_TESTING e append del progresso. Il suo hash e l'HEAD completo finale sono in **evidence/git-final.json**, evitando un hash autoreferenziale nel documento versionato. Confrontati i file di codice/test/tooling del repository con l'esportazione pulita: 180 file identici; diff produttivo da 14b2e4d vuoto. Il commit documentale non cambia i sorgenti verificati.

Working tree tracciato e index puliti alla consegna; restano soltanto i quattro rapporti iniziali non tracciati, con SHA-256 invariati. Tutti i ref precedenti, incluso codex/signum-0.4-hardening-b14c1 a 14b2e4d, invariati. Rapporto originario 14-C.1 e archivio evidenze precedente verificati invariati. Patch dei commit locali, risultati, log, riproduttori e inventario nel nuovo pacchetto di consegna. Nessun push.


## Decisioni finali

| Domanda | Risposta | Motivazione |
|---|---|---|
| ROOT CAUSE IDENTIFIED? | **YES** | Mancata esecuzione del teardown ASAN legacy all'unload: minimo indipendente, traccia flag, shadow residuo e sovrapposizione degli indirizzi spiegano il falso load8. |
| ASAN GATE RELIABLY PASSED? | **YES, nell'ambiente verificato** | Sei CTest standard finali su due build pulite, ulteriori dieci preparatori, contratti di unload/shadow e tre serie finali del riproduttore; nessun controllo disabilitato. |
| FULL TEST RUN PASSED? | **YES** | Singolo completo ufficiale passed sul commit bd4f81c, più packaging reale/integrato e controlli supplementari dichiarati. |
| READY FOR HARDENING 14-C.2? | **CONDITIONAL** | Il gate standard è chiuso. Prima di usare ASAN come diagnostica completa per ulteriore lavoro sulla memoria occorre un reporting post-unload verificato; il canary dimostra ancora il difetto del reporter. Mantenere inoltre obbligatori i contratti del ponte ABI a ogni cambio toolchain. |

La condizione residua riguarda la qualità diagnostica del runtime e la portabilità del ponte di test, **non un fallimento nascosto del completo standard**. Non si dichiara risolto tutto il runtime ASAN. Nessuna 14-C.2 avviata, nessun nuovo intervento sul motore o cambio globale di toolchain per aggirare questo limite.
