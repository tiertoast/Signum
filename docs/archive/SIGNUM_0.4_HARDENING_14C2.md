# SIGNUM 0.4 — Hardening 14-C.2

Digital signatures. Simply native.

20 ottobre 2026. **Implementazione e gate software completati; CQ-11 chiuso, CQ-10 condizionale sul budget di memoria.** Non è un fallimento della milestone per un'ottimizzazione opzionale rinviata. Le riduzioni misurate sono effettive; non viene dichiarato risolto il controllo generale del footprint di PDFKit o della firma PAdES.

## Baseline, perimetro e conservazione

Repository autorizzato `/Users/andreaoregioni/Developer/Signum-Reliability`, `tiertoast/Signum`. Partenza dall'HEAD completo **f9a03e6a586fd90ab2421a82dac139f91127874e**, incluso il documento successivo al codice ASAN bd4f81c. Branch locale **codex/signum-0.4-hardening-b14c2**. Checkpoint finale di codice/test/tooling verificato **8dd2e632c783a7e1fe9012a613038522df7787d2**; l'HEAD completo successivo al commit documentale è registrato in `evidence/git-final.json` della consegna, evitando un hash autoreferenziale.

All'inizio index/file tracciati puliti; quattro rapporti non tracciati inventariati e preservati. Controllati HEAD, remote locale, branch/worktree, script ufficiali, prefix e documenti. Letti integralmente code quality, invariants, 14-A, 14-B, 14-C.1, ASAN gate, performance diagnosis PAdES, LOCAL_TESTING e PROGRESS. Nessun rapporto originale riscritto o aggiunto all'index.

Inventario iniziale dei 16 bundle delle milestone precedenti nella workspace della chat; integrato prima dei gate finali con l'inventario completo dei bundle del repository autorizzato: **68 bundle, 1.087 file/link**, hash completi in preserved-bundles.json. Non si presenta l'inventario integrativo come una verifica eseguita prima delle modifiche. Tutti i comandi di build usano nuove directory scratch; nessun vecchio bundle è stato scritto. Ref precedenti e rapporti confrontati nuovamente a fine lavoro.

Prodotto invariato **0.4.0 / Build 13 / arm64 / macOS minimo 13**; package tools 5.9 e Swift language mode 5. Nessun accesso a HalleyMac, altri checkout applicativi, middleware installati, token/card, PIN personali o documenti di lavoro. I metadati Git comuni del medesimo repository sono usati per commit e manifest. Nessun push/fetch, merge, tag, release, Actions, PR #3, installazione globale o funzionalità 0.5.

Host arm64 macOS 27.2 (26B5112a), Swift 6.4, Apple Clang 21.0.0, SDK 27. Prefix locale preesistente PoDoFo 1.1.2/OpenSSL 3.5.4/FreeType 2.13.3; CMake/CTest e Poppler già disponibili. Nessun cambio toolchain. Gli SDK e il prefix non vengono certificati da questa verifica.

## Precondizione ASAN e perimetro diagnostico

Il ponte test-only `asan_image_teardown.c` e i due contratti loader/shadow sono presenti e invariati. Ricompilazione ASAN iniziale con il metodo native del runner ufficiale: **58 provider + 2 loader, CTest 2/2, exit 0**. Redzone attive con immagine viva, handle bilanciati, unload reale e ritiro shadow verificati. Non modificati lifecycle, mock, contratti, opzioni standard o runtime; ASAN_OPTIONS=detect_leaks=0.

Tre controlli intenzionalmente invalidi sono eseguiti in processi separati, fuori dalla suite: globale e heap producono rapporti completi global-buffer-overflow/heap-buffer-overflow ed exit -6; globale dopo unload del mock corretto fallisce exit 1 con DEADLYSIGNAL/nested bug. **Rilevazione presente; qualità del rapporto post-unload ancora limitata.** Non sono tre nuovi test verdi, né una correzione del reporter.

La prima automazione della precondizione registra failed per un attributo Python errato dopo il CTest già passato; la ripresa esegue soltanto i controlli diagnostici. Nessun retry del gate fino al verde. Entrambi i risultati originari sono conservati.

Le modifiche nuove usano Data posseduta/borrow sincrono con bounds invariati e vector RAII con capacità calcolata da lunghezze già validate; non cambiano ownership di puntatori vendor o immagini unload. Sono validate da regressioni di bounds/lunghezza/ownership/errori/cleanup/output, ASAN ordinario e TSAN pertinenti. Non si dipende dalla formattazione post-unload per giustificare una nuova gestione di handle. Il ponte rimane dipendente dall'ABI LLVM Mach-O e va ricontrollato al cambio toolchain. Leak detection disattivata; dipendenze precompilate, framework e mock compilati runtime Swift non equivalgono a copertura integrale.

## CQ-11 — inventario e isolamento

| Componente | Classificazione e chiamanti | Decisione / copertura |
|---|---|---|
| CAdESVerificationPane | UNUSED: nessun montaggio GUI, caller CLI/integration o test del tipo | Rimossi 184 righe di pannello non montato. La verifica non viene rimossa dal Core. |
| UnifiedVerificationPane / workspace | ACTIVE: main monta la sezione Verifica; usa SignumVerificationService | Conservati drop/picker, generazioni, cancel/reset e scarto risultati obsoleti. |
| PAdESPlacementPane / AppearancePDFView / PlacementPDFView | ACTIVE: workspace di firma e viewer attuale | Rimangono install/layout/eventi e updatePlacementOverlay. Nessuna nuova geometria. |
| SignaturePlacementOverlay / SignatureArtworkView | ACTIVE: AppearancePDFView chiama il percorso overlay | Rotazioni, crop/media/UserUnit, zoom/drag/resize e default visibile preservati. |
| AppearancePDFAnnotation, updateAppearance, updatePreview/freeText | TEST REFERENCE: pixel/thumbnail/geometria e vecchie assertion di ownership, nessun caller produttivo | Spostati in Tools/PlacementPrototype/Reference/ReferenceRenderer.swift, nomi Reference*. Target SignumPlacementReference dipende solo dal Core ed è dipendenza dei test, non di App/CLI/worker. |
| PAdESPreviewTests | TEST REFERENCE: quattro metodi storici freeText | Classe rinominata LegacyPAdESPreviewReferenceTests, commento e manifest espliciti; nessuna assertion unica eliminata. |
| Primo metodo PAdESPlacementPerformanceTests | TEST REFERENCE: riuso dell'annotazione | Nome test esplicito; mantiene byte/hash, oggetto e invalidazioni. |
| Secondo metodo della stessa classe | ACTIVE, test del pannello live | Rimane il drag a 60 eventi/s con overlay corrente, zero rendering/raster durante movimento e consenso al rilascio. Non è una prova di fps presentati. |
| DefaultPlacement / Geometry / Appearance, riferimenti thumbnail | TEST REFERENCE per i metodi che disegnano l'annotazione; ACTIVE per viewer/workspace/output | Riferimento indipendente mantenuto; assertion live controllano assenza di annotazioni nel documento. |
| Tools/PlacementPrototype | TEST REFERENCE; vecchio overlay alternativo UNUSED e build path storico DEPRECATED | Ritirati terzo renderer e git-show del vecchio pannello. La sonda compila il tipo viewport produttivo corrente e il riferimento isolato, con prodotti espliciti della stessa build; solo PDF sintetici. |
| CAdESVerifier.verifyAttached / verify / readInput | ACTIVE: SigningJob prima del commit, CLI verify-cades, lettore condiviso con verifica unificata e integrazioni | Conservati verificatore OpenSSL indipendente, nested attached e readback. Non eliminato per ridurre i file. |
| Verificatore nativo unificato | ACTIVE: GUI Verifica e CLI verify | Conservati integrità/firme multiple e distinzione trust/revoca/eIDAS non valutati. |

Non rimangono componenti UNCERTAIN rimossi senza chiarimento dei chiamanti. I riferimenti non sono presentati come prove del viewer live. Prima del freeze, gruppo UI ufficiale **45/45** (comprende anche riferimenti), più tre sonde sintetiche bounded zero/translated/rotated: pass. Il completo finale ripete tutti i test correnti e i riferimenti. La verifica finale dei simboli/dependency graph dei bundle è in binary-identity.json; nessun target Reference o pannello ritirato viene collegato ai prodotti.

## Metodo delle misure

Baseline Release da git archive di f9a03e6 e candidato finale pulito da 8dd2e632c783a7e1fe9012a613038522df7787d2. Scratch/build e processi nuovi. Stessa toolchain/configurazione, stesso provider/DER/chiave software e stessi hash fixture fra prima/dopo. Tre ripetizioni prefissate per 1/16/50/100 MiB, senza selezionare solo campioni favorevoli. Le prove preliminari e le nuove serie finali rimangono separate.

Tools/MemoryProfile è una sonda fissa, non un nuovo prodotto/worker o runner generico: usa Run.command/Run.native del runner ufficiale. Accesso interno tramite -enable-testing solo nelle build di profilo. Chiama Core, bridge App e viewer produttivi; il viewer è ospitato da una sonda senza discovery applicativa. Non è il processo completo SignumApp. Worker v2 e helper v5 sono esercitati dai job bound. Una prova separata misura il worker foglia con un **nuovo ID di job**, stdin sintetico eliminato dopo l'uso e risposta RSA verificata con OpenSSL; nessuna sessione/autorizzazione riutilizzata.

Le fixture dimensionali hanno padding inerte e complessità di parsing quasi costante. Completano la valutazione tre processi freschi per fase con quattro pagine/80.000 operazioni vettoriali e con immagine RGB 4096² (48 MiB decodificati) compressa. Queste ultime prove sono contemporanee alla suite finale: sono evidenza di memoria, non un confronto di latenza. Batch separati: due documenti da 1/16/50 MiB e **32×4 MiB = 128 MiB**. Incrementale misurato a 1/16/50 MiB; il primo output da input 100 MiB supera già il limite di input 100 MiB. Batch 100+100 MiB fuori limite 128 MiB: **NOT RUN per dominio**, senza forzare input non supportati o contarli come skip di suite.

Raccolti RSS SELF di picco e resident ai checkpoint, CPU/wall, dimensioni Data, capacità vector, clone/read CaptureIO e contatori Darwin di I/O attribuito. /usr/bin/time misura separatamente worker/helper/verificatori foglia. Un controllo locale parent/child mostra **SELF parent 1.736.704 byte, child/time 158.498.816 byte**: il max RSS di time su questo host include il valore del figlio. Perciò non viene usato come RSS del parent. CPU parent viene da RUSAGE_SELF; children rusage non è attribuito a un singolo figlio. **Nessun picco è sommato o dichiarato consumo simultaneo dell'intera pipeline.**

I contatori diskio sono dipendenti da cache/attribuzione OS; non sono byte logici o bandwidth. Capacità riservata non equivale a pagine residenti; append/copie derivate dal sorgente non sono un conteggio di malloc. Non eseguito un trace Allocations completo dei framework. Native-phases aggiunge marcatori soltanto in copie isolate; i risultati unmodified-helper separati sono quelli principali. I marcatori usano una pipe per conservare RLIMIT_FSIZE=0 del verificatore. Non sono abbassati limiti o controlli del prodotto.

## CQ-10 — interventi e costi conservati

**CAdES:** composizione identica di ContentInfo/SignedData con gli header DER esistenti, piccoli prefissi/suffissi e un solo append del documento in capacità riservata. Non è un nuovo motore CMS o serializer generalizzato; attributi, ordinamento SET, certificato, algoritmo e firma rimangono identici. Nel modello dei byte appesi a nuovi contenitori, il payload attraversava nove append/composizioni complete; ora uno. È un modello del percorso, non nove malloc né nove buffer simultanei. L'assegnazione a Prepared è CoW, non una copia materiale.

**Metadati CMS:** rimossa la conversione forzata dell'intero CMS in [UInt8] per sniff/signers. withUnsafeBytes ha uno scope sincrono, non restituisce puntatori/slice; escono stringhe e Data possedute per i campi. DER.read mantiene gli stessi bounds, lunghezze minime/definite e limiti; accetta array e buffer contiguo con indice zero. Nessuna fiducia crittografica è assegnata dal parser di display: OpenSSL resta l'autorità finale.

**PAdES:** tre riserve di capacità, senza cambiare reader, ByteRange o writer. readSource riserva la dimensione fstat già limitata; crescita, identità/size/mtime/ctime, header e cleanup invariati. Le due composizioni ByteRange (inspection e verifica finale) riservano la somma dei segmenti già validati prima di copiarli. La somma è entro la dimensione PDF; gli stessi byte sono passati a CMS. Per 100 MiB, capacità sorgente osservata 128→100 MiB; il concatenamento firmato passava da circa 100 a 200 MiB di capacità per il piccolo suffisso, ora riserva circa 100 MiB complessivi. La proprietà dei vector e il loro rilascio rimangono RAII.

Non cambiano PoDoFo o l'update incrementale. Il buffer PoDoFo mutabile, la conversione al writer e il readback posseduto rimangono distinti. La sola conversione del writer non determina il picco osservato; non viene estesa l'API per un beneficio marginale di picco. L'inspection nativa conserva ancora buffer propri durante la seconda verifica: costo valutato, non dichiarato eliminato.

| Fase | Lavoro preservato / valutazione |
|---|---|
| Acquisizione | Un clone CoW, N byte letti dal clone e un hash N nel caso stabile. CaptureIO finale misura 1 clone e N byte per tutte le taglie. Il ramo ctime richiede la corroborazione originale e resta presente. Clone logico non presentato come copia fisica N. |
| Review | Una verifiedBytes per snapshot: identità, lettura, confronto e hash. Batch legge in sequenza; job e approvazione condividono snapshot immutabili, senza cache globale. |
| Job CAdES | Tre verifiedBytes: pre-operazione, dopo firma, validator dello staged. Con capture e Prepared sono cinque hash applicativi N, esclusa review (che ne aggiunge uno) e gli hash dei verificatori. Tutte le letture protettive rimangono. |
| Staging CAdES | Scrittura M, fsync, readback M e confronto prima del validator. Il verificatore indipendente scrive il proprio CMS, OpenSSL estrae N e il parent confronta N con l'approvato. Non sostituito con sola verifica del buffer generato. |
| Parent PAdES | Capture N; preflight verifica lo snapshot prima/dopo IPC; bridge verifica ancora prima di avviare il helper. Data approvata condivisa CoW, non letta dal pathname originale dopo consenso. |
| Helper PAdES | Lettura N/hash atteso, policy sorgente, buffer mutabile PoDoFo, firma incrementale, conversione writer, scrittura/readback M e verifica. Le riserve riducono riallocazioni, non i controlli o i byte firmati. |
| Verifica unificata | Input bounded, frame output posseduto, estrazione Data e PNG bounded con annotazioni, cleanup. Il parent CMS da 100 MiB resta ~439 MiB: costo misurato delle copie/frame/ownership, non ottimizzato cambiando protocollo. |
| Batch/cleanup | 32 snapshot per 128 MiB, review, reset e ritiro dei file privati verificati. L'approvazione ancora posseduta dalla sonda trattiene intenzionalmente i byte fino allo scope. RSS/allocator retention non è prova di leak o secure erasure. |

## Confronto finale prima/dopo

MiB e CPU parent in ms: mediana [min–max] su tre processi. Picco SELF fino all'ultimo checkpoint. Taglia input 100 MiB; niente RSS cumulativo XCTest utilizzato come memoria app.

| Processo/percorso | RSS MiB prima → dopo | Δ RSS | CPU ms prima → dopo | Δ CPU |
|---|---:|---:|---:|---:|
| CMS, parent | 610.25 [610.22–610.30] → 210.08 [210.05–210.11] | -65.6% | 109.28 [108.29–125.41] → 68.08 [65.32–70.35] | -37.7% |
| Metadati CMS, parent | 210.58 [210.55–210.58] → 110.50 [110.47–110.50] | -47.5% | 29.23 [25.26–29.39] → 17.22 [17.12–17.60] | -41.1% |
| Job CAdES bound, parent | 737.55 [737.47–737.70] → 412.39 [412.30–412.52] | -44.1% | 329.28 [321.19–330.82] → 290.82 [290.09–292.35] | -11.7% |
| Job PAdES visibile bound, parent | 315.41 [315.33–315.45] → 315.17 [315.16–315.20] | -0.1% | 257.94 [245.88–264.48] → 247.82 [244.41–252.55] | -3.9% |
| Verifica PDF firmato + PNG, parent | 243.03 [243.03–243.05] → 243.09 [243.05–243.14] | +0.0% | 111.23 [103.36–114.79] → 105.02 [103.39–107.33] | -5.6% |
| Verifica/estrazione CMS + PNG, parent | 439.36 [439.34–439.39] → 439.31 [439.30–439.36] | -0.0% | 133.65 [130.29–134.49] → 133.75 [132.81–139.16] | +0.1% |
| Viewer/overlay attivi, host sintetico | 334.14 [331.31–335.69] → 334.17 [333.56–335.67] | +0.0% | 354.21 [339.74–359.32] → 364.34 [352.86–371.61] | +2.9% |
| Helper PAdES, processo foglia | 642.09 → 414.02 | -35.5% | 190 → 180* | -5.3%* |
| Verificatore PDF nativo, processo foglia | 539.52 → 439.47 | -18.5% | 110 → 120* | +9.1%* |
| Worker RSA sintetico v2, processo foglia | 8.61 → 8.53 | -0.9% | 0 → 0* | N/A* |

*CPU time dei processi foglia arrotondato dallo strumento a 0,01 s: per il worker 0 significa sotto risoluzione, non lavoro nullo. Helper 0,19→0,18 s; verificatore 0,11–0,12 s in entrambe le versioni (la mediana 0,11→0,12 non dimostra una regressione causale). Non si rivendicano miglioramenti piccoli nei percorsi invariati. Wall job CAdES 100 MiB: mediana 0,84→0,76 s; CMS 0,13→0,08 s. Le matrici complete con variabilità/CPU/wall/I/O sono in PROFILES.md e profiles-summary.json.

I **12 CMS finali sono byte-identici** fra baseline e candidato e ogni estrazione OpenSSL ha lo SHA-256 originale. Gli output PAdES con timestamp/field ID variabili sono verificati crittograficamente e sul prefisso; regressioni complete e Poppler verificano artwork/geometria reali, non l'hash dell'intero PDF variabile. La verifica del worker RSA è esterna e separata.

I/O invariato per contratto. Capture 100 MiB→100 MiB letti, 1→1 clone (0%); dimensione CMS prodotta identica. Contatori Darwin parent job CAdES: read mediano 104.976.384→104.861.696 byte (-0,11%, range sovrapposti/cache), write **209.731.584→209.731.584 byte (0%)**. CMS isolato write **104.861.696→104.861.696 (0%)**; il read attribuito 73.728→0 è rumore di cache/metadata, non un risparmio di lettura del documento. Parent PAdES visibile read 104.857.600→104.857.600 (0%); le scritture appartengono al helper, non al parent. Nessun miglioramento I/O generale rivendicato.

Il batch al limite 128 MiB ha picco SELF mediano **144,66→144,52 MiB**, CPU **233,75→238,81 ms**: controllo sostanzialmente invariato, non ottimizzazione. Il preflight nativo stdin da 100 MiB ha RSS ~238,53 MiB in entrambi i casi; la riserva di readSource non è applicata al reader stdin di dimensione non nota.

## Budget, residui e decisione su CQ-10

L'immagine PDF sintetica 4096² porta il viewer attivo a **331,52→333,09 MiB** di picco SELF, contro ~42,5 MiB nel parent della verifica/thumbnail della stessa fixture. Il helper di firma della stessa fixture compressa da 74.672 byte raggiunge **448,45→448,33 MiB**: il costo di decodifica/confronto risorse resta rilevante e non è corretto estrapolare il guadagno dei PDF con padding. Il vettoriale 4 pagine/80.000 operazioni raggiunge ~168,59→161,11 MiB nel viewer; non si attribuisce quel piccolo delta alla patch. Le prove confermano il costo della decodifica/tiling di PDFKit oltre il peso compresso. Non coprono tutti i PDF o un budget assoluto del framework.

**I limiti 100 MiB input, 128 MiB sessione e 132 MiB output non sono un tetto RSS.** La verifica unificata e il preflight pubblico conservano la supervisione RSS 1 GiB già presente. Il percorso di firma PAdES non passa maximumResidentBytes e il viewer GUI non ha un budget RSS duro. Non viene introdotto qui un kill/guard globale: durante un'operazione privata potrebbe produrre un esito incerto; non va trasformato in un falso fallimento sicuro.

Per questo **CQ-10 resta CONDITIONAL**, pur avendo profili essenziali e benefici dimostrati: resta da decidere e verificare il budget del viewer/decodifica e del percorso di firma, con policy pre-consenso o supervisione coerente con gli stati incerti. Il costo CMS unificato e i buffer indipendenti restanti sono ora quantificati. Non sono nascosti come completamente risolti; streaming, nuove cache, nuovi worker o motori PDF non vengono anticipati. L'ottimizzazione facoltativa del writer rinviata non rende fallita l'intera milestone.

## Nuovi test e regressioni

**Sei casi distinti nuovi: quattro XCTest e due casi nativi**, zero nuovi Python. Non si sommano ripetizioni, benchmark o rinomine ai nuovi casi.

- CAdESMemoryContractTests: equivalenza con composizione storica a 1/127/128/255/256/65535/65536/1 MiB e firme 128/256/512/1024; rifiuti firma; DER tronco/non minimo/out-of-bounds; Data slice con indice iniziale non zero e stringhe possedute dopo modifica del backing; tutti i troncamenti, 33 signer e nested CMS malformato non nascosto come originale.
- Nativo: letture binarie a 5/65535/65536/65537/1 MiB, ownership dopo unlink, rifiuti vuoto/header/oversize e descriptor cleanup; firma grande/incrementale con due CMS, output/readback identici, tampering rifiutato, staging pulito e precedente output preservato.

I 58 provider e i due contratti loader precedenti sono invariati. Restano i test CAdES singolo/batch/nested, PAdES visibile/invisibile/incrementale, firme precedenti supportate, batch misti, Secure Batch PIN sintetico, snapshot/consenso, binding certificato/provider, no-overwrite/directory, cancellazione/timeout/crash/esito incerto/cleanup, annotazioni e preview/output equivalence. Il completo include i veri workspace e overlay, le rotazioni 0/90/180/270, crop/media/UserUnit, immagini, zoom/drag/resize e Poppler. Nessun test di proprietà unica eliminato.

## Gate finali effettivamente eseguiti

**Un singolo runner completo ufficiale passed**, sul checkpoint pulito 8dd2e632c783a7e1fe9012a613038522df7787d2. Non è aggregazione di componenti verdi da run falliti. Supplementari strict/packaging/PAdES TSAN nello stesso sorgente con il watchdog ufficiale, directory nuove. I log nativi di esecuzione escludono configure/build; quelli Swift includono compilazione.

| Controllo | Risultato | Durata comando | Log evidence |
|---|---|---:|---|
| swift | PASS — 430/430; 0 fail/skip | 217.779 s | final-complete/swift.log |
| swift-asan | PASS — 212/212; 0 fail/skip | 112.333 s | final-complete/swift-asan.log |
| swift-tsan | PASS — 212/212; 0 fail/skip | 300.953 s | final-complete/swift-tsan.log |
| pkcs11-debug | PASS — 58 provider + 2 loader; CTest 2/2 | 4.908 s | final-complete/pkcs11-debug.log |
| pkcs11-asan | PASS — 58 provider + 2 loader; CTest 2/2 | 5.230 s | final-complete/pkcs11-asan.log |
| pkcs11-tsan | PASS — 58 provider + 2 loader; CTest 2/2 | 7.186 s | final-complete/pkcs11-tsan.log |
| pades-debug | PASS — 81/81; CTest 1/1 | 3.185 s | final-complete/pades-debug.log |
| pades-release | PASS — 81/81; CTest 1/1 | 1.760 s | final-complete/pades-release.log |
| pades-asan | PASS — 81/81; CTest 1/1 | 3.150 s | final-complete/pades-asan.log |
| packaging | PASS — 17/17 | 0.128 s | final-complete/packaging.log |
| strict-debug | PASS — 0 warning | 14.227 s | additional/strict-debug.log |
| strict-release | PASS — 0 warning | 27.492 s | additional/strict-release.log |
| package-debug | PASS — bundle nuovo | 24.577 s | additional/package-debug.log |
| packaged-debug | PASS — 10/10 | 0.994 s | additional/packaged-debug.log |
| package-release | PASS — bundle nuovo | 38.987 s | additional/package-release.log |
| packaged-release | PASS — 10/10 | 0.833 s | additional/packaged-release.log |
| pades-tsan | PASS — 81/81 | 27.583 s | additional/pades-tsan.log |

**PASS:** gate sopra. **FAIL finali:** 0. **SKIP nelle suite selezionate:** 0. **NOT RUN:** hardware/middleware reali, GUI umano completo/accessibilità, runtime macOS 13/14 reale, Intel, UBSAN, notarizzazione/Developer ID, installazione/distribuzione, trace Allocations completo e picco simultaneo dell'intera pipeline. Le condizioni dimensionali escluse dai profili non sono skip XCTest. Storici 426/208/79 non usati come pass automatici del nuovo codice.

Due bundle reali nuovi in `work/hardening14c2/bundles/Signum-14C2-final-{debug,release}.app` della workspace della chat. Manifest 8dd2e632c783a7e1fe9012a613038522df7787d2, sourceTrackedDirty=false, 0.4.0/13, arm64/minimo 13.0; audit/rilocazione e **20 integrazioni (10 per configurazione)** sui componenti confezionati, hash annidati e codesign deep/strict ricontrollati. Nessun vecchio bundle sostituito o app installata.

## Tentativi intermedi conservati

Errori dell'infrastruttura nuova: getpid senza include unistd; precondizione con attributo logs errato; test Swift borrow senza try richiesto dal compilatore; configure nativo con path assoluto che non selezionava il prefix ufficiale; invocazione helper senza campi v3 richiesti; primo output marcatori assente per stderr silenziato; successivo marker su file rifiutato da RLIMIT_FSIZE=0 (SIGXFSZ). Risolto il trasporto diagnostico con pipe, senza toccare limiti/runtime del prodotto. Fixture native inizialmente con /tmp symlink rifiutato da O_NOFOLLOW_ANY, poi padding compresso dalla fixture: usati percorso canonico e NoFlateCompress nella sola generazione della fixture. Tutti i tentativi restano nei log con esiti originali; non sono prove di un prodotto corretto dopo una build fallita.

## Invarianti e commit

SG-01/14: staged readback, confronto/verifica, directory approvata su descriptor, rename esclusivo e conservazione post-commit incerto restano invariati. SG-02: nessun cambiamento a Initialize/Finalize, sessioni, lease, checked teardown, PIN o retry. SG-03/04: ByteRange/CMS, algoritmi/policy e certificato approvato conservati. SG-05: snapshot/job/appearance/consenso immutabili e byte verificati prima/dopo operazione. SG-06: vendor isolato nei processi esistenti; nessun nuovo worker generico. Cambiamenti Git limitati a CQ-10/CQ-11 e relative prove/documentazione.

| Finding | Stato | Evidenza | Commit locale | Residuo |
|---|---|---|---|---|
| CQ-11 | CLOSED | Call graph, riferimento fuori runtime, UI 45/45, tre sonde, completo e bundle | 6f12cfb | Collaudo GUI umano/minimo OS resta separato |
| CQ-10 | CONDITIONAL | Matrice 3×4 taglie, fasi/processi/IO, 6 nuovi casi, completo/sanitizer; RSS CMS -65,6%, job CAdES -44,1%, helper PAdES -35,5% | b7752c6, 729929a; tooling 8dd2e63 | Budget RSS GUI/firma PAdES da definire/verificare; costo CMS unificato e buffer residui quantificati |

Segue commit documentale di questo rapporto, append PROGRESS e chiarimento della contabilità Darwin nella README della sonda. Source-consistency.json verifica codice/test/script/resource identici al checkpoint testato; solo documenti cambiano dopo. Working tree/index tracciati puliti alla consegna, quattro originali non tracciati invariati; hash ref/bundle/report in git-final.json e preserved-bundles-verification.json. Nessuna operazione remota.

## Collaudi manuali e verdetto

Con fixture sintetiche nel nuovo bundle: cambio documento/formato, default stamp e firme visibili/invisibili, crop/rotazioni/UserUnit e immagini; zoom/drag/resize e confronto fra preview e output. Provare remove/reset/chiusura durante preparazione e firma, picker/drop lento/generazione obsoleta, batch misti e sessione Secure Batch PIN, collisione/directory rinominata e avviso incerto senza retry. Ripetere sui sistemi minimi; definire una sessione autorizzata di hardware/middleware reale, senza trasferire automaticamente i risultati storici della Build 13.

| Domanda | Verdetto | Motivazione |
|---|---|---|
| CQ-10 CLOSED? | **CONDITIONAL** | Copie misurate ridotte e costi profilati; non chiuso il budget RSS GUI/firma. |
| CQ-11 CLOSED? | **YES** | Componenti classificati; codice inutilizzato ritirato, riferimenti utili isolati e test correnti preservati. |
| READY FOR FINAL 0.4 CODE REVIEW? | **YES** | Checkpoint pulito, gate richiesti verdi e residui espliciti, pronti a valutazione indipendente. |
| READY FOR HARDWARE VALIDATION? | **YES, in sessione dedicata autorizzata** | Gate sintetici passati; nessuna compatibilità hardware nuova attestata o prova reale eseguita qui. |
| READY FOR MERGE? | **CONDITIONAL** | Review finale e decisione sul residuo CQ-10, oltre ai gate manuali/hardware/minimo OS richiesti per il rilascio. Nessun merge eseguito. |
