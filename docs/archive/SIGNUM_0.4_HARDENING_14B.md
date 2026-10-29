# SIGNUM 0.4 — Hardening 14-B

Digital signatures. Simply native.

## Baseline, perimetro e conservazione

Repository `tiertoast/Signum`, workspace `/Users/andreaoregioni/Developer/Signum-Reliability`. HEAD completo 14-A **`886933014fc9a17f88cdb4a2cd10a12221fe4967`**: include la documentazione dopo il checkpoint di codice `6cc90ab21917e0514fb3e4ca3e053c910d19caf0`. Branch nuovo `codex/signum-0.4-hardening-b14b` da quell'HEAD; nessun ritorno alla Build 13 sorgente. Prodotto sempre **0.4.0 / Build 13**, nessuna Build 14 distribuita.

Prima delle modifiche: controllati remote, cronologia, branch, index, working tree, worktree e bundle. Nessuna modifica tracciata iniziale. Quattro rapporti non tracciati preservati: code review 0.3.3, code quality 0.4, invariants 0.4, performance diagnosis PAdES. Le review, il rapporto 14-A e il progresso sono stati letti integralmente, consultati Foundation e profilo della verifica PAdES. Rapporti diagnostici originali invariati.

Main `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70`, branch B13 `c45bb006b8ab00c5f80bcb03a25232abf002e2e6`, branch 14-A `8869330` preservati. Il secondo checkout è stato identificato solo tramite metadati Git. Nessun altro repository aperto/compilato/modificato; HalleyMac escluso. Nessun push, fetch, merge, tag, release, Actions o accesso/modifica alla PR #3. Nessun dispositivo, middleware installato, PIN personale o documento personale utilizzato.

## Metodo ed evidenze

Le milestone sono state eseguite in ordine A–E, con test del comportamento precedente prima della patch quando espresso dalle API esistenti, correzione circoscritta, regressioni e commit locali distinti. Le prove rosse non modificano la logica del prodotto per simulare il difetto. Fixture errate e tentativi intermedi non sono promossi a prove della regressione: restano nei log.

Base di consegna: `/Users/andreaoregioni/Documents/Codex/2026-10-19/files-pasted-by-the-user-signum/outputs/14B/`. `evidence/runs.jsonl` registra comandi esterni/esiti/durate; ogni log ha comando e cwd. Il runner ufficiale registra separatamente ogni suite e conserva `results.json`. La copia pulita finale è un `git archive` di **`276585c`**, senza `.git`, build o directory di evidenze preesistenti. Build/fixture/evidenze finali hanno una directory UTC/UUID nuova: nessun mkdir del vecchio percorso `.build/04stabilization-b13/evidence`. Il primo run su `c8797e1` è conservato come tentativo intermedio: completo 410/410 e ASAN 139/139, ma TSAN interrotto; non è una suite completa verde. La copia finale include anche il ritiro bounded dell'acquisizione e il teardown checked delle fixture sincrone.

## A — CQ-04: preflight PAdES

La review è confermata nel helper: la policy della sorgente (Perms e profilo delle firme precedenti) veniva applicata soltanto durante la verifica dell'output. La regressione sintetica su `Perms` arriva al provider sul codice precedente, e fallisce dopo i 67 casi storici (`cq04-red.log`). Dopo la patch lo stesso caso non crea nemmeno l'audit delle operazioni del provider e non pubblica output.

`requireSupportedSource` riusa parser CoreGraphics, lettore bounded dei campi/risorse/annotazioni, validazione ByteRange e verifica CMS già usati dal controllo finale. Rifiuta cataloghi Perms, sorgenti malformate/cifrate e firme precedenti non appartenenti al profilo ammesso o non integre. Le firme incrementali supportate vengono verificate e rimangono ammesse. Lo stesso controllo è richiamato dal verificatore finale e dal helper **prima** di staging, lease/provider/PIN/operazioni private. Nessuna primitiva crittografica è cambiata.

L'ingresso isolato `--source-preflight-stdin-v1` legge solo byte, entro 100 MiB; non accetta provider/destinazione/PIN e non produce documenti. Risposta tipizzata `accepted/rejected`, motivo bounded e SHA-256 dei byte letti. `PAdESSourcePreflight` verifica la risposta, il digest e l'integrità dello snapshot; preparazione review/approval eseguita fuori main conserva il risultato nel job prima del consenso. La verifica finale resta obbligatoria.

Nessun rifiuto indiscriminato dei documenti già firmati. Nessun nuovo limite arbitrario di 1000 pagine: quella soglia appartiene alla preview/verifica unificata, non al precedente contratto di firma. Il test da 1001 pagine ne impedisce l'introduzione nel preflight. Conservati anche i commenti PDF finali già ammessi. Quattro nuovi test Swift e quattro casi nativi coprono input ordinari/multipagina/rotazioni, binding dei byte, modifiche dell'originale e dello snapshot, cancellation, firme precedenti supportate/unsupported, malformed/encrypted e firma successiva valida; appearance/geometria restano nelle integrazioni esistenti.

Limite: accettare la sorgente significa superare i controlli prevedibili del profilo, non garantisce successo del dispositivo, disponibilità futura del percorso o validità universale ETSI. Trust, revoca, qualificazione, DocMDP/FieldMDP e profili ulteriori restano fuori dal supporto dichiarato.

## B — CQ-05: identità del writer

Riproduzione valida `cq05-red-confirm.log`: la directory viene rinominata e sostituita dopo `requireAvailableDestination`, nella firma sintetica prima del writer. Il codice precedente non solleva errore e crea `result.p7m` nella directory sostitutiva. Dopo la patch: rifiuto, directory errata e directory approvata prive di output/staging.

Il writer Swift riceve `destinationDirectoryIdentity` dal job. Subito dopo open esegue fstat sul descriptor reale e confronta device/inode, **prima di recovery, staging o payload**. Il writer nativo riceve l'identità approvata con `--expected-output-directory-v1`, esegue la stessa verifica e mantiene il pinning. I piani GUI conservano sempre l'identità; le API legacy senza piano restano esplicitamente prive di un'identità approvata da confrontare. L'opzione pubblica non contiene segreti e mantiene il contratto helper v5 della 14-A.

Semantica dichiarata:

| Momento | Esito |
| --- | --- |
| Rinomina prima di open o tra validazione del job e open | Open non disponibile oppure fstat mismatch: rifiuto prima del payload |
| Stesso nome con directory diversa | Rifiuto; nessun payload nella directory errata |
| Alias scelto durante pianificazione | Risolto nel percorso canonico approvato; il writer non accetta una nuova indirection al suo posto |
| Rinomina dopo il descriptor, prima del commit | Descriptor rimane ancorato alla directory originale; controllo del percorso prima del rename esclusivo rifiuta un percorso diverso/non risolvibile, con cleanup solo dello staging proprio |
| Directory e percorso approvati ancora validi | Pubblicazione esclusiva nello stesso descriptor approvato |
| Cambio osservato dopo il commit | Esito **incerto**, output pubblicato conservato; nessun retry o cancellazione del file finale |

Il punto di commit resta `renameatx_np(..., RENAME_EXCL)`: esistenti e collisioni tardive non vengono sovrascritti. Un esito incerto del writer rimane tale anche nello stato `SigningOperation`. Non è una promessa di immutabilità permanente del namespace dopo l'ultima osservazione, né di durabilità in caso di perdita di alimentazione.

Cinque nuovi test Swift e otto casi nativi: descriptor corretto/mismatch, open/fstat in errore, directory sostituita/rinominata nelle varie fasi, alias/symlink, conservazione post-commit. I test esistenti continuano a coprire collisioni/esistenti, ACL, originali immutati, crash/recovery e no-overwrite.

## C — CQ-07: cancellazione pubblica e ownership

`cq07-red.log`: il secondo contesto non raggiunge il proprio validatore entro 1 secondo, mentre il primo processo pubblico continua fino alla deadline. Il test non cambia il prodotto né il timeout produttivo.

`SigningReview` cancella il token **e** la Task posseduta. Il validatore off-main è un figlio esplicitamente posseduto con cancellation handler; la GUI passa il controllo a `DeviceCertificateRoute.requireCurrentCredential`, poi a scan e lettura DER di `IsolatedPKCS11Client`/`SupervisedProcess`. Cancellation resta cancellation, non diventa indisponibilità del certificato o esito di firma. Chiusura vista chiama `review.cancel`; generazioni obsolete non pubblicano approvazione o errore corrente.

È conservato un solo preflight attivo: la nuova richiesta attende il **ritiro cancellato e supervisionato** del precedente, non la sua normale deadline vendor. Le richieste intermedie vengono accorpate all’ultima tramite la generazione (regressione esistente: 31 contesti, 2 avvii). Non sono introdotti polling produttivi o detached senza owner. Anche acquisizione snapshot e preparazione review del coordinatore ricevono la cancellazione della Task; cleanup e pubblicazione restano guardati dalla generazione. Un capture cancellato conserva il proprio slot fino al ritorno del lavoro posseduto: nuove acquisizioni non si sovrappongono durante il ritiro. La regressione esistente è stata rafforzata e ha fallito tre assertion prima del completamento di questa patch (`cq07-draining-red.log`), poi è passata con il limite di ownership ripristinato.

Tre nuovi test Swift: avanzamento dopo cancel del subprocess, due/tre richieste/coalescing/chiusura durante lavoro attivo e scan/DER realmente bloccati in mock figli. La cancellation PAdES è provata anche dopo l'avvio di un helper sintetico supervisionato tramite marker controllato. I test delle variazioni provider/certificato/documento/formato/appearance/discovery e callback tardive restano attivi. Nessun cambiamento alla semantica delle operazioni private di `SigningOperation`.

Limite del sistema: una syscall/kernel non interrompibile non può essere resa cancellabile da una Task Swift. Il supervisore conserva la capacità del figlio fino al reaping, limita i processi e può restituire `terminationPending`; non dichiara che quel figlio sia certamente già terminato. Le operazioni vendor restano fuori MainActor.

## D — CQ-09: acquisizione Verifica

`cq09-red.log`: cancellare la Task di un vero NSItemProvider differito non risolve l'attesa entro 0,5 s, e la callback tardiva restituisce ancora un URL. La fixture rilascia poi la callback per terminare la prova senza lasciare attese pendenti.

`VerificationDropLoader` riusa `FileDropResolution`. Il collector risolve una sola volta; cancellation viene registrata prima di avviare callback, deadline predefinita 10 s (bounded, testabile), callback duplicate/tardive ignorate. Il workspace possiede Task di acquisizione/verifica e ID della richiesta; busy/acquiring vengono riservati sincronicamente. Nuovo drop, picker, cancel, reset e chiusura invalidano la generazione e cancellano il lavoro precedente. Solo la richiesta corrente modifica righe, errori e stato; anche una verifica già iniziata e terminata tardi viene scartata.

Cinque nuovi test deterministici, con deadline azionabile e callback controllate, coprono ordine/multipli, mancata risposta, duplicate/late, cancel nativo, supersessione da drop/picker, chiusura/reset, timeout e recupero. La UI mostra acquisizione in corso e consente il picker mentre il drop è pendente. Verifica resta indipendente da Firma, PIN, certificati e dispositivi: condiviso soltanto il resolver di acquisizione.

## E — CQ-13: test riproducibili

Il test della preview fallisce davvero su copia senza la directory storica (`cq13-clean-red.log`). `FixtureFiles` ora crea directory uniche e canoniche per fixture/evidenze; preview, workspace e confronti appearance non sovrascrivono immagini storiche. Il mock provider è isolato sotto il root della singola esecuzione. Le fixture preparano autonomamente le proprie directory anche fuori dal runner.

Attese fixture Swift: timeout, SIGKILL e osservazione bounded; eliminati waitUntilExit nei test e lettura pipe OpenSSL prima della fine processo. Barriere asincrone bounded. Attese figli native bounded, oltre alla deadline CTest. Nessuna modifica alla logica produttiva per accomodare il test harness.

`scripts/test-local.py` è il runner locale ufficiale: setup esplicito, manifest delle classi/gruppi, nuova directory per ogni run, log e riepilogo machine-readable, watchdog del gruppo di processi. Completo = Swift senza filtri, PKCS#11 Debug, PAdES Debug/Release, Python packaging/tooling e sanitizer mirati; un prerequisito mancante è un errore di setup, uno skip in un gruppo selezionato fa fallire la suite. Gruppi opzionali espliciti: pure-swift, native-helper, poppler, synthetic-pkcs11, integration, ui; selezionarne uno non autorizza a dichiarare il completo verde. Nessuna CI, rete o installazione globale.

Due nuovi test Swift per unicità/directory pronta e processo non rispondente; quattro unit test Python di classificazione, prerequisiti e selezione sanitizer. Istruzioni, env, timeout, skip ed evidenze in [LOCAL_TESTING.md](../LOCAL_TESTING.md). `scripts/test-packaged-bindings.py` rende riproducibili anche i controlli sintetici sui bundle nuovi.

## Risultati finali della 14-B

Host arm64, macOS 27.2, Apple Swift 6.4; linguaggio/tools del package invariati. Prefix locale preesistente PoDoFo 1.1.2/OpenSSL 3.5.4/FreeType 2.13.3, non installato globalmente né scaricato. I risultati storici 14-A non sono usati come prova di queste patch.

| Controllo | Risultato finale | Log in evidence/ |
| --- | --- | --- |
| Swift completo senza filtri | **410/410, 0 fail, 0 skip; 190,786 s test / 219,483 s comando** | `final-run/swift.log` |
| PKCS#11 Debug | **58/58, 1/1 target CTest** | `final-run/pkcs11-debug.log` |
| PAdES Debug | **79/79, 1/1 target CTest** | `final-run/pades-debug.log` |
| PAdES Release | **79/79, 1/1 target CTest** | `final-run/pades-release.log` |
| Swift ASAN mirato | **145/145, 0 fail, 0 skip** | `final-run/swift-asan.log` |
| Swift TSAN mirato | **145/145, 0 fail, 0 skip** | `final-run/swift-tsan.log` |
| PKCS#11 ASAN | **58/58, nessuna diagnostica runtime** | `final-run/pkcs11-asan.log` |
| PAdES ASAN | **79/79, nessuna diagnostica runtime** | `final-run/pades-asan.log` |
| PKCS#11 TSAN | **58/58, nessuna diagnostica runtime** | `final-run/pkcs11-tsan.log` |
| Python packaging/tooling | **14/14 (10 packaging + 4 runner)** | `final-run/packaging.log` |
| Packaging nuovo Debug/Release | **Due bundle nuovi da 276585c; audit/minimo 13.0/codesign/rilocazione superati** | `verified-package-debug.log; verified-package-release.log` |
| Contratti nei bundle finali | **20/20 (10 per configurazione), 0 fail** | `verified-packaged-debug.log; verified-packaged-release.log` |

I test mirati e i sanitizer ripetono casi del completo: **19 nuovi metodi XCTest distinti**, **12 nuovi casi nativi PAdES**, **4 nuovi test Python** (35 nuovi controlli di suite; le integrazioni bundle supplementari non sono sommate). I numeri nativi sono casi interni a un target CTest per suite.

ASAN usa `detect_leaks=0`: nessuna conclusione di assenza di leak. Le librerie del prefix e i framework Apple non sono ricompilati con sanitizer; i mock runtime delle suite Swift non sono completamente strumentati. Gli harness nativi ricompilano shim/mock con i flag specificati. Non è una certificazione del middleware/hardware.

### Regressioni incrociate e contratti conservati

1. Snapshot approvato → preflight typed → firma PAdES valida → verifica finale → output esclusivo: completo Swift e helper impacchettati.
2. Perms/unsupported source → rifiuto prima del provider/operazione privata, nessun output: casi nativi e policy comune; firme incrementali supportate ancora ammesse.
3. Destinazione sostituita dopo il controllo del job → mismatch sul descriptor, nessun payload errato: regressione Swift e native.
4. Provider pubblico lento, nuovo contesto → cancellazione reale scan/DER/subprocess e solo approvazione corrente: SigningReview/worker.
5. Drop lento, picker o nuovo drop → risposta vecchia scartata: VerificationDropLifecycleTests.
6. Runner su sorgente/build puliti, nessun mkdir manuale, zero skip nel completo: results.json finale.
7. Secure Batch PIN sintetico, ritiro incerto della sessione, autenticazioni USER/CONTEXT e binding 14-A: completo e sanitizer; nessuna modifica al PIN batch.
8. PAdES visibile Rotate=90, CropBox traslato e UserUnit: suite default/orientation/output con OpenSSL, struttura AP e confronto Poppler; tutte le rotazioni restano coperte.

SG-01/14: staging privato, readback, rename esclusivo, cleanup proprio e output incerto preservato. SG-02: ownership/lease/teardown e assenza di retry immutati. SG-03/04: policy comune, DER approvato e verifica matematica finale obbligatori. SG-05: snapshot e consenso congelati. SG-06: worker isolati e supervisione. CQ-01/02/03/06 e INV-01/02 della 14-A restano coperti dalle regressioni, incluse le esecuzioni su componenti realmente impacchettati v2/v5.

### Run iniziali non verdi e correzioni

Le prove rosse valide sono identificate sopra. Restano nei log anche tentativi intermedi non validi come prova del prodotto: nome errato di una costante Swift durante compilazione; fixture snapshot non privata o non resa scrivibile per la prova di tampering; locator di output non canonico; helper non esplicitato in due invocazioni parziali (una aveva uno skip); include C di `kill` assente nel nuovo harness. Corrette le cause e ripetuti i test. È stato corretto anche un limite aggiuntivo EOF/page-count inizialmente troppo restrittivo per il contratto esistente. Il primo TSAN è terminato con SIGABRT dopo SEGV nell'enumerazione dei moduli del runtime sanitizer durante `MockModule.deinit`/`dlclose`; riprodotto isolando SigningJobTests. I due test raw sincroni ora completano il teardown checked del proprio modulo single-owner prima di rilasciare l'handle loader della fixture. Il gruppo isolato passa 13/13. Non sono soppressi warning, disabilitati unload o modificati deinit/teardown del prodotto: la semantica asincrona resta esercitata nei test lifecycle e il nativo viene nuovamente verificato con TSAN. Il run iniziale rimane fallito e i target nativi che non aveva raggiunto non sono dichiarati eseguiti in quel run. Nessun risultato di un binario precedente dopo build fallita è usato come prova finale. Il runner completo non ha skip inattesi o suite mancanti.

### Prestazioni limitate al cambiamento

Cinque avvii isolati del nuovo preflight su PDF sintetico da 599 byte nei bundle nuovi: mediana Debug **10,34 ms**, Release **9,61 ms**, inclusi avvio processo e hash. L'audit conferma zero ulteriori autenticazioni. Sono misure diagnostiche su un documento minuscolo, non una stima per documenti reali/grandi o un confronto prestazionale generale. Il test da 1001 pagine resta entro la deadline del preflight. Nessun serializer CMS, cache globale, parallelismo sul token o rimozione di riletture d'integrità; CQ-08/CQ-10 non affrontati.

## Registro finding e commit locali

| Finding | Stato | Test | Commit | Residuo |
| --- | --- | --- | --- | --- |
| CQ-04 | Corretto nel profilo ammesso | red pre-auth, 4 Swift + 4 nativi, completo/bundle | `9de856c`, `85d8241` | Profili ulteriori e verifica finale sempre necessari |
| CQ-05 | Corretto per piani approvati | red directory sostituita, 5 Swift + 8 nativi, no-overwrite | `7db8db4`, `81de711` | Cambio post-commit incerto, file conservato |
| CQ-07 | Corretto | red attesa obsoleta, 3 nuovi + regressioni, scan/DER supervisionati | `41a6569`, `fb1fb6a` | Limiti kernel/reaping espliciti, nessuna cancellazione privata nuova |
| CQ-09 | Corretto | red cancel NSItemProvider, 5 nuovi lifecycle, completo | `3a8b521` | Integrazione manuale della finestra da collaudare |
| CQ-13 | Corretto per ambiente preparato | red copia pulita, 2 Swift + 4 Python, runner completo | `c8797e1`, `6baa4b5`, `276585c` | Prerequisiti locali e WindowServer espliciti |

HEAD completo di codice/test/tooling verificato: **`276585cc04f0505276464aa1edc628a0ea88755e`**; ultimo commit produttivo **`fb1fb6a`**. Entrambi i bundle finali nuovi dichiarano `276585c` nei manifest (sorgente tracciata pulita, arm64, minimo Mach-O 13.0); dopo le integrazioni, hash annidati e codesign deep/strict sono ancora validi. L'HEAD completo finale, inclusi i documenti, è nel `git-final.json` della consegna, per evitare un hash auto-riferito nel rapporto versionato.

## Residui, verifiche manuali e decisione

Rimangono **aperti CQ-08, CQ-10, CQ-11, CQ-12, CQ-14**: I/O e lifecycle UI generali, costo memoria/copie, percorsi renderer/verifica legacy, script build legacy, ownership/Sendable e migrazione strict concurrency. Nessuna chiusura indiretta viene rivendicata. Restano i limiti dichiarati di INV-01/02 su firmware/identità fisica, i profili PDF ulteriori e le valutazioni trust/revoca/qualificazione escluse dal prodotto attuale.

Non eseguiti: hardware reale, middleware installati, GUI click-test umano, runtime macOS 13/14, Intel, notarizzazione/Developer ID, installazione/distribuzione, UBSAN e profilo prestazionale generale. Necessari prima di distribuire: prova manuale del cambio contesto e chiusura finestra, drop lento/picker/cancel/riapertura, destinazione rinominata con avviso incerto, CAdES/PAdES/batch e appearance Rotate=90/CropBox/UserUnit in GUI; collaudo dedicato sui sistemi/hardware che si intende dichiarare supportati, con autorizzazione separata.

Git finale: branch 14-B, tutti i cambiamenti richiesti in commit locali; working tree/index tracciati puliti dopo il commit documentale. I quattro rapporti originali restano non tracciati, con SHA-256 identico. Ref protetti, worktree, vecchi bundle, versione e build preservati; nuovi bundle solo in `work/hardening14b/bundles/`. Manifest, hash e stato esatto nelle evidenze. Nessuna operazione remota.

**READY FOR 14-C: YES**, per proseguire l'hardening: cinque finding richiesti corretti e testati, suite obbligatorie complete e verdi, nessuna regressione nota introdotta. Non equivale ad approvazione di una release o a una nuova dichiarazione di compatibilità hardware. **14-C non avviata.**
