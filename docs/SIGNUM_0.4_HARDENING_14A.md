# SIGNUM 0.4 — Hardening 14-A

Digital signatures. Simply native.

## Baseline e stato iniziale

Repository `tiertoast/Signum`, workspace `/Users/andreaoregioni/Developer/Signum-Reliability`.
Baseline esatta `c45bb006b8ab00c5f80bcb03a25232abf002e2e6`, Build 13, branch sorgente `codex/signum-0.4-ux-refinement-b13`.
Branch dedicato `codex/signum-0.4-hardening-b14a`, creato dalla baseline. Diff iniziale tracciato vuoto. Quattro documenti non tracciati preservati, incluse le due review lette integralmente. Worktree preesistenti: questo workspace e `/Users/andreaoregioni/Signum` su main; quest’ultimo solo identificato tramite Git, non modificato. Main locale `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70`.
Inventariati i bundle preesistenti in `build` e `.build`; le esecuzioni usano una nuova copia sorgente senza Git e build scratch esterne. Nessun push, fetch, PR, tag, release o workflow remoto. Versione distribuita invariata.

## Registro finding e milestone

### CQ-01 — corretto

Confermato il passaggio indiscriminato di `manualPaths` dalla finestra. Estratta una policy locale dei trigger e riprodotto il comportamento precedente: il test fallisce in cinque assertion con le preferenze salvate. La policy non legge più le preferenze per autorizzare esecuzione: all’apertura solo candidati noti; Carica manuale autorizza il percorso scelto per questa finestra; Cerca nuovamente ripete noti e autorizzati di sessione; Rimuovi revoca anche l’autorizzazione. Nessuna autorizzazione persiste alla riapertura. UI allineata.
`expectedPaths` deriva dal piano autorizzato completo: selezione dell’unica route idonea solo dopo completamento. Guard sulla generazione invariato. Test mirato prima: 1 test, 5 assertion fallite; dopo: 29 test discovery/selezione/consenso passati, nessuno skip.

## Esecuzione ed evidenze

Log e runner nella consegna della chat, `outputs/evidence`; scratch `work/hardening/source`. Il runner registra comando, exit e durata con watchdog di processo. Prerequisito CQ-13 predisposto solo nello scratch: `.build/04stabilization-b13/evidence`. I rapporti originali non vengono alterati.

### CQ-02 — corretto

Un solo ritiro conserva il fallimento di finish sotto lock, prima di abort e azzeramento. Lo stesso checkpoint registra il fallimento della chiusura finale. Il flag non può tornare falso; l’errore primario mantiene la classificazione documento e il coordinatore espone separatamente cleanup incerto e blocco delle autorizzazioni. Nessun retry. Un protocollo interno ristretto consente una connessione fittizia, senza nuovo manager o livello runtime.
Regressione con primo output CMS sintetico verificato, errore locale prima del secondo submit e finish fallito: sul catch precedente quattro assertion falliscono (flag, propagazione, avviso, stop ripetuto); dopo correzione 48 test batch/Secure Batch PIN passati, zero skip. I primi tentativi dell’harness avevano un locator temporaneo non canonico: corretta la fixture e ripetuta la prova prima/dopo; quei run falliti restano nei log e non provano la regressione applicativa.

### CQ-03 — corretto

Scelta A: validazione coerente del framing esistente, senza nuovo protocollo. PAdES accetta UTF-8 1…64 byte senza NUL/CR/LF; il codec aggiunge solo LF. Gate comune del coordinatore, UI e bridge usano lo stesso contratto per i documenti PAdES. Il dominio CAdES resta invariato. Il lettore nativo rifiuta CR/NUL, overflow, input vuoto e EOF prima del terminatore; gestisce EINTR senza trasformare i byte. Nessun valore è registrato.
Regressioni prima: codec Swift fallisce su CR/LF; codec C++ fallisce sul frame incompleto. Dopo: suite Swift contratto/processo/interazione passata e CTest PAdES completo 66 casi passato, zero skip. Coperti input ordinario, UTF-8, limite esatto, oltre limite, vuoto/NUL/CR/LF, incompletezza e mapping delle risposte malformate/obsolete nella suite processo esistente.

### CQ-06 — corretto

Le due primitive one-shot rifiutano zero e lunghezze superiori alla capacità prima di esporle. Recupero DER: query 1…65536, secondo risultato entro capacità e limite DER; errore e cleanup fallito azzerano lunghezza e buffer utilizzabile. Verificate anche dimensione/valore dell’attributo booleano di autenticazione; batch mantiene il controllo oltre capacità e rifiuta anche firma vuota. Nel callback C++ e nel recupero DER è presente una seconda guardia prima di resize/intervalli.
Mock scalar-only, nessuna scrittura oltre capacità: regressione prima conferma rifiuto mancante con capacità 8192/ritorno 8193 (anche zero era accettato). Dopo: 58 casi PKCS#11, 66 PAdES e 17 Swift policy/lifecycle/Secure Batch nativo passati, zero skip. Matrice zero/valida/esatta/+1/unavailable, sentinel oltre buffer e azzeramento, errori CKR delle regressioni esistenti. Un errore iniziale di compilazione nella firma del helper test C++ è corretto nell’harness e conservato nei log.

### INV-01 — corretto, limite temporale esplicito

I due entry point checked conservano il gate pre-login e rileggono oggetto, DER e policy nella sessione autenticata dopo USER login, prima di cercare la chiave e SignInit. Le primitive raw restano legacy di test esplicite. Ordine: USER → certificato/policy → chiave → SignInit → eventuale CONTEXT_SPECIFIC → Sign. Nessun retry.
Riferimento primario: [PKCS#11 v2.40, CKA_ALWAYS_AUTHENTICATE e C_Login](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html). Lo standard colloca CONTEXT_SPECIFIC sull’operazione iniziata; non si aggiungono arbitrariamente FindObjects dopo quel punto. Limite: non si attesta immutabilità dell’oggetto nel firmware dopo l’ultimo check; resta la verifica crittografica contro DER approvato e il gate pre-pubblicazione.
Test a stati su entrambi i meccanismi: DER coerente, sostituito, assente, policy mutata, sessione invalidata, CONTEXT obbligatorio. Prima: 24 assertion falliscono per SignInit/CONTEXT/Sign raggiunti nei casi non ammessi. Dopo: 32 test Swift pertinenti, 58 casi PKCS#11, 66 PAdES passati, zero skip. La fixture strict rifiuta FindObjects con operazione Sign attiva.
Microbenchmark locale scalar-only, 100 firme checked con provider sintetico e policy reale: prima 0,005583 s, dopo 0,008558 s (circa +0,030 ms per operazione). Una singola coppia di misure, esclusi hardware e latenza vendor; non è una soglia prestazionale né una misura dell’app.

### INV-02 — corretto per le proprietà osservabili, limiti espliciti

Il job conserva un contesto immutabile versionato: path canonico, device/inode/size/mtime/ctime del middleware, origine automatica/manuale, slot, label/manufacturer/model/reader/serial del token, Object ID, SHA-256 DER, route ID e generazione discovery. Preparazione/riepilogo/freeze GUI trasportano lo stesso valore; la GUI rifiuta piani senza binding anche all’esecuzione. Il DER originale e la verifica matematica restano invariati.
CAdES: worker one-shot v2 richiede il contesto completo coerente con i campi top-level, acquisisce lease, ricontrolla il modulo prima di caricarlo, e modulo/token prima di autenticare; risponde con versione/contesto validati e teardown checked. Nessun downgrade a v1. PAdES: richiesta v5 richiede contesto v1 pubblico, limitato a 16 KiB e 20 campi delimitati (testi codificati hex, interi con limiti), nei soli argomenti pubblici. Il PIN rimane sulla pipe nel framing corretto da CQ-03. Il consumer ripete identità file e token prima di leggere/inviare il PIN; per origine automatica riusa la policy ACL C e controlla proprietà root/POSIX degli antenati canonici. È stata aggiunta alla compilazione CMake la sorgente della policy ACL già esistente, senza nuove dipendenze. Normalizzazione UTF-8/whitespace dei metadati coerente con discovery per middleware conformi.
Legacy esplicito: job con providerContext=nil = contratto locator/DER storico, worker v1 e helper PAdES v3/v4 per CLI/test/API esistenti. I marker v2/v5 richiedono il nuovo binding; un helper vecchio o risposta v4 a richiesta v5 fallisce, senza fallback. Il workflow GUI produce e ammette solo job con contesto.
Prima: il test con contesto atteso iniettato ma non trasportato vede firme anche per token/module/slot/Object ID diversi, a DER invariato. Dopo: test consumer con zero USER/Sign su mismatch, modulo sostituito rifiutato prima di Initialize; stessa route firma, CMS verificata; PAdES v5 invisibile e visibile ruotato pubblicano PDF verificati con originale immutato/no-overwrite. Test nativo dei campi malformati, limiti, metadata/slot e sostituzione inode. Test review/generazione obsoleta, context congelato, richiesta v2 incompleta, risposta v5 malformata/downgrade. Suite mirata: 25 Swift e 67 PAdES passati, più suite status aggiornata.
Limiti effettivi: seriali e metadata sono dichiarazioni del middleware; non attestano un’identità fisica universale, non collegano provider diversi allo stesso hardware, non riconoscono rimozione/reinserimento con tutte le proprietà identiche. La generazione prova la provenienza del consenso nel parent e viene trasportata come dato opaco, non interrogata nel dispositivo. Identità file non è una firma del binario, non copre tutte le sue dipendenze e non elimina ogni sostituzione concorrente privilegiata fra stat e dlopen. Le route cambiate e le risposte discovery obsolete sono rifiutate; non si promette continuità fisica. Metadati nativi non conformi a UTF-8 possono essere rifiutati dal binding PAdES anziché interpretati arbitrariamente. Nessuna compatibilità hardware nuova attestata.
Durante l’implementazione: errori di link della policy ACL e di qualificazione Rect/CoreFoundation corretti; run CTest eseguiti dopo una build fallita usavano gli ultimi binari disponibili e non sono prova dei sorgenti nuovi. I run f-native-build-verified/f-native-verified e f-swift-verified sono quelli validi dopo ricompilazione riuscita.

### CQ-02 — completamento del collegamento di ritiro al coordinatore

Nel controllo finale è stata coperta anche la chiusura dopo un errore locale di pubblicazione sul primo documento: la finestra ritirava il riferimento senza attendere l’esito osservabile dal coordinatore. Il nuovo ritiro marca sincronicamente il gate delle autorizzazioni, attende il teardown fuori main e propaga il flag persistente prima di liberare la capacità. Il percorso di continuazione usa lo stesso ritiro. Stato documento fallito e cleanup incerto restano distinti, senza cambiare l’output presente o ritentare.
Test con collisione sintetica creata dopo Sign, finish fittizio fallito e documento successivo mai eseguito: prima tre assertion falliscono (gate immediato, avviso e revisione esito), dopo 16 test di cleanup/integrazione batch passati. Il primo tentativo della nuova fixture aveva due contenuti identici, correttamente deduplicati dall’acquisizione: corretta la fixture prima della riproduzione valida. Questo è un ulteriore commit solo CQ-02, necessario a coprire anche l’uscita GUI senza continuazione.

## Regressioni finali effettivamente eseguite

Codice finale testato: `6cc90ab21917e0514fb3e4ca3e053c910d19caf0`; il successivo commit contiene esclusivamente questo rapporto. Host arm64, macOS 27.2 (26B5112a), Apple Swift 6.4; package tools/language mode non migrati. Prefix nativo preesistente `pr2-native-macos13/prefix` (PoDoFo 1.1.2, OpenSSL 3.5.4, FreeType 2.13.3): riutilizzato, non scaricato né ricompilato/autenticato indipendentemente.

Base evidenze: `/Users/andreaoregioni/Documents/Codex/2026-10-19/files-pasted-by-the-user-signum/outputs/evidence`.
Ogni `.log` registra comando e directory; `runs.jsonl` riporta exit e tempo parete; `TEST_RESULTS.md` e `test-runs-summary.json` classificano anche i run rossi e gli errori di preparazione, senza cancellarli.

| Controllo | Risultato finale | Log |
| --- | --- | --- |
| Swift completo senza filtri | **391/391**, 0 fail, 0 skip; 213,071 s test, 225,698 s complessivi | `final-full-swift.log` |
| Primo Swift completo prima dell’ultimo collegamento CQ-02 | 390/390, 0 fail/skip; resta prova di quel commit, non sostituisce il run finale | `full-swift.log` |
| Batch authentication / Secure Batch PIN | 47/47 esistenti + 2 nuovi cleanup, tutti inclusi nel completo e nei sanitizer | suite nei log Swift finali |
| PKCS#11 Debug | **58/58** casi, 1/1 target CTest, 0 fail/skip | `final-pkcs-debug.log` |
| PAdES Debug | **67/67** casi, 1/1 CTest, 0 fail/skip | `final-pades-debug.log` |
| PAdES Release | **67/67** casi, 1/1 CTest, 0 fail/skip | `final-pades-release.log` |
| Swift ASAN mirato, codice finale | **76/76**, 0 fail/skip; 88,536 s complessivi | `final-swift-asan.log` |
| Swift TSAN mirato, codice finale | **76/76**, 0 fail/skip; 247,634 s complessivi | `final-swift-tsan.log` |
| PAdES ASAN | **67/67**, 0 fail/skip | `pades-asan.log` |
| PKCS#11 ASAN | **58/58**, 0 fail/skip | `pkcs-asan.log` |
| PKCS#11 TSAN | **58/58**, 0 fail/skip | `pkcs-tsan.log` |
| Packaging Python | **10/10** | `final-packaging-unit.log` |
| Packaging reale Debug e Release | Due bundle nuovi ad-hoc verificati, audit dipendenze/deployment target/codesign, IPC sintetico CLI-worker, verifica helper e rilocazione | `package-debug.log`, `package-release.log` |
| Contratti bound nei bundle effettivi | **12/12** controlli: worker v2 con verifica RSA indipendente, mismatch pre-login, v2 incompleto, PAdES v5 verificato anche da verifica unificata, originale invariato, no-overwrite, token cambiato | `packaged-bound-e2e-fixed.log`, ripetuto con misure in `packaged-bound-e2e-performance.log` |
| Build strict concurrency da scratch nuovo | Exit 0; warning in 9 posizioni sorgente, famiglie CQ-14 ancora aperte | `strict-final-code.log`, `strict-warning-locations.txt` |

I run mirati/sanitizer ripetono casi del completo: non si sommano ai 391 test distinti. I numeri nativi sono casi interni a un target, non altrettanti target CTest. Le sorgenti C/C++ dei sanitizer nativi sono identiche tra il commit INV-02 e il codice finale, che modifica solo il ritiro Swift/UI.

ASAN: `detect_leaks=0`, quindi nessuna conclusione di assenza di leak. Nessuna diagnostica runtime ASAN/TSAN nelle esecuzioni indicate. Il worker normale è usato solo nel test di rifiuto mlock previsto dalla suite, perché i sanitizer possono intercettare mlock. I mock compilati runtime dai test Swift e le dipendenze del prefix non sono strumentati da quelle build Swift; i target nativi ricompilano shim e mock con i flag sanitizer. Non è una strumentazione completa di SDK/framework/vendor.

UBSAN, hardware reale, Intel, runtime macOS 13/14, notarizzazione/Developer ID, installazione pulita e prove di sleep fisico: **non eseguiti**. Nessun test richiesto per i sei finding rimane saltato; le verifiche hardware non vengono dedotte dai mock.

I due primi tentativi del controllo supplementare sui bundle sono falliti nell’harness: LibreSSL `x509 -pubkey -noout` scrive la chiave pubblica su stdout e non aveva creato il file richiesto dalla successiva verifica. Catturato esplicitamente stdout nel file pubblico, i 12 controlli sono passati in entrambe le ripetizioni. Non è stato un fallimento della firma né sono state alterate assertion o sorgenti del prodotto per far passare il controllo.

### Riproduzione e isolamento

La copia sorgente finale è stata materializzata con `git archive` dal commit locale sopra, senza altro checkout/repository. Build/test sotto la cartella nuova `work/hardening`; watchdog esterni per ogni invocazione (TERM e poi KILL dopo 3 s alla scadenza), nessuna scadenza osservata. Le copie preliminari includono i cambiamenti locali per le prove rosse prima del commit. I log riportano i comandi esatti per ciascuna copia. Il runner e l’harness dei bundle sono inclusi nella consegna delle evidenze.
Prerequisito ambientale CQ-13: creata esclusivamente nella nuova copia `.build/04stabilization-b13/evidence` prima del completo; esplicitati `SIGNUM_TEST_PADES_HELPER` e `SIGNUM_TEST_POPPLER`. Nessuna modifica al test CQ-13, nessuna sovrascrittura delle evidenze dell’utente. Il fallimento storico descritto nelle review rimane tale: non viene riscritto.
Per il packaging eseguito nella copia senza `.git`, `GIT_DIR` punta al metadata Git del medesimo repository autorizzato e `GIT_WORK_TREE` alla copia esatta: il packager usa solo letture rev-parse/diff. Entrambi i manifest attestano commit `6cc90ab…`, `sourceTrackedDirty=false`, versione `0.4.0`, build **13**. Bundle diagnostici nuovi in `work/hardening/bundles`; nessun bundle preesistente sostituito, nessun avvio dell’app con discovery reale. Gli smoke usano esclusivamente il mock sintetico.

### Prestazioni delle verifiche aggiunte

Oltre al microbenchmark post-login sopra, confrontate versioni legacy e bound dello stesso consumer confezionato, con chiamate alternate, chiave software e fixture nuove. Mediane, inclusi processo/I/O/verifica:

| Bundle | Worker legacy v1 / bound v2 (5 campioni ciascuno) | PAdES legacy v4 / bound v5 (3 campioni ciascuno) |
| --- | --- | --- |
| Debug | 12,570 / 13,606 ms | 17,138 / 17,367 ms |
| Release | 12,721 / 13,166 ms | 16,288 / 17,034 ms |

Delta osservato circa +0,45…1,04 ms per worker e +0,23…0,75 ms per helper in questa piccola prova locale. Non si attribuisce ogni differenza esclusivamente ai controlli, non si presume significatività statistica e non si trasferiscono i tempi al middleware reale. Nessuna cache globale, parallelizzazione delle firme o rimozione di controlli per compensare.

## Comportamenti e invarianti preservati

- SG-01/14: writer e rename esclusivo restano invariati; output verificato su readback prima della pubblicazione, nessun overwrite. Le guardie native fermano i risultati incoerenti prima dell’uso.
- SG-02: ownership Initialize/Finalize, lease, chiusura checked/quarantena e nessun Logout globale preservati; nuovo checkpoint nella sessione USER, nessuna autenticazione ritentata.
- SG-03: verifica CMS/PDF e profilo PAdES esistenti invariati; firme invisibili, visibili e ruotate esercitate anche con contratto bound.
- SG-04: stessa policy condivisa, DER approvato e verifica matematica finale; nessun algoritmo aggiunto.
- SG-05: snapshot, bytes approvati, job/appearance congelati e consenso invariati; il contesto dispositivo è ora parte del valore congelato.
- SG-06: esecuzione vendor nel worker/helper, timeout e supervisione preservati.
- Secure Batch PIN resta sperimentale opt-in CAdES; manifesti chiusi, erase/lifecycle e autenticazioni USER/CONTEXT esercitati da mock. CAdES singolo/batch, batch misti, PAdES grafico, selezione certificato, originali invariati, annullamento, esito incerto e verifica unificata coperti dal completo. Nessuna riprogettazione UI, renderer, snapshot o writer.

## Registro finale e commit locali

| Finding | Corretto | Test/evidenza | Commit | Residuo |
| --- | --- | --- | --- | --- |
| CQ-01 | Sì | red trigger + 29 mirati + completo | `892fb25` | autorizzazioni solo nella finestra/sessione corrente |
| CQ-02 | Sì | red errore composto e primo documento + 49 casi batch/cleanup nel completo | `ff7b5db`, `6cc90ab` | kill/teardown non confermato resta esplicitamente incerto |
| CQ-03 | Sì | red codec Swift/native, limiti/UTF-8, gate comuni e risposte | `cd29235` | PAdES rifiuta NUL/CR/LF prima del lancio |
| CQ-06 | Sì | red 8192/8193 + matrice 58 casi nativi + ASAN/TSAN | `e764b2d` | provider arbitrario non può essere certificato dai soli controlli scalari |
| INV-01 | Sì | red cambio dopo USER, 32 mirati, completo/native | `96740ab` | checkpoint prima di SignInit/CONTEXT; stato interno successivo non attestato |
| INV-02 | Sì, nel perimetro osservabile | red contesto ignorato, worker/helper/codec/generazioni, 12 controlli bundle | `0c9f93b` | identità fisica/continuità del token non attestata; vedere limiti sopra |

Tutti e sei i finding richiesti sono affrontati e verificati. Nessuno è lasciato bloccato o dichiarato risolto sulla sola analisi statica. Il registro originale resta immutato: CQ-04, CQ-05, CQ-07, CQ-08, CQ-09, CQ-10, CQ-11, CQ-12, CQ-13, CQ-14 rimangono fuori perimetro e non sono dichiarati risolti (8 P2 e 2 P3 residui nel registro complessivo). Dipendenze strettamente necessarie: seam fittizio per CQ-02; sorgente ACL C già esistente e versioni IPC per INV-02; niente nuove librerie o manager generici.

## Stato Git finale e conservazione

Branch `codex/signum-0.4-hardening-b14a`, sette commit di codice/test più il commit finale di questo rapporto. Dopo il commit del rapporto non restano modifiche tracciate pendenti; i quattro documenti originariamente non tracciati restano non tracciati e con SHA-256 identico. Il resoconto esatto di HEAD/status/commit è in `git-final.json` nelle evidenze di consegna (evita un hash auto-riferito in questo documento).
Main resta `be84a1e44f3b0bbe41bee9a2f46dbed36342ab70`; il branch sorgente resta `c45bb006b8ab00c5f80bcb03a25232abf002e2e6`. Worktree invariati; tutti i bundle inventariati preesistenti ancora presenti. Rapporti originali non alterati. Nessun push/fetch, merge, tag, release, GitHub Actions o modifica alla PR #3. HalleyMac e altri repository non sono stati letti o modificati. Nessun dispositivo, documento, PIN o credenziale reale utilizzato.

## Collaudi manuali successivi richiesti

1. Con fixture e provider sintetici: riapertura con A/B salvati, Carica manuale A, refresh, rimozione e riapertura; verificare testo e caricamenti effettivi, selezione unica solo al termine, nessuna selezione con discovery incompleta.
2. Nella GUI: firme CAdES/PAdES, appearance visibile/ruotata e batch misto; controllare riepilogo, certificato, consenso congelato, percorso output e gestione della collisione.
3. Con teardown sintetico non confermato, anche sul primo documento: stato documento distinto dall’avviso sessione, blocco delle nuove autorizzazioni fino alla presa d’atto, nessun retry automatico.
4. Prima di una distribuzione: collaudo dedicato sui sistemi macOS minimi e middleware/hardware che si intende dichiarare compatibili, in sessione separata esplicitamente autorizzata. I risultati della Build 13 non vengono estesi automaticamente al nuovo ordine post-login o ai nuovi contratti.

## READY FOR BUILD 14-B?

**YES — per proseguire la manutenzione correttiva.** I sei gate richiesti sono verificati, completo Swift e regressioni native/packaging/sanitizer richieste passano, nessuna regressione applicativa nota introdotta. I limiti tecnici di INV-01/02 sono espliciti. Questa risposta non autorizza distribuzione, release o un nuovo claim di compatibilità hardware; i collaudi manuali indicati restano necessari prima di tali decisioni. La milestone successiva non è stata avviata.
