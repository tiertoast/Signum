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
