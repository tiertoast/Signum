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
