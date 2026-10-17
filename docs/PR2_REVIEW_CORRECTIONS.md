# PR #2 — Correzioni della code review

Partenza: `e06bb4d`, branch `codex/signum-beta-foundation`, 17 ottobre 2026.
Letti metadati e commenti della PR #2, inclusa la review
https://github.com/tiertoast/Signum/pull/2#issuecomment-6234902113.
Nessuna modifica remota: PR lasciata in bozza, nessun commento/risoluzione inviato.
Review locale originale non tracciata preservata. Nessun accesso a HalleyMac,
nessuna modifica a main, nessun uso di hardware o credenziali personali.

## P2 — Classificazione degli esiti PAdES

**IMPLEMENTATO:** protocollo interno v4, con risposta limitata e UUID del job.
Il helper riserva un descriptor CLOEXEC per la risposta prima di caricare il
vendor e devia stdout/stderr ordinari a `/dev/null`. Il v3 resta disponibile per
compatibilità con le prove precedenti; l'app richiede v4, quindi un vecchio helper
non può essere interpretato come un rifiuto pre-autenticazione confermato.

La risposta distingue published, rejectedBeforeAuthentication, uncertain.
Il flag «autenticazione possibile» viene impostato prima di chiamare il bridge
privato e non viene azzerato dopo un errore. Un rifiuto pre-autenticazione viene
comunicato solo dopo l'unwinding/cleanup; crash, timeout, annullamento durante il
processo e risposte assenti/malformate/estranee restano incerti. Anche la presenza
di una destinazione dopo un'interruzione conserva l'incertezza e il file.

Destinazione già esistente, parametri locali invalidi e lancio fallito restano
errori ordinari. La cancellazione prima dell'avvio resta cancellazione. Busy o
certificato sostituito sono errori ordinari soltanto con la prova v4 corretta e
nessun output finale. Nessun retry PIN o cambiamento alla semantica RSA/CMS/PDF.
Il canale evita rumore/exit code ambigui, non è una sandbox contro vendor ostile.

**TESTATO:** 10 test Swift del trasporto/mapping, più un test nativo end-to-end
attraverso `SignumPAdESHelper.sign` con quattro scenari (busy, certificato diverso,
errore Sign, successo). Busy: zero Initialize/Login; certificato diverso: zero
Login/Sign; negli altri casi esattamente un Login e un Sign, senza retry. Esiti
mappati all'errore finale usato dall'app; nessun output sugli errori, originale
invariato e snapshot eliminato. Suite PAdES Debug **63/63**, positivo nativo ora
verifica anche published e UUID v4. Log locali `pr2-pades-debug.log` e
`pr2-pades-mapping-swift.log` in `.build/reliability/evidence`.

## P2 — Provider visibile e selezione attiva

**IMPLEMENTATO:** `ProviderSelection` contiene in un unico valore percorso,
provider canonico accettato, generazione discovery, token, slot, certificati,
DER/assessment/identità e PIN. La Binding del percorso sostituisce immediatamente
il valore, richiede cancellazione della vecchia discovery e rende inapplicabili
i suoi callback. Anche un nuovo Carica svuota la selezione prima dell'avvio:
annullarlo non ripristina il vecchio provider. Il percorso canonico viene
accettato soltanto per la stessa generazione e lo stesso testo visibile.
`canSign` e la creazione del job usano entrambi questa provenienza validata;
nessuna risoluzione filesystem o chiamata vendor viene aggiunta al main thread.

**TESTATO:** quattro test del modello effettivamente usato dalla View: cambio A→B
seguito da discovery annullata; risposta vecchia dopo A→B→A; binding fra percorso
alias visibile e canonico solo con richiesta fresca; cambio slot che cancella
cache certificati/PIN. **4/4** riusciti (`pr2-provider-swift.log`). La GUI non viene
avviata automaticamente: questi sono test della logica della selezione, non click
registrati sulla View. Gli input di un job già approvato rimangono immutabili.
