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

## P3 — Versione visualizzata

**IMPLEMENTATO e TESTATO:** la View legge `AppVersion.label`, derivata da
CFBundleShortVersionString e CFBundleVersion del bundle effettivo; nessuna label
Alpha/Beta inventata. Eseguibile senza metadati: «Build di sviluppo».
Resources/Info.plist aggiornato a 0.3.3/build 1. Due test verificano cambio di
versione/build senza costanti UI e fallback senza metadati: **2/2** riusciti
(`pr2-version-swift.log`). Il packager verrà allineato alla stessa fonte.

## Decisione macOS 13/14

**DECISIONE IMPLEMENTATA:** mantenere **macOS 13.0 come target di build**, senza
ridurre protezioni. Il precedente 14.0 era imposto dalla ricetta nativa, non da
un requisito dimostrato delle API esaminate. I precedenti eseguibili Swift erano
già minos 13.0; ora anche helper e PoDoFo vengono ricompilati a 13.0.

Analisi locale: Package.swift rimane `.macOS(.v13)`; SwiftUI usa gli overload
onChange precedenti a macOS 14, senza richiedere i nuovi overload. PDFKit,
Security, CoreGraphics e la supervisione Process non hanno richiesto API esclusive
14 durante questa compilazione. Gli header SDK indicano disponibilità 10.12 per
fclonefileat/renamex_np/renameatx_np. Non sono stati rimossi O_NOFOLLOW_ANY,
controlli descriptor/inode, ACL, CoW, SHA-256, lease, verifica delle firme,
pubblicazione esclusiva o isolamento dei processi. Non è stato aggiunto alcun
fallback meno sicuro per un filesystem/flag non supportato: resta fail closed.

Resources/Info.plist è la fonte del target per entrambe le ricette native.
Il packager conserva versione/build delle risorse e **rifiuta** un prefisso
nativo più recente o qualunque Mach-O sopra il minimo dichiarato, invece di
alzare silenziosamente Info.plist. Manifest distingue minimo dichiarato e misurato.
Due confronti separati impediscono che metadati sbagliati mascherino un binario
incompatibile. La vecchia `.build/beta-native-v1` a target 14 è stata provata e
rifiutata prima della build/pubblicazione; non viene alterata o riutilizzata.

**TESTATO:** ricompilazione completa offline, da archivi SHA-256 già fissati,
in `.build/pr2-native-macos13`. Debug e Release: tutti e cinque i Mach-O
(GUI, CLI, worker, helper PAdES, PoDoFo) hanno minos **13.0**, come Info.plist.
BuildManifest e Info.plist concordano su **0.3.3/build 1**. Audit byte/stringhe,
load command, chiusura dylib, firma annidata e rilocazione passati. Dieci test
Python coprono anche prefisso troppo recente, binari 14/27 o 13.0.1 contro
minimo 13.0 e coerenza Package/risorse/ricetta (`pr2-packaging-tests.log`).

**NON TESTATO:** esecuzione su macOS 13 e 14, Mac pulito e middleware reale.
Host effettivo: macOS 27.2 (26B5101f), Swift 6.4, SDK macOS 27.0. Il target e
l'audit Mach-O dimostrano coerenza di build, non una matrice runtime già validata.
Il supporto Beta su 13/14 resta subordinato a test su quegli OS: avvio GUI/helper,
ACL incluse deny-delete, snapshot/clone APFS, cancellazione, crash/lease e firma
manuale sintetica. Non si deduce sicurezza del sistema operativo dal solo target.

Durante il primo tentativo di packaging la nuova variabile del target era
sovrascritta da un percorso dylib del ciclo: TypeError, staging eliminato e nessun
bundle finale. Rinominata `declared_target`; entrambi i packaging completi ripetuti
con successo. Nessuna verifica fallita lasciata come evidenza di riuscita.
