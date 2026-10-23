# Signum 0.7 — Native Experience · Build 2

Digital signatures. Simply native.

23 ottobre 2026 · `feature/signum-0.7-ui-redesign` · PR #8.
Base di partenza: `bc7da6c` (Build 1). STOP alla consegna per collaudo manuale.

## Workspace ridisegnato

Sidebar nativa Firma / Verifica / Dispositivi; impostazioni dalla toolbar e dal
comando macOS Impostazioni… (⌘,). Documenti al centro, selezione ordinata tramite
schede, PDFKit grande e inspector destro. CAdES mostra il PDF verificato in sola
lettura; non visualizzabili: nome, formato, dimensioni, senza contenuti inventati.
PAdES mantiene il pane di posizionamento/aspetto originale e richiede la conferma
dell'anteprima pronta prima dell'approvazione. Per più PDF ripetere su ogni file.

Firmatario, dispositivo, formato e destinazione sono normalmente visibili.
Opzioni, certificato e diagnostica sono richiudibili; i formati avanzati restano
nei menu e nelle opzioni. I GroupBox dell'inspector sono stati sostituiti da
sezioni semplici. Burgundy #64313E, tipografia/controlli e toolbar nativi; nessuna
API Liquid Glass obbligatoria, quindi resta il target macOS 13.

main.swift contiene ora solo il bootstrap. Shell e azioni sono in SigningWindow;
workspace, inspector, esiti e refresh hanno file distinti. Nessuna duplicazione
del motore. Nessun cambiamento a SignumCore, trust, verifica o HalleyMac.

## Due correzioni prioritarie

Aggiorna dispositivi (arrow.clockwise) è sempre presente nella toolbar. Usa il
discovery pubblico esistente senza PIN; esclude richieste concorrenti, rifiuta
risposte obsolete e conserva il route ID se ancora presente e localmente idoneo.
È disabilitato esplicitamente durante lavori e sessioni approvate, senza modificare
il loro contesto. Indicatore discreto durante la ricerca.

Gli esiti terminali vengono copiati in valori di presentazione (nome, formato,
stato, dettaglio, output), senza conservare job, snapshot, approvazione o segreti.
Solo dopo la conclusione di tutti i documenti, nessun lavoro attivo, nessun PIN
in invio, nessun contesto autenticato e nessuna verifica d'esito richiesta, la UI
chiama il reset già esistente. Nessuna firma viene avviata dal completamento.
Gli errori e gli annullamenti restano visibili; gli esiti incerti richiedono prima
l'esplicita presa visione già prevista dalla 0.6. File completati: Apri file firmato
e Mostra nel Finder. Gli esiti precedenti sono accessibili anche nella nuova
selezione. Non è un archivio persistente: gli esiti restano per la vita della finestra;
gli output su disco restano invariati.

## Test eseguiti

- Regressione Swift: **113 test**, 0 errori, 0 skip. Include consenso, PIN, firma
  multipla/autenticata, annullamento, errori, selezione certificati, review,
  workspace, PAdES, overlay e i nuovi test di refresh/rilascio sessione.
- Dopo la correzione del rendering: **15 test finali mirati**, tutti passati
  (sottoinsieme ripetuto più il nuovo test raster dei colori PDF).
- **21 test Python** packaging/runner passati. Build 2 ha un'identità diversa
  anche da Build 1; le identità 0.6 e Build 1 restano invariate.
- I nuovi test coprono: tutti gli output di tre firme sintetiche verificati dopo
  reset, nuova selezione, blocco con documenti pendenti, callback operativa ancora
  viva, autenticazione non ancora ritirata, annullamento, errore conservato,
  esito incerto prima/dopo presa visione, sblocco automatico della finestra,
  refresh concorrente/obsoleto, route rimosso e selezione conservata.
- PDF CAdES: vero PDFView senza overlay PAdES, bytes snapshot immutati. Test nativo
  di layout per tutte le sezioni, Light/Dark e minimo 980×650; PIN visibile con
  32 documenti. Test PAdES e cambio formato preservati.

In collaudo visivo il PDF senza colore iniziale esplicito perdeva il testo in
Dark. La pagina PDFKit ora inizializza nero il proprio stato grafico; PDFKit
continua a renderizzare colori espliciti e annotazioni. La correzione è limitata
all'anteprima, senza riscrivere PDF o snapshot. Il test raster verifica anche il
rosso esplicito, e lo screenshot Dark conferma la leggibilità del PDF sintetico.

Build Debug e Release complete con packager locale, firma ad hoc, audit librerie,
macOS minimo e rilocazione. Controlli sintetici dei bundle e verifica DMG registrati
nei log consegnati. Le build consegnate sono prodotte dal commit pulito indicato
in BuildManifest.json. Xcode 27.1 usa ancora i suoi componenti estratti localmente
per actool (solo ambiente strumenti, come Build 1).

## Screenshot e collaudo interattivo

Screenshot nativi Light/Dark della build candidata con la stessa UI della consegna,
PDF sintetico, senza firma privata. Verificati apertura documento, menu formati,
resa Light/Dark, inspector e refresh dalla toolbar senza PIN. Tema originale Light
ripristinato. Le interruzioni intermittenti `Sky Computer Use native pipe closed`
hanno limitato il collaudo interattivo di PAdES e scorciatoia impostazioni:
non sono dichiarati superati. I test automatici relativi rimangono verdi.

Non è una regressione completa del motore né un test su macOS 13/14 reali o una
sessione di firma con PIN personale. Nessuna firma reale è stata eseguita.

## Consegna e checklist manuale

`Signum 0.7 Development Preview — Build 2.app`, versione 0.7.0/build 2,
ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B2`. Nome, preferenze e cache
sono separati da Beta 0.6 e Build 1. Copiare dal DMG in Applicazioni mantenendo il
nome completo. Apple Silicon, firma ad hoc, nessuna notarizzazione Developer ID.

- [ ] Firmare un documento con token reale; verificare esito, Apri file firmato,
      Mostra nel Finder e accesso immediato a Verifica/refresh/nuova selezione.
- [ ] Firma multipla: nessuno sblocco prima dell'ultimo output e del teardown.
- [ ] Annullamento durante l'operazione; output esistente, errore, esito incerto:
      nessuna ripetizione automatica, dettaglio conservato, presa visione richiesta.
- [ ] Rimuovere/reinserire token, refresh ripetuto, selezione conservata se valida;
      nessun PIN durante la sola ricerca, comando indisponibile se approvato.
- [ ] CAdES PDF, PAdES con aspetto grafico, conferma di ogni anteprima, più file,
      cambio selezione, formati avanzati, cartella comune e nomi senza overwrite.
- [ ] Ridimensionamento, tastiera, ⌘,, VoiceOver, apri/chiudi opzioni e dettaglio
      documenti; navigazione e app affiancate con 0.6 e Build 1.

Nessuna Action, merge, tag, release o modifica a HalleyMac. STOP Build 2.
