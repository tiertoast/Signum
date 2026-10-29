# Signum 0.7 — UX Refinement · Build 6

23 ottobre 2026 · `feature/signum-0.7-ui-redesign` · PR #8.
Base Build 5: `4bc7393`. Consegna locale, STOP per collaudo manuale.

## Modifiche

Sidebar: testo a 14 pt, icone Burgundy #64313E in Light e variante di contrasto
#DCA1AD in Dark. Separatori di sistema discreti fra le righe, senza righe vuote
selezionabili. Restano NavigationSplitView, Liquid Glass, selezione e hide/show
nativi; nessuna superficie o simulazione Glass aggiunta.

Area documenti: un solo elenco compatto sopra l’anteprima, con nome, stato e
selezione nativa. Mostra fino a tre righe, poi scorre. Il + resta fuori dallo
scorrimento; drag & drop usa la stessa acquisizione. Eliminati schede, intestazione
con nome duplicato e DisclosureGroup Documenti ed esiti sotto il PDF.

Sotto l’elenco compare il percorso completo dell’output selezionato, comprensivo
di nome ed estensione e senza troncamento intenzionale. Prima del preflight è
etichettato Destinazione prevista; quando disponibile viene mostrato il nome
verificato del piano, comprese le collisioni, poi quello approvato/effettivo.
Il percorso nominale non viene presentato come un’autorizzazione alla firma.
Esito e dettagli apre un popover con i controlli esistenti di rimozione,
annullamento del singolo documento e informazioni tecniche. Errori bloccanti ed
esiti incerti rimangono visibili nei punti operativi. Attività recenti ed Elimina
tutto conservano il comportamento della Build 5.

Inspector: gruppi Firmatario, Formato e Destinazione con separatori sottili;
menu senza etichette laterali duplicate e della stessa larghezza. Sui sistemi
26+ viene usato buttonSizing(.flexible), perché il nuovo SDK rende i picker
intrinsecamente aderenti al testo; il fallback conserva il comportamento delle
versioni precedenti. Inspector ridimensionabile fra 300 e 440 pt.

Ogni formato mostra subito una descrizione sintetica in colore secondario.
Documenti successivi è nello stesso gruppo: Automatico segue il formato del
documento selezionato, oppure il formato iniziale se l’elenco è vuoto. Un valore
esplicito influisce solo sulle nuove acquisizioni, inclusi + e drop, e non
converte i documenti già caricati. Sono preservati identificativi, controlli
sui file, firme speciali e acquisizione dei contenitori ASiC. Le informazioni
tecniche restano contestuali; non essendoci altre impostazioni da nascondere,
non viene mostrato un gruppo Opzioni avanzate vuoto.

Barra Firma: dichiarazione richiesta al singolare/plurale sotto Pronto per la
firma. È testo dichiarativo dell’utente, non un esito di verifica, una
qualificazione eIDAS o un’attestazione automatica di validità giuridica. La
richiesta di approvazione effettiva e il legame con documenti, destinazioni e
certificato sono invariati. Dopo l’approvazione: PIN con focus automatico e
pulsanti Annulla/Firma affiancati; Invio conserva il medesimo percorso autorizzato.
Burgundy #64313E rimane il riempimento del pulsante principale.

## Risultati locali

- Test mirati su selezione, policy dei nuovi file, destinazioni complete e nomi
  con collisione, configurazioni dinamiche, consenso/review, PIN, annullamento,
  sessioni, cronologia, autenticazione multipla e interoperabilità ASiC.
  75 test Swift superati, nessun errore. Verificatori XMLSec e Python locali
  configurati per l’interoperabilità ASiC. 22 test Python di packaging superati.
  Esiti finali e log nella cartella della consegna.
- Test nativi di layout minimo Light/Dark, PIN accessibile con 32 documenti e
  anteprima PDFKit reale. Build Debug/Release, audit dei bundle e DMG verificato.
- Collaudo UI con middleware/certificato sintetici: cambio di documento aggiorna
  il percorso; P7S aggiorna descrizione ed estensione; override CAdES per i nuovi
  file conserva il P7S già caricato; + aggiunge un PDF e ne seleziona la preview.
- Approvazione di quattro documenti dalla GUI: focus automatico sul PIN, Invio
  completa la prima firma; Annulla lascia gli altri tre annullati e sblocca la
  sessione. L’output CMS è verificato e coincide con l’originale. Il suo hash
  rimane invariato anche dopo Elimina tutto. Nessun PIN personale impiegato.

Sources/SignumCore, librerie Trust, Tools e Package.swift invariati rispetto alla
Build 5. Nessuna modifica a HalleyMac, GitHub Action, merge o release pubblica.
L’icona Refined e l’isolamento della preview sono preservati: bundle ID V07.B6,
versione 0.7.0, build 6, arm64, minimo macOS 13, SDK collegato 27.
Firma locale ad-hoc; nessun Developer ID o notarizzazione.

## Screenshot e limiti

Catture reali senza ritocchi su macOS 27.2. I nomi contenenti fixture identificano
le viste di produzione ospitate in un harness AppKit, con dati sintetici. Le
catture Finale provengono dal bundle Release. La cartella Screenshot contiene
l’indice e distingue i diversi stati.

Il passaggio all’editor grafico PAdES ha causato la chiusura della connessione
del servizio di automazione: diagnostica SkyComputerUseService presente, processo
dell’app ancora attivo. Non viene dichiarato superato quel collaudo visivo;
anteprima/appearance restano coperte dai test locali mirati e dalla checklist.

Verificate due larghezze dell’inspector, circa 369 e 440 pt, nella finestra
compatta con sidebar aperta/chiusa. I trascinamenti del separatore tramite
automazione non hanno modificato la geometria; la fluidità del trascinamento
continuo rimane al collaudo manuale.

Non disponibili macOS 13–15 e 26 per esecuzione locale. Compatibilità protetta
tramite availability e minimo Mach-O, da completare con collaudo su quei sistemi.
Token, PIN reali e interruzioni hardware rimangono manuali. Le preferenze di
sistema modificate per le catture vengono ripristinate al termine.

## Checklist manuale

- [ ] Installare il DMG accanto alla Beta 0.6 e alle precedenti preview; verificare icona.
- [ ] Sidebar Light/Dark: testo, Burgundy, separatori, selezione nativa e Glass;
      hide/show e Riduci trasparenza, senza effetti sul documento.
- [ ] Aggiungere più documenti con + e drag & drop; scorrere e cambiare selezione.
- [ ] Verificare il percorso completo e il nome finale dopo preflight, con file
      omonimi già presenti e cartella comune diversa da quella degli originali.
- [ ] Controllare descrizioni e restrizioni di tutti gli otto formati.
- [ ] Automatico segue il formato corrente; l’override cambia solo i nuovi file;
      tornare ad Automatico e provare ASiC-S/ASiC-E senza convertire i precedenti.
- [ ] Ridimensionare inspector e finestra fino a 980×650: menu allineati, percorso
      leggibile, preview ampia, pulsante Firma e PIN sempre raggiungibili.
- [ ] Verificare la dichiarazione singolare/plurale e l’approvazione di documenti
      e destinazioni prima di qualsiasi richiesta privata.
- [ ] PAdES: scegliere PDF, regolare/confermare l’appearance e provare la firma.
- [ ] PIN: focus automatico, Invio, PIN errato, Annulla affiancato a Firma.
- [ ] Firma multipla: completare, annullare dopo un primo successo, disconnettere
      il token e gestire un esito incerto senza ripetere la richiesta privata.
- [ ] Apri/Mostra nel Finder dagli esiti; Elimina tutto conserva tutti i file;
      nuova sessione e Riduci movimento non alterano approvazioni o output.
- [ ] Ripetere fallback su macOS 13–15 e comportamento nativo su macOS 26.

Riferimento tecnico: [Apple, dimensionamento dei controlli nel nuovo SDK](https://developer.apple.com/documentation/macos-release-notes/macos-26-release-notes).

STOP alla consegna della Build 6 per collaudo manuale.
