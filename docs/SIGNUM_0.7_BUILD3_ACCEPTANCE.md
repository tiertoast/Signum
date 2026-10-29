# Signum 0.7 — UI Refinement · Build 3

23 ottobre 2026 · branch `feature/signum-0.7-ui-redesign` · PR #8.
Base: Build 2, commit `546d78d`. STOP alla consegna per collaudo manuale.

## Modifiche

Rifinitura del workspace esistente. Titolo Signum e comando sidebar sono nella
toolbar di sistema; rimossi il secondo titolo della sezione e la versione ripetuta.
Sidebar ideale 200 pt (180–240), inspector ideale 320 pt (300–340), separazione
ridimensionabile nativa; il resto dello spazio va ai documenti. Sidebar richiudibile
tramite il comando nativo. Riquadro vuoto centrato verticalmente. PDF grande e
selezione di più documenti conservati.

Inspector normalmente limitato a firmatario/certificato, emittente, formato e
destinazione. Un solo gruppo «Opzioni avanzate» raccoglie impostazioni secondarie,
autenticazione e stato diagnostico; i dettagli dei dispositivi/certificati si
consultano in Dispositivi. Gli errori di selezione e la ricerca incompleta sono
vicino al menu Firmatario, con Ripeti ricerca. L'indisponibilità sopravvenuta del
certificato conserva il messaggio specifico. Nessun blocco di firma è nascosto.

Barra inferiore separata dallo scorrimento: stato sintetico, consenso visibile
quando pronto e pulsante Firma… a tutta larghezza, ancorato al fondo. Nessun
GroupBox o dettaglio di autenticazione sotto il pulsante. PIN, annullamento,
interruzione, avvisi ed esito incerto restano nella barra operativa; firma in corso
ha un indicatore con testo esplicito. Aggiorna dispositivi resta in toolbar, con
nome stabile e i precedenti blocchi durante preparazione/firma/sessione approvata.

Accento Burgundy #64313E, colori/controlli/toolbar, simboli e font di sistema.
Nessun materiale Glass simulato né nuova API che alzi il requisito macOS 13.
Icona Refined di Icon Composer e fallback macOS già integrati, preservati.

Le modifiche operative sono di presentazione. Invariati approvazione e review,
autorizzazione, buffer PIN, esecuzione multipla, gestione errori, presa visione
dell'esito incerto e rilascio automatico della sessione della Build 2. Nessuna
modifica a SignumCore, trust, verifica, motore 0.6 o HalleyMac.

## Verifica locale

- Campagna Swift: 114 test mirati passati, zero errori/skip.
- Dopo le ultime rifiniture: 32 test UI/consenso/refresh/rilascio passati, zero
  errori/skip; 31 sono ripetizioni, uno è nuovo: 115 test distinti complessivi.
- Il nuovo test verifica i motivi di indisponibilità (documenti, certificato,
  consenso PDF) senza creare un'approvazione. Restano i test delle quattro sezioni
  Light/Dark a 980×650, PIN fuori dallo scorrimento con 32 documenti, PDFKit reale,
  cambio formato, colori PDF, errori conservati e sblocco sicuro della sessione.
- 21 test Python di packaging/runner passati; identità Build 3 distinta da 0.6,
  Build 1 e Build 2, con rifiuto di build non dichiarate.

Build Debug/Release e controlli del bundle/DMG vengono registrati nei log e in
TestSummary.json della consegna, insieme al manifest del commit pulito e ai checksum.
I controlli includono worker/helper/librerie rilocabili, firma ad hoc, contratti
sintetici del bundle, icona Finder/app e contenuto del DMG montato in sola lettura.
Nessuna GitHub Action è stata usata.

## Evidenza visiva e interattiva

Le PNG con suffisso `fixture` sono catture di finestre native con le vere viste
SignumWindow/inspector/workspace della build. Un eseguibile di collaudo separato,
non incluso nell'app consegnata, inietta solo documenti e certificato sintetici.
Non sono mockup, né provano l'uso di un token personale. La finestra host AppKit
può disporre la toolbar diversamente da WindowGroup: per la toolbar dell'app fare
riferimento alla cattura del bundle finale. I controlli nelle catture possono
avere l'aspetto inattivo nativo.

Controllati visivamente: vuoto centrato; PDF/certificato Light e Dark, testo nero
leggibile; PIN con tre documenti; operazione in corso; tre esiti completati;
980×650 con sidebar nascosta e ripristinata dal pulsante. Stato in corso: operazione
reale del coordinatore mantenuta in attesa dalla fixture, senza chiamata privata.
Esiti fixture: tre firme CAdES sintetiche, verificate prima della presentazione.

In più, click-through della UI con tre documenti sintetici: Firma… → approvazione
→ PIN esclusivamente sintetico → Firma → tre output completati → PIN scomparso,
menu e refresh nuovamente disponibili. La cattura `clickthrough` documenta questo
ultimo passaggio. Nessun PIN personale o firma con dispositivo reale.

Il servizio di controllo computer ha interrotto alcuni tentativi di navigazione
nel bundle con dispositivi reali (`Sky Computer Use native pipe closed`); non sono
conteggiati come verifiche superate. Il collaudo interattivo completo su quel
bundle e su token reale resta nella checklist. Tema di sistema non modificato:
Light/Dark delle fixture usa l'aspetto nativo limitato al processo di collaudo.

La cartella Screenshot e Confronto.html affiancano le catture Build 2 e Build 3.
Differiscono per host e stato del certificato: confronto di ingombri e gerarchia,
non misura pixel-per-pixel di una sessione identica.

## Installazione e checklist manuale

`Signum 0.7 Development Preview — Build 3.app`, versione 0.7.0/build 3,
ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B3`. Copiare dal DMG in
Applicazioni conservando il nome completo. Preferenze/cache separate da Beta 0.6
e dalle Build 1/2. Apple Silicon; firma locale ad hoc, non notarizzata Developer ID.

- [ ] Bundle finale: navigare Firma/Verifica/Dispositivi/Impostazioni, ⌘,, tastiera
      e VoiceOver; verificare sidebar, toolbar e accento Burgundy a finestra attiva.
- [ ] Ridimensionare finestra e divisori; nascondere/ripristinare sidebar; aprire
      Opzioni avanzate e scorrerle: Firma e PIN devono restare al fondo e visibili.
- [ ] Certificato assente, ricerca parziale, rimozione/reinserimento token: errore
      vicino al menu, Ripeti ricerca, nessun PIN richiesto dalla sola ricerca.
- [ ] PDF singolo/multipli in CAdES e PAdES, Light/Dark: contenuto leggibile;
      controllare/confermare ogni anteprima PAdES, aspetto grafico e cambio formato.
- [ ] Firma con token reale: conferma facoltativa, autorizzazione, PIN errato e
      corretto, annullamento; nessuna chiamata privata prima del consenso.
- [ ] Firma multipla: sblocco soltanto dopo ultimo esito e teardown; esiti visibili,
      Apri file firmato/Mostra nel Finder, nuova selezione e refresh immediati.
- [ ] Errore, annullamento, output già esistente ed esito incerto: dettaglio
      conservato, nessuna ripetizione automatica, presa visione quando richiesta.
- [ ] Avvio affiancato a Beta 0.6; prova su macOS 13/14 e hardware reale.

Nessuna Action, merge, tag, release pubblica o modifica a HalleyMac. STOP Build 3.
