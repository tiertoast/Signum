# Signum 0.7 — Native Glass & UX Polish · Build 5

23 ottobre 2026 · branch `feature/signum-0.7-ui-redesign` · PR #8.
Base Build 4: `ffa18aa`. Consegna locale per collaudo, STOP alla Build 5.

## Interventi

Sidebar e toolbar rimangono gestite da NavigationSplitView e dai controlli di
sistema. Rimossi lo sfondo dello scorrimento della sidebar e lo stile balanced
forzato. L’estensione dello sfondo è disponibile solo da macOS 26 e viene
esclusa con Riduci trasparenza: interessa una superficie di sfondo, mai le viste
interattive o i pixel del PDF. Su macOS 13–15 rimane lo split view nativo.
Non si aggiungono vetri artificiali o materiali al documento.

Il difetto principale era nel packaging: swiftbuild registrava SDK 13.0 nel
Mach-O anche compilando con SDK 27. Questo attivava il comportamento visivo di
compatibilità. La ricetta della sola preview 0.7 Build 5 ora passa al linker
l’SDK effettivamente selezionato da Xcode, verifica il risultato e mantiene
indipendente il deployment target 13.0. La ricetta 0.6 è invariata. Il confronto
visivo conferma i controlli e la toolbar di sistema aggiornati. Liquid Glass
segue le preferenze del sistema e lo stato attivo della finestra, senza opacità
forzate, NSVisualEffectView sovrapposte o animazioni custom della sidebar.

Opzioni avanzate ha un solo livello: il formato per i nuovi documenti è subito
accessibile, quando pertinente; le informazioni tecniche di formato e
autenticazione si aprono in un popover. Nomi dei formati aggiornati come richiesto
in menu, dettagli documento e ricevute, con mappatura solo nell’app. Identificativi,
restrizioni, destinazioni, approvazione, PIN e operazioni restano invariati.

Attività recenti sostituisce Operazioni precedenti/concluse. Elimina tutto
rimuove esclusivamente il vettore delle ricevute in memoria. Il metodo non
riceve un coordinatore né accede al filesystem; sessioni attive, approvazioni e
risultati incerti in attesa di gestione rimangono al loro posto. La transizione
allo stato vuoto usa SwiftUI e disattiva l’animazione con Riduci movimento.
Apri file firmato e Mostra nel Finder continuano a usare l’URL della ricevuta.

Impostazioni conserva le quattro schede e Indietro/⌘,. Generali usa sezioni e
colonne, senza il secondo DisclosureGroup sull’autenticazione. Rimossi i GroupBox
da Firma grafica e Trusted Lists; dettagli del catalogo consultabili in popover.
Burgundy #64313E e icona Refined sono preservati. Il Burgundy rimane esatto
sui pulsanti principali; una variante chiara #DCA1AD per i testi dei controlli
in Dark Mode evita il basso contrasto del Burgundy scuro sul fondo scuro.

## Verifiche locali

- 35 test Swift mirati, nessun errore: consenso/review, PIN/interazione,
  configurazioni dinamiche, layout minimo Light/Dark, anteprima PDFKit e sessioni.
- Copertura cronologia: svuotamento ripetuto; nuova sessione; nuova istanza vuota;
  originali e firme CMS verificabili dopo lo svuotamento; sessione approvata con
  esito incerto ancora presente; lavoro attivo non rilasciato.
- 22 test Python di packaging, nessun errore, inclusa distinzione fra SDK e minimo OS.
- Build Debug/Release, audit di dipendenze/rpath, firma ad-hoc, rilocazione,
  contratti del bundle e contenuto DMG: risultati e log nella cartella di consegna.
- Nessuna modifica a Sources/SignumCore, librerie Trust, Tools o Package.swift
  rispetto a ffa18aa. Nessun intervento su HalleyMac.

## Evidenze visive e limiti

Collaudo eseguito su macOS 27.2 Apple Silicon, SDK 27. Gli screenshot sono catture
reali, senza ritocchi. Quelli denominati fixture usano le viste di produzione
ospitate da un harness AppKit con documenti e certificato sintetici: servono per
PDF Light/Dark, attività completate e svuotamento, non certificano un token reale.
Gli altri provengono dal bundle preview. La cartella distingue le catture della
candidata con SDK corretto dalle catture del bundle finale.

Verificati apertura/chiusura sidebar, ⌘, e Indietro, quattro schede, nomi dei
formati, popover, zoom nativo, Riduci trasparenza attivo/disattivo. Preferenze
originali ripristinate: Chiaro, Riduci trasparenza disattivato. I tentativi di
ridimensionamento tramite trascinamento automatizzato non hanno cambiato le
misure; lo zoom nativo le ha cambiate. Il minimo 980×650 è coperto dai test e
dalla fixture compatta. Rimane da valutare manualmente la fluidità durante un
trascinamento continuo e il gusto estetico rispetto a Pixelmator.

macOS 13–15 e 26 non disponibili per esecuzione locale: fallback protetto da
availability e minimo del bundle verificato, collaudo su quei sistemi da completare.
Firma con token/PIN personali e interruzioni hardware restano al collaudo manuale.
Preview arm64 con firma locale ad-hoc, senza Developer ID o notarizzazione.

## Checklist manuale

- [ ] Installare Build 5 dal DMG accanto alla Beta 0.6; verificare icona Dock/Finder.
- [ ] Light/Dark, finestra attiva/inattiva, wallpaper e Riduci trasparenza:
      controllare sidebar, titolo, toolbar e leggibilità senza vetro sul PDF.
- [ ] Mostrare/nascondere e ridimensionare sidebar e finestra, fino a 980×650;
      verificare scroll, preview, Aggiorna dispositivi e barra Firma fissa.
- [ ] Provare Riduci movimento: Elimina tutto deve passare allo stato vuoto
      senza animazione e senza eliminare file originali o firmati.
- [ ] Caricare più documenti; selezionare formati diversi; verificare che il
      formato dei nuovi documenti non modifichi quello già selezionato.
- [ ] Controllare i nomi di tutti gli otto formati e le informazioni contestuali.
- [ ] Aprire Impostazioni con ⌘,, visitare le quattro schede e tornare con Indietro.
- [ ] Firma singola e multipla con certificato reale, PIN errato/annullamento,
      disconnessione e gestione esito incerto: stessi blocchi e consenso della 0.6.
- [ ] Apri file firmato/Mostra nel Finder prima dello svuotamento; svuotare,
      controllare gli output sul disco e iniziare una nuova sessione.
- [ ] Ripetere su macOS 13–15 e 26, inclusa la resa del fallback nativo.

Riferimenti Apple: [Adopting Liquid Glass](https://developer.apple.com/documentation/TechnologyOverviews/adopting-liquid-glass),
[backgroundExtensionEffect](https://developer.apple.com/documentation/swiftui/view/backgroundextensioneffect()).

Nessuna GitHub Action, merge o release pubblica. PR #8 mantenuta draft.
