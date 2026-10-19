# Signum 0.4 — Orientamento PAdES, build 12

## Baseline e analisi

Branch dedicato codex/signum-0.4-pades-orientation-b12 dall’HEAD effettivo B11 **217611a**, successivo alla sorgente dei bundle **3a2e1dd**. Stato iniziale tracciato pulito, due file non tracciati preesistenti preservati. Worktree censiti senza accesso agli altri checkout. Ref protetti, manifest/eseguibili B11 e file precedenti registrati in .build/04stabilization-b12/evidence/baseline.json. Letti rapporti B11/stabilizzazione/appearance/diagnosi/progresso prima dell’intervento.

**Problema dimostrato dalla trasformazione B11 e confermato dal collaudo riferito dall’utente:** l’overlay mappa correttamente il rettangolo grezzo, ma il contenuto AP non compensa /Rotate. Su pagina 90 l’asse di lettura del timbro diventa verticale. MediaBox landscape e rotazione interna sono indipendenti: nessuna euristica basata sulle proporzioni.

Percorso analizzato: configurazione per documento → geometria CGPDFPage dello snapshot → renderer CoreGraphics/CoreText → RenderedPAdESAppearance → mapping PDFKit/overlay → approvalIdentity/preflight → SigningJob → stdin helper → PoDoFo. Il helper esistente importa la pagina artwork solo se Rotate=0 e dimensioni MediaBox uguali al Rect raw; FillFromPage crea AP/N prima di ByteRange/CMS. Non serve modificarlo, né ruotare la tavola.

## Semantica e architettura

PAdESAppearanceOrientation: Automatico (default), 0,90,180,270. Angoli manuali **orari rispetto alla normale direzione di lettura del visualizzatore**. Automatico e 0 hanno lo stesso risultato visivo, ma sono scelte distinte nel consenso. Compensazione pura: rotazione artwork antioraria nei byte PDF = (rotazione pagina − angolo manuale orario + 360) mod 360. Quattro trasformazioni esatte, nessuna trigonometria/zoom o inferenza dall’orientamento fisico.

Dimensioni del contenuto espresse prima della rotazione; rectangle è sempre l’ingombro assiale raw approvato /Rect. A 90/270 si scambiano gli assi; il cambio conserva il centro ove possibile e trasla soltanto per rientrare nel CropBox∩MediaBox, senza deformazione o ridimensionamento silenzioso. Se l’ingombro non entra, errore esplicito. Stepper e Option-resize rispettano limiti sulle dimensioni del contenuto.

Il renderer esistente genera una sola versione upright vettoriale, conservata immutabile. Orientare usa la stessa pagina PDF come contenuto, con trasformazione esatta dentro un nuovo PDF a origine zero e Rotate=0; niente secondo layout testo, lettura immagine o rasterizzazione della tavola. Rotazioni successive ripartono sempre dall’upright, senza accumulo di wrapper. L’overlay e PoDoFo ricevono gli stessi byte finali già orientati. Nessuna correzione indipendente nell’overlay o nel helper.

API precedenti conservate: chiamanti che passano soltanto CropBox continuano con rotazione pagina implicita 0 e metadata legacy nil; la GUI B12 passa sempre la rotazione effettiva. Il job verifica, per la nuova API, che la rotazione sia quella della pagina dello snapshot e che l’ingombro sia valido prima dell’approvazione/autenticazione.

Cambio orientamento invalida subito readiness, genera nuova approvalIdentity (scelta e angolo risolto inclusi), cancella callback obsolete tramite generation. Configurazione, rotazione pagina, AP e geometria sono valori immutabili nel job. Il drag condivide byte/hash/artworkID, non ricrea PDF o cache; orientare conserva contentArtworkID e riusa l’artwork upright nel worker asincrono.
