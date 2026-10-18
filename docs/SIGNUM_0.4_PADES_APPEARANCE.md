# Signum 0.4-B — Appearance PAdES

Baseline 18 ottobre 2026: HEAD build 6 `72060b7`, codice `37d21e8`.
Branch `codex/signum-0.4-pades-verification`, main `be84a1e` e build 6 preservati;
review non tracciata preservata. PR #3 soltanto riferimento, nessuna modifica.
Colloquio hardware positivo su CAdES/PIN temporaneo/InfoCamere riferito
dall'utente, non trasferito per presunzione a questo sviluppo.

## Design B prima del codice

Il renderer testuale PoDoFo e l'overlay freeText PDFKit attuali sono differenti.
La nuova appearance usa un unico PDF autonomo prodotto da CoreGraphics/CoreText:
gli stessi byte vengono disegnati nella preview e incorporati da PoDoFo in /AP
prima della firma. Nessun salvataggio dello snapshot PDFKit. Il percorso testuale
legacy resta compatibile, non è il renderer della nuova GUI.

Configurazione per documento, geometria PDF non ruotata, nome dal DER selezionato,
data locale congelata (non timestamp qualificato), testo opzionale, PNG/JPEG
validati e allineamento. Risorse incorporate, nessun riferimento esterno.
La configurazione e il PDF appearance vengono congelati al consenso; dopo il
consenso non viene riletto il percorso dell'immagine. Coordinate raw esplicite
anche nel widget PoDoFo per evitare una seconda rotazione.

C non iniziata: si procede alla verifica unificata soltanto dopo test/build e
commit B. Nessun nuovo hardware/PIN reale, rete documentale o nuova primitiva.
