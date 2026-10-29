# Signum 0.6-E.1 — Rifinitura rapporti

Baseline: `9e6e1b835adbe1364f454d1a78370f8b76a52bd1`.
Branch: `feature/signum-0.6e-verification-reports`.

## Modifiche circoscritte

- Accento PDF Burgundy `#64313E` (RGB 100, 49, 62) su linee, etichette,
  titoli di sezione, accenti e motto. Testo principale antracite, sfondi neutri,
  metriche, layout A4, sezioni e cinque risultati indipendenti conservati.
- Date PDF/TXT in `dd/MM/yyyy HH:mm:ss UTC`, calendario gregoriano esplicito.
  signingTime visualizzato da GMT OpenSSL o ISO 8601 con zona esplicita, senza
  mutare la sorgente o usare la zona locale. Eventuali frazioni sono omesse nella
  sola presentazione al secondo, senza arrotondamento. Date impossibili o formati
  sconosciuti/senza zona restano riconoscibili come originali non convertiti.
- Appendice: tipo, stato, motivazione, istante di valutazione, thisUpdate,
  nextUpdate e revoca sono mostrati solo dove presenti nei risultati tipizzati
  OCSP/CRL già disponibili. Nessuna nuova interrogazione o verifica.
- La data di aggiornamento TL non è esposta dai risultati attuali del motore:
  viene dichiarata non disponibile. Lo stato del servizio e la sua decorrenza,
  la sequenza TL e l’identità restano distinti; statusSince non diventa una
  presunta data di aggiornamento della lista.
- Gli esiti conservano nomi e motivazioni testuali leggibili senza colore.
  GUI, crittografia, policy eIDAS e flussi di firma non modificati.

## Verifica mirata

17 test distinti del generatore PDF/TXT hanno esito finale positivo: contenuti e
coerenza con risultati tipizzati, firme multiple/controfirme, date/offset e sorgenti
immutabili, dati mancanti, colori, geometria, sicurezza/esclusività della scrittura.
Un controllo geometrico è stato aggiornato per distinguere i titoli dalle etichette
ora dello stesso colore; sono stati ripetuti solo i test interessati. L’esempio
sintetico espone OCSP e un secondo firmatario senza percorso disponibile.

Evidenze locali: `outputs/signum-0.6e1/{targeted.log,corrections.log,sample-final.log,results.json}`.
Esempi: `outputs/signum-0.6e1/examples-delivery/Signum-rapporto-esempio.pdf` e `.txt`.
Il PDF finale ha cinque pagine A4, tutte renderizzate e ispezionate visivamente:
nessun ritaglio, sovrapposizione o riga isolata nell’appendice.
Nessuna nuova Build, dipendenza o regressione completa. I limiti dei profili e del
rapporto non firmato definiti dalla 0.6-E restano applicabili.
