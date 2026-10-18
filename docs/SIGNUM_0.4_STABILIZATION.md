# Signum 0.4 — Stabilizzazione PAdES e workflow

## M1 — Baseline e riproduzione

Branch `codex/signum-0.4-stabilization`, da HEAD effettivo `13d817b9d090119f367d22ef9de037b95226b5e5`. Main e branch di origine preservati. Letta la diagnosi prestazionale prima di intervenire. Review non tracciata e diagnosi preesistente conservate; la review non viene aggiunta a Git. Bundle precedenti non sovrascritti.

Semantica baseline: il selettore «Formato per nuovi documenti» viene letto soltanto all’acquisizione. `DocumentSnapshot.format` è immutabile; `SigningJob.format` proviene dallo snapshot; destinazione ed esecutore seguono il job. Cambiare il selettore non converte i documenti già acquisiti. Le righe e il consenso opzionale contengono già il formato, ma il contesto selezionato non è esplicito nella preview; la preferenza per nuove acquisizioni può essere scambiata per il formato del documento corrente. Non è riprodotta una conversione autonoma PAdES→CAdES.

La preview segue lo snapshot selezionato, non il selettore. Questo comportamento è corretto per il batch misto, ma il documento corrente va reso esplicito; vanno impedite callback grafiche tardive. L’appearance è conservata separatamente dal job: si rafforzerà il vincolo nel piano immutabile.

Drag: diagnosi precedente riproduce rigenerazione PDF e decodifica immagine a ogni posizione, circa 63 ms con PNG 2800² e risultati cancellati terminati inutilmente. Non si attribuisce il timbro assente alla modalità invisibile: il collaudo riferisce esplicitamente il toggle attivo. Fit PDFKit e coordinate richiedono prove pixel.

Il PDF tecnico citato non è presente nell’allegato corrente (che contiene soltanto le istruzioni) né fra gli allegati PDF della cartella di progetto accessibile. Nessuna ricerca del documento per nome; si useranno fixture sintetiche, senza documenti personali o hardware.

I numeri del checkpoint (317 Swift ecc.) sono storici e non costituiscono validazione delle modifiche. Le verifiche effettive sono registrate nelle milestone successive.
