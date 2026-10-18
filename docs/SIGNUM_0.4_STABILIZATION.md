# Signum 0.4 — Stabilizzazione PAdES e workflow

## M1 — Baseline e riproduzione

Branch `codex/signum-0.4-stabilization`, da HEAD effettivo `13d817b9d090119f367d22ef9de037b95226b5e5`. Main e branch di origine preservati. Letta la diagnosi prestazionale prima di intervenire. Review non tracciata e diagnosi preesistente conservate; la review non viene aggiunta a Git. Bundle precedenti non sovrascritti.

Semantica baseline: il selettore «Formato per nuovi documenti» viene letto soltanto all’acquisizione. `DocumentSnapshot.format` è immutabile; `SigningJob.format` proviene dallo snapshot; destinazione ed esecutore seguono il job. Cambiare il selettore non converte i documenti già acquisiti. Le righe e il consenso opzionale contengono già il formato, ma il contesto selezionato non è esplicito nella preview; la preferenza per nuove acquisizioni può essere scambiata per il formato del documento corrente. Non è riprodotta una conversione autonoma PAdES→CAdES.

La preview segue lo snapshot selezionato, non il selettore. Questo comportamento è corretto per il batch misto, ma il documento corrente va reso esplicito; vanno impedite callback grafiche tardive. L’appearance è conservata separatamente dal job: si rafforzerà il vincolo nel piano immutabile.

Drag: diagnosi precedente riproduce rigenerazione PDF e decodifica immagine a ogni posizione, circa 63 ms con PNG 2800² e risultati cancellati terminati inutilmente. Non si attribuisce il timbro assente alla modalità invisibile: il collaudo riferisce esplicitamente il toggle attivo. Fit PDFKit e coordinate richiedono prove pixel.

Il PDF tecnico citato non è presente nell’allegato corrente (che contiene soltanto le istruzioni) né fra gli allegati PDF della cartella di progetto accessibile. Nessuna ricerca del documento per nome; si useranno fixture sintetiche, senza documenti personali o hardware.

I numeri del checkpoint (317 Swift ecc.) sono storici e non costituiscono validazione delle modifiche. Le verifiche effettive sono registrate nelle milestone successive.

## M2 — Formato e consenso

Conservata la semantica A: il selettore agisce soltanto sui nuovi documenti. Nota esplicita, formato effettivo del documento corrente nella colonna sinistra, formato per riga e nel consenso opzionale. Il riepilogo GUI ora trasferisce l’appearance al `SigningJob` immutabile: certificato, artwork e geometria congelati insieme a snapshot/formato/provider/destinazione. Il helper rifiuta un’appearance differente da quella del job. Le API legacy senza appearance rimangono disponibili ai test/percorsi esistenti, la GUI passa sempre l’appearance pronta per ogni PAdES.

Verifiche locali: M1 2/2; dopo M2 `SigningFormatStabilizationTests|SigningReviewTests` 11/11, zero skip/fallimenti. Inclusi batch misto, destinazioni, formato congelato, certificato sostituito, contesto appearance incongruente e invalidazione durante preflight/modale. Non si dichiara risolto un difetto crittografico di conversione non riprodotto; è corretta l’ambiguità di presentazione e rafforzato il piano.

## M3 — Documento corrente e callback

Selezione del workspace distinta dal formato per nuove acquisizioni. Un contesto con generazione identifica ogni montaggio, anche dopo il ritorno allo stesso documento: callback di precedenti pannelli non possono aggiornare placement/readiness. Il pannello segue lo snapshot selezionato; CAdES mostra Documenti ed esiti, PAdES mantiene la preview anche se cambia il default. Nome/formato corrente sono visibili. Le appearance già completate per altri documenti del batch restano conservate, senza alterare i job congelati.

Verifiche: `SigningWorkspaceSelectionTests|SigningWorkspaceTests` 5/5, zero skip/fallimenti. Inclusi selezione ripetuta/mista, callback tardiva dopo riselezione, reset e hosting nativo del PDFKit sullo snapshot. Il ciclo di vita interno delle task grafiche viene ulteriormente consolidato in M4–M6.

## M4 — Grande formato, fit ed errori

Riprodotto sulla tavola sintetica con 10.000 vettori: scala 1 invece del fit ~0,195. Il wrapper applicava fit/limiti prima del documento/layout. Correzione: installazione del documento e pagina, layout, calcolo del fit, limiti relativi al fit e applicazione esplicita della scala iniziale. Zoom successivo conservato; nessuna rasterizzazione della tavola e nessun ingrandimento arbitrario del timbro. Eliminato l’osservatore duplicato che resettava il rettangolo al cambio pagina. No-op del clic non invalida più la readiness senza una modifica.

Stato/errori sopra la preview: rendering, invisibile, attesa annotazione, pronta, errore. L’annotazione fallita restituisce un errore esplicito e non readiness positiva. Una transizione PDF invalida cancella e invalida prima il render precedente. La readiness positiva è emessa dopo la costruzione dell’annotazione, non soltanto dopo la generazione dei byte.

Prima del fix il test del fit falliva; dopo: geometria+preview 6/6 e geometria finale 3/3, zero skip/fallimenti. Confronto pixel con artwork incorporato nel contenuto pagina come riferimento indipendente dall’annotazione: A4/A3/A1/A0/superiore A0, rotazioni 0/90/180/270, MediaBox non zero, crop traslato e UserUnit 10. Il primo assert sperimentale basato su CGPDFPage.getDrawingTransform non rappresentava il ritaglio della thumbnail PDFKit: corretto il riferimento di test, senza alterare la trasformazione applicativa. Non si attribuiscono quei fallimenti iniziali a difetti delle coordinate. Restano da verificare il documento tecnico non disponibile e il comportamento interattivo sul Mac dell’utente.

## M5 — Artwork separato dalla geometria

Il renderer conserva hash PDF e identità dell’artwork immutabili. `placed` consente solo pagina/origine nuove con lo stesso contenuto/dimensioni, validando il crop; non decodifica, non impagina, non crea PDF e non ricalcola SHA-256 del payload. L’identità approvabile include sempre la geometria. PDFKit riusa la stessa annotazione e aggiorna i bounds, invalidando la regione interessata. Modificare testo, dimensioni, visibilità o risorse richiede invece nuovo artwork. Il drag invalida subito la readiness e il rilascio la ripristina solo dopo l’annotazione aggiornata.

Geometria+prestazioni 4/4, zero skip/fallimenti. Per testo/PNG 1024²/PNG 2800², ciascuno con 30 e 120 spostamenti: una sola costruzione dell’annotazione, byte/hash/artwork identici, geometria aggiornata a ogni evento. Mediane del solo percorso placement+aggiornamento annotazione 0,033–0,046 ms, p95 0,036–0,073 ms sul Mac di sviluppo. Non sono frame presentati né misura dell’intera GUI. La baseline circa 63 ms riguardava invece la rigenerazione del PDF ora evitata dal movimento.

## M6 — Coalescing, cancellazione e preflight

Coordinatore grafico per pannello con un’operazione attiva e una sola pending sostituibile; sparisce la coda globale. Checkpoint cooperativi prima/fra le fasi ImageIO/CoreText/PDF; nessuna pretesa di interrompere chiamate sincrone a metà. Ogni modifica invalida immediatamente ID/readiness; chiusura e cambio contesto revocano le callback. Il riepilogo mantiene al massimo una preparazione attiva: i richiedenti superati vengono scartati prima di nuove letture. Conservati `verifiedBytes`, hash, controlli certificato/destinazione e quelli prima della firma.

Verifiche: coordinamento+review+geometria 14/14; coordinamento+misure finali 6/6; ultima protezione chiusura 7/7, zero skip/fallimenti. Con 120 sostituzioni mentre il primo render è bloccato: due render effettivi, uno scartato, solo l’ultimo pubblicato. Con 31 contesti di preflight e snapshot 64 MiB: due preparazioni avviate, 30 richieste superate, soltanto la finale raggiunge la verifica snapshot; nessuna moltiplicazione delle letture. Cancellazione senza retry e pending eliminata alla chiusura.

Pannello SwiftUI/PDFKit reale in finestra sintetica, A0 con 10.000 vettori, sequenze 30 e 120 eventi inviate con scadenze assolute 60 Hz:

| Immagine | Eventi | Placement pubblicati | Nuovi render/annotazioni durante drag | Latenza evento→binding mediana/p95 |
|---|---:|---:|---:|---:|
| Testo | 30 / 120 | 30 / 120 | 0 / 0 | 2,61/2,87 ms · 2,23/3,00 ms |
| PNG 1024² | 30 / 120 | 30 / 120 | 0 / 0 | 2,92/3,35 ms · 2,67/3,66 ms |
| PNG 2800² | 30 / 120 | 30 / 120 | 0 / 0 | 2,66/3,21 ms · 2,48/3,03 ms |

Nessuna readiness positiva durante il movimento; una al rilascio, inclusi clic no-op. Questo conta il gate del preflight, non un riepilogo con provider nel test del pannello. Decodifiche immagine e hash del PDF durante movimento sono assenti nel percorso riusato (render zero, hash già memorizzato). Il picco RSS cumulativo dell’intero processo di test cresce da 162 a 297 MB: include framework, fixture e precedenti iterazioni; non è il consumo isolato dell’app o una prova di leak. I tempi non sono frame presentati: non si dichiara 60 fps. Le misure M5 del solo aggiornamento geometrico e queste del pannello completo sono metriche distinte.

## M7 — Regressioni e candidata

Suite Swift completa **333/333**, zero skip/fallimenti (317 storici + 16 regressioni). PKCS#11 **40/40**; PAdES nativi Debug/Release **63/63** ciascuno; packaging unit **10/10**; ASAN/TSAN Swift mirati **34/34** ciascuno, nessuna diagnostica. Le primitive/autenticazione Secure Batch PIN, discovery, worker/lifecycle, atomicità e no-overwrite sono rimaste inalterate e sono incluse nella suite completa.

Nuovo end-to-end: job con artwork spostato e congelato, quattro PDF vettoriali firmati con provider software, rotazioni 0/90/180/270, crop/MediaBox traslati, pagina superiore A0/UserUnit 10. Controllati /AP/N, /Rect finale, aggiornamento incrementale, verifica unificata (ByteRange/CMS), originali invariati. Poppler sul vero PDF firmato e sul riferimento appiattito: centroidi dei pixel rossi coincidenti per tutte le rotazioni, non soltanto confronto dell’overlay.

Incrementata soltanto la nuova candidata a **0.4.0/build 10**, minimo 13.0. Bundle Debug/Release da produrre in `.build/04stabilization-bundles/build10-{debug,release}/Signum.app`, mai nelle directory delle build precedenti. La verifica finale dei bundle viene registrata dopo la compilazione dal commit sorgente pulito.

### Controllo finale del workspace

Individuato e riprodotto durante la revisione M7: dopo il ritorno all’elenco, selezionare il nome dello stesso PAdES non riapriva la preview perché la selezione era trattata come no-op. Test iniziale 1 fallimento atteso su 2; corretto il modello per riaprire la preview con una nuova generazione, senza toccare il job. Dopo: selezione+hosting workspace 5/5. I primi bundle `build10-{debug,release}` da `b760a54` sono intermedi e preservati; usare soltanto i successivi `final-{debug,release}` registrati nella consegna finale.
