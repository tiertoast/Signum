# Signum 0.4 — Stabilizzazione build 11

## M1 — Baseline

Branch `codex/signum-0.4-stabilization-b11` dall’HEAD effettivo `718406a` della build 10 (sorgente candidato `6e3c4ce`). Letti rapporto build 10 e diagnosi, preservati snapshot, consenso e ottimizzazioni del drag. Main e i branch precedenti non vengono modificati; hash iniziali dei bundle/manifest e dei due documenti non tracciati in `.build/04stabilization-b11/evidence/baseline.json`.

**P0 riproducibile per costruzione:** il menu della build 10 modifica soltanto il default di acquisizione; lo snapshot conserva `format` e il coordinatore non espone una mutazione per il documento corrente. La nuova richiesta cambia esplicitamente questa semantica: byte immutabili, configurazione pre-consenso modificabile, job approvato immutabile.

**P1:** il collaudo dell’utente riferisce ancora timbro assente con modalità visibile. Fit, readiness e conteggio annotazioni della build 10 non sono una prova di pixel nel viewport. Si predisporrà una riproduzione separata e un prototipo overlay prima di cambiare il percorso live.

Ricerca locale nei nomi degli allegati Codex e nel mirror di progetto: PDF/video citati non accessibili; l’allegato corrente contiene soltanto le istruzioni. Nessuna analisi dichiarata del video o del documento reale, nessuna ricerca Internet o copia in Git. Fixture sintetiche per tutte le nuove prove; eventuale corrispondenza alla tavola reale resta un limite esplicito.

Baseline locale mirata: `SigningFormatStabilizationTests|PAdESGeometryStabilizationTests|PAdESPlacementPerformanceTests` **9/9**, zero skip/fallimenti. I 333 test storici non sono assunti validi dopo le modifiche: saranno rieseguiti sul codice finale.

## M2 — Configurazione dinamica

Aggiunta `DocumentSigningConfiguration` per documento, distinta dallo snapshot immutabile. `setFormat` modifica soltanto la preparazione, invalida sincronicamente revisione/preflight e ricalcola i nomi con la convenzione esistente; i job copiano il formato esplicito e lo congelano. `DocumentSnapshot.format` resta un hint immutabile di acquisizione/limiti per i chiamanti legacy, non è più la sorgente del formato del batch. Nessuna nuova copia/lettura dell’originale per cambiare formato. PDF non strutturalmente leggibili/protetti sono rifiutati prima del consenso PAdES.

Riprodotto inoltre un caso asincrono: se la revisione cambiava durante la validazione provider, un vecchio `SigningReviewContext` poteva avviare una preparazione con configurazioni nuove. Aggiunto il controllo di revisione anche dopo quella attesa. Test iniziale con due assert falliti, poi **27/27** pertinenti, zero skip/fallimenti. Inclusi cambi ripetuti, batch misto, collisioni, revisione durante preflight, blocco dopo approvazione/conclusione, snapshot invariato e firme CAdES/PAdES effettive con formato diverso dall’hint di acquisizione. Verificati CMS/PDF reali sintetici e assenza dell’output del vecchio formato.

## M3 — Workflow GUI

Menu principale «Formato firma» collegato al documento corrente, scelta separata per i prossimi documenti e menu per riga nei batch. Il cambio modifica soltanto il documento indicato, mostra il nuovo nome previsto (distinto dalla destinazione già riservata dal preflight), azzera l’appearance del vecchio formato e revoca il contesto grafico. PAdES apre la preview; CAdES torna all’elenco. Il workspace legge la configurazione corrente, mai l’hint di acquisizione. Nessuna rimozione/riacquisizione del file richiesta.

Prima di iniziare M4/M5: **12/12** test pertinenti, zero skip/fallimenti. Incluso hosting nativo della GUI: stesso snapshot CAdES→PAdES→CAdES ripetuto, PDFView presente/assente coerentemente, vecchie generazioni non accettate. Confermate le cinque regressioni Core del formato dinamico e i test workspace precedenti.

## M4 — Riproduzione e gate del prototipo

Prototipo isolato riproducibile in Tools/PlacementPrototype/: due PDFView native affiancate, a sinistra il percorso annotazione esatto di 718406a, a destra una NSView trasparente che disegna lo **stesso PDF artwork**, senza nuovo layout. Nessuna modifica applicativa in questa milestone. Il runner utilizza gli oggetti Core della build Release locale e non esegue discovery/firma.

**Fatti dimostrati nel viewport reale** (cattura finestra locale, non thumbnail):
- Fixture vettoriale 10.000 segmenti, 3370×2384 pt, origine zero o traslata, rotazione 0: entrambe visibili.
- Stessa fixture, CropBox traslato e rotazione 90: annotazione assente (0 pixel scuri nel ROI del timbro), overlay presente (1683). Durante il callback nativo il clip dopo la trasformazione dell’annotazione è (-72,468,100,240), disgiunto dal box artwork (0,0,240,100). L’ulteriore trasformazione dell’intera pagina applicata dall’annotazione non è valida nel percorso live ruotato. Le prove thumbnail precedenti non esercitavano questo percorso.
- **Aggiornamento evidenza fornita successivamente dall’utente:** tavola reale ora accessibile, letta soltanto localmente e mai firmata. 140893 byte, una pagina non cifrata, MediaBox=CropBox (0,0,1304,1843), Rotate=90, UserUnit=1. Anche qui, al centro del viewport, callback annotazione con clip artwork (-826,-323,100,240) disgiunto dal box AP. Il confronto delle due metà mostra solo nell’overlay il timbro e il suo fondo opaco. Riprodotto quindi il difetto sul documento effettivo; il peso elevato non è necessario per questo caso. Originale non modificato, nessuna risorsa personale in Git.
- Cambio zoom 25% esercitato nel prototipo sul documento reale. Validazione sistematica di zoom/scroll e performance nel percorso integrato prevista in M5/M7.
- Riferimento finale già rieseguito: PAdESStabilizationSigningTests **1/1**, quattro rotazioni, AP/Rect, integrità crittografica, confronto indipendente Poppler e originale sintetico invariato. La geometria dell’overlay deriva dalle conversioni PDFKit degli stessi tre punti del rettangolo grezzo usato da questi job.

**Decisione:** gate soddisfatto per procedere all’overlay live. Conservare il renderer esistente e il binding immutabile; sostituire soltanto la presentazione nel viewport. I dati di prova/catture rimangono ignorati in .build/04stabilization-b11/. La registrazione video non è stata esaminata. L’esito sul prototipo non equivale ancora alla consegna di P1 nell’app.

## M5 — Overlay live

Introdotta SignaturePlacementOverlay, NSView trasparente e non intercettante sopra il viewport, ritagliata all’area di scorrimento. Il rettangolo del job resta in coordinate PDF grezze: tre conversioni PDFKit determinano la trasformazione dell’artwork, comprese rotazioni/box/origini/UserUnit. Zoom, scroll, layout e cambio pagina aggiornano solo la geometria. Nessun parser o renderer del documento aggiuntivo; nessuna annotazione temporanea nel PDF live. L’annotazione legacy rimane esclusivamente per confronti offline e regressioni preesistenti.

Lo stesso PDF artwork è conservato e presentato tramite una cache dei suoi soli pixel (dimensione massima 4096 per asse). La prova iniziale ha mostrato che AppKit può ridisegnare una NSView anche per cambi di origine: il solo backing layer non bastava (201 disegni su 200 spostamenti). Aggiunta quindi cache esplicita CGImage; ora 200 spostamenti non richiamano drawPDFPage né decodificano PNG/JPEG. Zoom/resize invalidano la piccola cache, mai l’intera tavola. Bordo di selezione separato dal contenuto firmato.

Readiness visibile solo dopo il disegno effettivo; callback differiti e vincolati all’identità corrente, consenso invalido durante il gesto come prima. Errori artwork espliciti, cancellazione/documento sostituito eliminano le risorse precedenti. Firma invisibile non richiede disegno.

**8/8 test** pertinenti, zero skip/fallimenti: hosting GUI e cambio formato, precedenti prove offline, pixel della NSView overlay e rettangoli live per A1/A0/>A0/geometria equivalente alla tavola, quattro rotazioni, origini/box traslati, UserUnit, zoom 25/100/200, riuso della cache su 200 movimenti, notifiche scroll, errori/invisibile/reset. La prova precedente fallita è conservata nei log. Avviso PDFKit durante teardown di documenti sintetici, senza assert falliti; nessun errore ignorato di approvazione.

## M6 — Consenso e output finale

Estesa la regressione di firma effettiva alle quattro rotazioni: prima del consenso presenta lo stesso artwork nell’overlay nativo, controlla pixel rossi, rettangolo convertito e uguaglianza dei byte AP; dopo il freeze modifica/chiude la presentazione e verifica che il job e il PDF finale conservino i valori approvati. Il helper continua a ricevere i byte AP congelati, mai una posizione ricavata dalla vista durante la firma.

**17/17** test pertinenti, zero skip/fallimenti, inclusi formati dinamici con firme effettive, revisioni/preflight e output PAdES. Per ciascuna rotazione: AP/N e Rect presenti, originale invariato, verifica crittografica valida e centroidi Poppler coincidenti entro 2 pixel con il riferimento che incorpora gli stessi byte in page content. Nessuna modifica alle primitive o alla pubblicazione.

## M7 — Regressioni grafiche e prestazioni

**13/13** mirati, zero skip/fallimenti. Rafforzata la prova del pannello SwiftUI reale: ora misura i contatori overlay/raster effettivi (non quelli dell’annotazione dismessa). Aggiunti 40 immagini sintetiche nel documento, gesti nativi click/drag/Option-resize con round-trip coordinate, pagine miste, cambio pagina, rigenerazione al resize, notifiche zoom/scroll. Errori allocazione espliciti e invalidazione cache su cambio backing scale.

Misure Debug non sanitizzate sul Mac corrente; tre esecuzioni con immagini assenti/1024/2800, 120 movimenti:
| Misura (ms) | Testo | PNG 1024 | PNG 2800 |
|---|---:|---:|---:|
| Generazione artwork (renderer esistente) | 0,69 | 9,30 | 65,89 |
| Prima presentazione/cache nativa | 0,73 | 2,93 | 17,35 |
| Movimento overlay p95, incluso display | 0,088 | 0,070 | 0,091 |
| Resize incluso renderer | 1,34 | 12,66 | 84,71 |
| Zoom/raster della sola AP | 1,52 | 3,95 | 17,84 |

Nel pannello SwiftUI, input schedulato a 60 eventi/s (30 e 120 eventi), latenza evento→binding mediana 2,99–3,20 ms, p95 3,41–3,99 ms, **zero render/nuovi artwork/rasterizzazioni durante drag**, readiness soltanto al rilascio. Non è una misura dei frame presentati: nessuna dichiarazione di 60 fps. RSS di picco dell’intero processo test 182–257 MB; non attribuibile alla sola cache (include fixture, PNG, PDFKit, test precedenti). La prima presentazione/zoom PNG grande resta circa 17–18 ms sincrona sul MainActor; il render/resize viene eseguito dal coordinatore asincrono nell’app. Cache massima 4096²×4 byte per artwork; limite della sola rappresentazione a schermo, AP finale vettoriale invariata.

Runner A/B aggiornato con opzione --integrated per usare a destra il codice live effettivo, mantenendo a sinistra 718406a. Riesaminata la tavola reale localmente, senza firma: pixel del timbro presenti nel codice integrato, assenti nel percorso precedente; esercitati clic e zoom 25/100/200. Catture ignorate, nessun documento personale nel commit. I test automatici usano esclusivamente fixture sintetiche. Ulteriori tavole dell’utente non ancora disponibili restano da collaudare.

ASAN e TSAN mirati sul codice corrente: **17/17 ciascuno**, zero skip/fallimenti e nessuna segnalazione sanitizer nei log. Comprendono formati, GUI, overlay, cancellazione/render/preflight e output firmato sintetico.
