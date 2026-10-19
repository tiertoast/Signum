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
