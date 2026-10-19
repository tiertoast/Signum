# Signum 0.4 — Stabilizzazione build 11

## M1 — Baseline

Branch `codex/signum-0.4-stabilization-b11` dall’HEAD effettivo `718406a` della build 10 (sorgente candidato `6e3c4ce`). Letti rapporto build 10 e diagnosi, preservati snapshot, consenso e ottimizzazioni del drag. Main e i branch precedenti non vengono modificati; hash iniziali dei bundle/manifest e dei due documenti non tracciati in `.build/04stabilization-b11/evidence/baseline.json`.

**P0 riproducibile per costruzione:** il menu della build 10 modifica soltanto il default di acquisizione; lo snapshot conserva `format` e il coordinatore non espone una mutazione per il documento corrente. La nuova richiesta cambia esplicitamente questa semantica: byte immutabili, configurazione pre-consenso modificabile, job approvato immutabile.

**P1:** il collaudo dell’utente riferisce ancora timbro assente con modalità visibile. Fit, readiness e conteggio annotazioni della build 10 non sono una prova di pixel nel viewport. Si predisporrà una riproduzione separata e un prototipo overlay prima di cambiare il percorso live.

Ricerca locale nei nomi degli allegati Codex e nel mirror di progetto: PDF/video citati non accessibili; l’allegato corrente contiene soltanto le istruzioni. Nessuna analisi dichiarata del video o del documento reale, nessuna ricerca Internet o copia in Git. Fixture sintetiche per tutte le nuove prove; eventuale corrispondenza alla tavola reale resta un limite esplicito.

Baseline locale mirata: `SigningFormatStabilizationTests|PAdESGeometryStabilizationTests|PAdESPlacementPerformanceTests` **9/9**, zero skip/fallimenti. I 333 test storici non sono assunti validi dopo le modifiche: saranno rieseguiti sul codice finale.
