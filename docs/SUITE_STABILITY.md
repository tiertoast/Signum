# Misure offline della stabilità XCTest

`scripts/test-suite-stability.py` misura senza modificare i budget o gli assert dei test. Richiede sorgenti correnti, prefix nativo in sola lettura, helper della configurazione scelta, XMLSec/Python/Poppler e una sessione WindowServer per le classi native. Non esegue packaging, non installa dipendenze e non accede a middleware reali.

Tutte le directory `--output` e `--scratch` devono essere esterne al checkout; output deve essere nuovo. Il catalogo viene compilato con `swift test list` e confrontato col manifest S07. Non si usa `--skip-build`. Ogni esecuzione usa fixture, TMPDIR ed evidenze separati, con configurazione/rpath/deployment espliciti. Le campagne che condividono la barriera amministrativa per utente vanno eseguite in sequenza.

```sh
python3 scripts/test-suite-stability.py \
  --configuration release --condition cpu --selection failed-methods --repeat 20 \
  --native-prefix /prefix/offline --helper /build/esterna/signum-pades-local \
  --xmlsec /prefix/offline/bin/xmlsec1 --python /percorso/python3 \
  --poppler /percorso/pdftoppm --scratch /build/esterna/swift-release \
  --output /evidenze/nuova/cella-release-cpu --timeout 1800
```

`local-stability-cases.json` identifica i sei metodi falliti storicamente e le cinque classi che li contengono; contiene anche la selezione pertinente della Fase 4. Il catalogo compilato rimane autorevole: classe/metodo storico mancante, insieme incompleto, doppie esecuzioni o skip sono errori. Gli exit non vengono trasformati in verde e ogni tentativo, anche rosso, resta nei risultati.

Per la caratterizzazione Fase 5a, in ciascuna delle quattro celle Debug/Release × idle/cpu: almeno20 esecuzioni dei sei metodi, una campagna di contesto sulle cinque classi, almeno5 esecuzioni della selezione pertinente completa. La modalità `idle` significa assenza di carico sintetico del runner: non certifica che altre applicazioni dell'utente siano ferme. Si registra il carico osservato. La modalità `cpu` avvia per default tanti processi di prova quanti core logici, attende il loro READY, ne limita la durata con timeout, poi termina/raccoglie i supervisori e verifica l'uscita dei worker, registrando CPU time e ricevute. Un fallimento non interrompe la raccolta dei tentativi successivi: non è una strategia di retry per accettare l'ultimo verde.

Per ogni run vengono conservati comando, exit, UTC, tempo monotono, clock gap, load average e log grezzo con SHA256. Gli eventi `.events.jsonl` marcano la **ricezione dell'output** nel runner; buffering può ritardarla rispetto all'emissione XCTest, e non viene presentata come timestamp interno di un checkpoint. Le durate minime/mediane/massime nella sintesi derivano dal timer XCTest, con il clock gap separato. La sola correlazione con carico/clock non determina automaticamente la causa di un assert.

Caffeinate può avvolgere temporaneamente la campagna. Nessuna impostazione di sistema o toolchain viene modificata. Prima di cambiare un test occorrono riproduzione/misure, commit del solo strumento/rosso e motivazione che preservi tutti gli assert semantici. Una diagnosi non determinabile resta aperta; il solo verde a una ripetizione non la risolve.
