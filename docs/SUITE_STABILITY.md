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

## Controlli dell'osservatore e dell'operazione

Il verificatore `scripts/verify-terminal-observer.py --scratch-root /directory/esterna --self-test` confronta un osservatore precedente congelato con una variante guidata da barriera, usando un figlio sintetico che ripristina correttamente il proprio stato. La modalità ordinaria estrae il vero helper PTY dal test corrente e richiede che riconosca il ripristino corretto anche se il padre è schedulato dopo l'avvio del figlio. Il timeout del controllo è un limite del riproduttore, non un aumento dei budget dei test. La copia congelata è soltanto una fixture del verificatore.

La correzione del helper PTY usa una pipe: il padre acquisisce termios prima di permettere exec al figlio. Rimangono invariati input, assert su eco protetta/ripristino/output, audit dei byte e watchdog15/20secondi. Il controllo S04 conserva invece la stessa operazione osservata al checkpoint C_Sign e ne verifica il flag dopo il close/drain; il coordinatore può già aver svuotato activeOperation. Il controllo esplicito forza anche un drain completo prima della verifica, mantenendo PID raccolto, esito incerto, un Login/Sign e nessun output/segue.

Sono correzioni di assunzioni dei test dimostrate con controlli rossi dedicati, senza cambiamenti al prodotto. Non dimostrano retroattivamente la causa dei timeout storici né quale dei due assert sulla riga terminale ambigua fosse fallito. Le diagnosi che non si riproducono restano dichiarate tali, senza attribuirle per analogia.

`--case-file` consente selezioni diagnostiche aggiuntive esplicite; il manifest storico conserva i sei metodi originari. Nel confronto dopo le correzioni si possono aggiungere i due controlli direttamente coinvolti, dichiarando separatamente il conteggio; nessun metodo originario è escluso. Gli stessi cataloghi completi e i conteggi795/466 rimangono autorevoli finché non si aggiungono nuovi metodi XCTest.
