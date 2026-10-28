# Test locali Signum 0.7 — contratto del runner

Il runner ufficiale è `python3 scripts/test-local.py`. Usa soltanto fixture e provider sintetici; non apre middleware installati, non richiede PIN personali e non avvia CI remota. Non installa dipendenze. Il documento descrive i test del sorgente corrente, senza promuovere metadati o artefatti a release Stable.

## Ambiente preparato

Servono macOS con developer tools Apple (Swift, SDK, `/usr/bin/cc`), Python 3, `/usr/bin/openssl` per le chiavi effimere, CMake >= 3.23 e CTest. Per compilare i target Swift serve un prefix locale offline con PoDoFo **1.1.2**, OpenSSL >= 3, FreeType, libxml2 e XMLSec/OpenSSL (header, librerie e file pkg-config). Il prefix è letto, mai modificato dal runner. XMLSec CLI e Python con il modulo zipfile sono prerequisiti espliciti delle fixture di interoperabilità; il setup ne prova l’esecuzione. CMake/CTest sono verificati anche per versione (>= 3.23). Per i confronti raster serve Poppler `pdftoppm`. La suite completa richiede una sessione WindowServer, anche per i test AppKit/PDFKit senza interazione manuale. I controlli di setup non caricano provider.

```sh
python3 scripts/test-local.py --group complete \
  --native-prefix /percorso/prefix-locale \
  --cmake /percorso/cmake --ctest /percorso/ctest \
  --xmlsec /percorso/prefix-locale/bin/xmlsec1 --python /percorso/python3 \
  --output-root /directory/esterna/signum-tests \
  --poppler /percorso/pdftoppm --check

python3 scripts/test-local.py --group complete \
  --native-prefix /percorso/prefix-locale \
  --cmake /percorso/cmake --ctest /percorso/ctest \
  --xmlsec /percorso/prefix-locale/bin/xmlsec1 --python /percorso/python3 \
  --output-root /directory/esterna/signum-tests \
  --poppler /percorso/pdftoppm
```

Gli argomenti possono essere forniti con `SIGNUM_NATIVE_PREFIX`, `SIGNUM_CMAKE`, `SIGNUM_CTEST`, `SIGNUM_TEST_POPPLER`, `SIGNUM_TEST_XMLSEC`, `SIGNUM_TEST_PYTHON`. Non serve predisporre cartelle `.build/04*`, helper o evidenze da una build precedente. Il runner compila il proprio helper Debug e passa `SIGNUM_TEST_PADES_HELPER` ai test. Il prodotto non legge questa variabile di test.

## Gruppi e prerequisiti

`scripts/local-test-groups.json` assegna ogni classe XCTest di **tutti e cinque i target** a uno dei sei gruppi e dichiara i prerequisiti aggiuntivi. Le classi Core mantengono il nome breve; le altre usano `Target.Classe`. Prima controlla i nomi nei sorgenti, poi esegue `swift test list` con una vera build nello scratch esterno: `scripts/xctest_contract.py` confronta il catalogo compilato con il manifest. Nuove classi non classificate, nomi obsoleti, duplicati e motivazioni di esclusione vuote sono errori. I metodi nuovi di una classe già censita entrano automaticamente nel catalogo atteso. Il campo `excluded` è attualmente vuoto: nessuna classe è esclusa. Le esecuzioni complete rifiutano esclusioni e usano Swift senza filtro.

La baseline della fase3b è **795 metodi in 114 classi** (Core608, CertificateValidation129, TrustAuthentication34, TrustCore19, TrustIntegration5). Sono dati della baseline, non un numero hardcoded usato per accettare una suite futura. Il runner confronta ogni coppia `Target.Classe/metodo` iniziata e passata con la lista compilata e conserva conteggi per target e SHA256 del catalogo. Anche un comando exit0 con zero metodi, un metodo mancante o duplicato fallisce. `--check` valida tool e catalogo compilato senza eseguire i test; crea quindi evidenze e scratch di compilazione esterni, non è un controllo esclusivamente statico.

| Gruppo | Esecuzione |
| --- | --- |
| `complete` | Swift **senza filtro**, PKCS#11 Debug, PAdES Debug/Release, Python packaging/tooling, sanitizer mirati |
| `swift` | Swift senza filtro e helper nativo Debug preparato dal runner |
| `pure-swift` | Test Swift senza helper PAdES o provider PKCS#11; filtri dichiarati nel manifest |
| `native-helper` | Classi Swift che richiedono helper PAdES |
| `poppler` | Integrazioni con confronto raster indipendente; helper e Poppler obbligatori |
| `synthetic-pkcs11` | Classi Swift con provider PKCS#11 compilato localmente |
| `integration` | Altre integrazioni locali, snapshot, processi e writer |
| `ui` | Render AppKit/PDFKit; WindowServer obbligatorio. Alcune classi richiedono anche helper/Poppler, come dichiarato nel manifest |
| `pkcs11` | Harness nativo PKCS#11 Debug |
| `pades` | Harness nativo PAdES Debug e Release |
| `packaging` | Unit test Python di packaging e runner |
| `sanitizers` | Swift ASAN/TSAN mirati, PKCS#11 ASAN/TSAN e PAdES ASAN |

I gruppi filtrati sono esecuzioni parziali esplicite e **non** valgono come suite completa. Il riepilogo registra i gruppi non selezionati. Un prerequisito obbligatorio assente è un errore di setup (exit 2), non uno skip. Qualsiasi skip XCTest nel gruppo eseguito fa fallire il runner. I test UI possono ancora segnalare l'assenza di WindowServer in invocazioni manuali esterne al runner: quel risultato non è una suite completa verde.

## Isolamento, timeout ed evidenze

Ogni esecuzione crea `<output-root>/<UTC>-<UUID>/` fuori dai sorgenti; il default è una directory canonica nel temporaneo del sistema. Passare esplicitamente `--output-root` per controllare anche le evidenze di setup. Il runner rifiuta un output dentro il checkout. TMPDIR è una sottocartella canonica della nuova esecuzione; non riusa alias o fixture di campagne precedenti. Il runner non riutilizza o sovrascrive directory precedenti. Dentro la nuova directory si trovano build separate, `fixtures/`, `evidence/*.log`, immagini uniche in `evidence/artifacts/` e `results.json` con setup, comandi, exit code, tempi e stato finale.

`FixtureFiles` crea le proprie directory anche eseguendo `swift test` direttamente. Le immagini non usano nomi storici condivisi. `MockModule` continua a rimuovere il proprio provider al termine; i certificati di test conservati sono solo DER pubblici.

I processi fixture Swift hanno una deadline di 30 secondi, poi SIGKILL e osservazione bounded di 2 secondi. Le barriere asincrone di test hanno deadline; i provider volutamente bloccati usano i limiti del supervisore produttivo. I figli nativi hanno attese bounded (10 secondi, 2 per osservare il kill); CTest impone comunque 60 secondi al harness. Il runner limita ogni comando: normalmente 300 secondi, build native 600, catalogo Swift 900, suite Swift e sanitizer 1800, CTest 120. Il catalogo viene ricompilato senza `--skip-build`; i JSON catalogo ed esecuzione sono confrontati anche quando Swift esce0. CTest deve riportare un numero non nullo di test passati. Al timeout termina il gruppo di processi (TERM, poi KILL dopo 3 secondi), registra exit 124 e fallisce. Non cambia timeout o logica del prodotto per accomodare i test.

ASAN usa `detect_leaks=0`: sono controllati gli accessi alla memoria; questa esecuzione non è una verifica delle perdite dei framework Apple. TSAN è mirato ai contratti, ai writer e ai lifecycle interessati. Il filtro comprende anche snapshot, preparazione preview, render/overlay e workspace AppKit: il gruppo `sanitizers` richiede quindi WindowServer. Non certifica tutta la GUI. I test del workspace attendono lo stato osservabile del viewer cedendo il MainActor alle Task possedute, con deadline; non presumono il completamento asincrono dopo un RunLoop sincrono. `SIGNUM_TEST_LOCK_REFUSAL_WORKER` indica il worker non strumentato della stessa esecuzione, usato soltanto per il controllo di rifiuto del coordinamento nei test sanitizer.

## Packaging

`scripts/build-app.sh` è ritirato: esce sempre con codice 2 prima di costruire o modificare file. Non esiste più un packager minimale alternativo. L'unico percorso supportato è `scripts/build-beta-app.py`, che richiede app, CLI, worker e helper eseguibili, include/audita la closure nativa, firma ad hoc e prova la rilocazione prima della pubblicazione esclusiva. Una dipendenza o un worker mancanti impediscono il successo.

Le unit test Python non producono un'app distribuibile. Per integrare bundle nuovi usare `scripts/build-beta-app.py --help`, con output in una directory nuova, configurazioni Debug e Release e lo stesso prefix locale. Non installare l'app o sostituire bundle precedenti. Controllare manifest, firma ad hoc, closure delle librerie, minimo macOS e protocolli worker v2/helper v5. I collaudi con dispositivi reali, macOS 13 reale, accessibilità e interazione manuale rimangono separati e non sono impliciti nei risultati sintetici.

Per un bundle appena creato, il controllo riproducibile delle integrazioni è:

```sh
python3 scripts/test-packaged-bindings.py --bundle /nuova/directory/Signum-diagnostic.app
```

Esegue 10 controlli: worker v2 e firma RSA verificata indipendentemente, rifiuto contesto cambiato e v2 incompleto, helper v5 e verifica PAdES, no-overwrite, contesto PAdES cambiato, preflight read-only anche su firma incrementale supportata, directory errata prima dell'autenticazione, checkpoint post-login nel worker e nel helper. I provider sono copie sintetiche locali; le fixture vengono eliminate. Il bundle resta invariato.

I test SigningJob con un modulo raw sincrono possiedono anche il teardown checked: lo completano prima di rilasciare l'handle loader della fixture. Questo evita due `dlclose` concorrenti nel runtime TSAN dell'host. Non sono disabilitati unload, controlli o diagnostiche sanitizer; le prove di deinit asincrono restano in `PKCS11LifecycleIntegrationTests`, e il teardown nativo è verificato anche con TSAN.

## Teardown delle immagini ASAN nel target PKCS#11

Il CTest nativo comprende i 58 casi provider e due contratti loader distinti, seriale e concorrente. Questi ultimi verificano handle bilanciati, tabella viva, unload reale con RTLD_NOLOAD e, con ASAN, redzone globali attive durante il caricamento e shadow ritirato dopo l'ultimo close. I round ripetuti non sono casi distinti. Il runner mantiene gli stessi flag e ASAN_OPTIONS=detect_leaks=0.

Il solo mock nativo collega `Tools/PKCS11Tests/asan_image_teardown.c`. Nell'ambiente Apple Clang 21/macOS 27 il distruttore ASAN in __mod_term_func non veniva eseguito all'unload. Il file registra un distruttore C tramite __cxa_atexit che delega alla stessa __asan_unregister_image_globals e al flag originale ___asan_globals_registered del compilatore. Non gestisce handle, non anticipa dlclose, non disabilita globali e non chiama unpoison manuale. Il flag rende la chiamata idempotente. In Debug/TSAN non effettua chiamate ASAN. Nessun codice del prodotto è coinvolto.

Il ponte dipende dall'ABI immagine LLVM ASAN Mach-O con il default globals dead stripping del runner: ripetere i contratti a ogni cambio toolchain. Un ABI incompatibile deve fallire link o test; non usare soppressioni o disabilitare i controlli per superarlo. Rimuovere il ponte soltanto dopo una prova del teardown generato dal compilatore. Rimane un limite separato del runtime osservato: un accesso deliberatamente invalido dopo unload può terminare con reporting annidato invece del rapporto ASAN completo; il processo fallisce comunque. Diagnosi, riproduttore minimo, controllo di copertura e risultati sono in `docs/SIGNUM_0.4_C1_ASAN_GATE.md`.

## Variabili delle fixture e riproduzione indipendente

Il runner scarta le variabili `SIGNUM_TEST_*` ereditate e ricostruisce quelle convalidate: `SIGNUM_TEST_XMLSEC`, `SIGNUM_TEST_PYTHON`, `SIGNUM_TEST_POPPLER`; possiede `SIGNUM_TEST_FIXTURE_ROOT`, `SIGNUM_TEST_EVIDENCE_ROOT`, `SIGNUM_TEST_PADES_HELPER` e il control worker Debug `SIGNUM_TEST_LOCK_REFUSAL_WORKER` quando serve. Le ripetizioni lifecycle non vengono ereditate accidentalmente. Imposta PKG_CONFIG_PATH/LIBDIR dal prefix e MACOSX_DEPLOYMENT_TARGET (default13.0); `--triple` consente un target esplicito, per default architettura host e deployment target. Nessun percorso personale o build locale precedente è necessario. La CLI XMLSec è provata con il solo DYLD_LIBRARY_PATH del prefix nel processo di setup; i test interop possiedono già i propri override locali. Nessun override DYLD viene aggiunto all’app da distribuire.

Per il confronto richiesto dalla fase4 usare il gruppo `swift` (tutti gli XCTest, senza filtro), quindi una seconda invocazione diretta `swift test` senza filtro con scratch esterno e con le stesse variabili fixture registrate nel results.json e nei log. Le due suite vanno eseguite **in sequenza**, perché alcuni contratti amministrativi condividono una barriera per utente. Confrontare le coppie classe/metodo e i conteggi per target, non sommare i footer XCTest. Il gruppo `complete` aggiunge Python/packaging e, salvo `--skip-sanitizers`, i sanitizer configurati: un tool di packaging non disponibile resta un errore, non viene trasformato in skip o verde della campagna completa.
