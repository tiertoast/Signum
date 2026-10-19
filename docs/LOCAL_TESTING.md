# Test locali Signum 0.4

Il runner ufficiale è `python3 scripts/test-local.py`. Usa soltanto fixture e provider sintetici; non apre middleware installati, non richiede PIN personali e non avvia CI remota. Non installa dipendenze. Versione prodotto invariata: 0.4.0 / 13.

## Ambiente preparato

Servono macOS con developer tools Apple (Swift, SDK, `/usr/bin/cc`), Python 3, `/usr/bin/openssl` per le chiavi effimere, CMake >= 3.23 e CTest. Per PAdES serve un prefix locale con PoDoFo **1.1.2**, OpenSSL >= 3 e FreeType. Per i confronti raster serve Poppler `pdftoppm`. La suite completa richiede una sessione WindowServer, anche per i test AppKit/PDFKit senza interazione manuale. I controlli di setup non caricano provider.

```sh
python3 scripts/test-local.py --group complete \
  --native-prefix /percorso/prefix-locale \
  --cmake /percorso/cmake --ctest /percorso/ctest \
  --poppler /percorso/pdftoppm --check

python3 scripts/test-local.py --group complete \
  --native-prefix /percorso/prefix-locale \
  --cmake /percorso/cmake --ctest /percorso/ctest \
  --poppler /percorso/pdftoppm
```

Gli argomenti possono essere forniti con `SIGNUM_NATIVE_PREFIX`, `SIGNUM_CMAKE`, `SIGNUM_CTEST`, `SIGNUM_TEST_POPPLER`. Non serve predisporre cartelle `.build/04*`, helper o evidenze da una build precedente. Il runner compila il proprio helper Debug e passa `SIGNUM_TEST_PADES_HELPER` ai test. Il prodotto non legge questa variabile di test.

## Gruppi e prerequisiti

`scripts/local-test-groups.json` assegna ogni classe XCTest una volta sola a un gruppo e dichiara i prerequisiti aggiuntivi. Il runner rifiuta classi nuove non classificate.

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

Ogni esecuzione crea `.build/local-tests/<UTC>-<UUID>/`; `--output-root` cambia solo il genitore. Il runner non riutilizza o sovrascrive directory precedenti. Dentro la nuova directory si trovano build separate, `fixtures/`, `evidence/*.log`, immagini uniche in `evidence/artifacts/` e `results.json` con setup, comandi, exit code, tempi e stato finale.

`FixtureFiles` crea le proprie directory anche eseguendo `swift test` direttamente. Le immagini non usano nomi storici condivisi. `MockModule` continua a rimuovere il proprio provider al termine; i certificati di test conservati sono solo DER pubblici.

I processi fixture Swift hanno una deadline di 30 secondi, poi SIGKILL e osservazione bounded di 2 secondi. Le barriere asincrone di test hanno deadline; i provider volutamente bloccati usano i limiti del supervisore produttivo. I figli nativi hanno attese bounded (10 secondi, 2 per osservare il kill); CTest impone comunque 60 secondi al harness. Il runner limita ogni comando: normalmente 300 secondi, build native 600, Swift e sanitizer 900, CTest 120. Al timeout termina il gruppo di processi (TERM, poi KILL dopo 3 secondi), registra exit 124 e fallisce. Non cambia timeout o logica del prodotto per accomodare i test.

ASAN usa `detect_leaks=0`: sono controllati gli accessi alla memoria; questa esecuzione non è una verifica delle perdite dei framework Apple. TSAN è mirato ai contratti, ai writer e ai lifecycle interessati, non all'intera GUI. `SIGNUM_TEST_LOCK_REFUSAL_WORKER` indica il worker non strumentato della stessa esecuzione, usato soltanto per il controllo di rifiuto del coordinamento nei test sanitizer.

## Packaging

Le unit test Python non producono un'app distribuibile. Per integrare bundle nuovi usare `scripts/build-beta-app.py --help`, con output in una directory nuova, configurazioni Debug e Release e lo stesso prefix locale. Non installare l'app o sostituire bundle precedenti. Controllare manifest, firma ad hoc, closure delle librerie, minimo macOS e protocolli worker v2/helper v5. I collaudi con dispositivi reali, macOS 13 reale, accessibilità e interazione manuale rimangono separati e non sono impliciti nei risultati sintetici.

Per un bundle appena creato, il controllo riproducibile delle integrazioni è:

```sh
python3 scripts/test-packaged-bindings.py --bundle /nuova/directory/Signum-diagnostic.app
```

Esegue 10 controlli: worker v2 e firma RSA verificata indipendentemente, rifiuto contesto cambiato e v2 incompleto, helper v5 e verifica PAdES, no-overwrite, contesto PAdES cambiato, preflight read-only anche su firma incrementale supportata, directory errata prima dell'autenticazione, checkpoint post-login nel worker e nel helper. I provider sono copie sintetiche locali; le fixture vengono eliminate. Il bundle resta invariato.
