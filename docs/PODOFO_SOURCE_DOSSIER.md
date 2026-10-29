# PoDoFo: dossier locale dei sorgenti e della ridistribuzione

Stato corrente Fase6b: S09 PARZIALE. Scelte definitive MPL2.0 / FTL applicate; archivi attesi recuperati e verificati; consegna source-with-artifact predisposta. Patch e corrispondenza integrale dei binari restano non attestate. Vedere aggiornamento Fase6b in fondo e FREETYPE_DOSSIER.md. Le sezioni Fase4–6 seguenti conservano la ricostruzione storica; i relativi pending decisionali sono superati dal nuovo aggiornamento. Nessuna pubblicazione o ricompilazione.

## Fatti e provenienza

Il prefix nativo autorizzato contiene `signum-native-build.json`: PoDoFo 1.1.2, archivio atteso SHA-256 `d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a`, recipe 1, arm64, deployment target 13.0. Gli header installati dichiarano 1.1.2. `podofo/podofo.h` reca `SPDX-License-Identifier: LGPL-2.0-or-later OR MPL-2.0`. I due testi copiati byte per byte dai notice del prefix sono `PoDoFo-LGPL.txt` (titolo GNU LIBRARY GENERAL PUBLIC LICENSE, Version 2, June 1991, con eccezione OpenSSL nella sezione 17) e `PoDoFo-MPL.txt` (Mozilla Public License Version 2.0). Non sostituire il primo con LGPL 2.1.

`otool -L` sull'helper costruito e sulla closure mostra `@rpath/libpodofo.4.dylib`, risolto nel prefix a `libpodofo.1.1.2.dylib`: collegamento DINAMICO, non una copia statica di PoDoFo nell'helper. FreeType 2.13.3 è costruito staticamente (`libfreetype.a`) dalla recipe e simboli definiti `_FT_*` sono esportati dalla dylib PoDoFo; non c'è una dylib FreeType nella closure. OpenSSL 3.5.6 e libxml2 2.15.4 sono dinamici. Il valore minimo Mach-O non prova l'esecuzione su macOS 13.

I percorsi assoluti locali, gli hash dei binari costruiti, i comandi e la closure sono conservati nel registro esterno della Fase 4 (`local-dependency-inventory-base.json`, `s08-coverage-proof.json`, `s09-local-facts.log`). Questo dossier portabile non incorpora percorsi personali.

| Componente PoDoFo / incorporato | Evidenza/versione locale | Testi distribuiti | Limite |
|---|---|---|---|
| PoDoFo | 1.1.2 da header e metadata | PoDoFo-LGPL.txt e PoDoFo-MPL.txt | alternativa da scegliere; sorgente non attestato |
| FreeType | 2.13.3 da metadata/header, statico in PoDoFo | FreeType-license.txt, FreeType-FTL.txt | FTL e alternativa GPL descritte dal testo; GPLv2 e notice per singolo modulo non reperiti |
| Chromium PDFium | snapshot incluso secondo recipe; revisione autonoma NON VERIFICABILE | PoDoFo-PDFium.txt | testo composito, non attribuire un singolo SPDX all'intero file |
| Chromium numerics | snapshot incluso secondo recipe; revisione autonoma NON VERIFICABILE | PoDoFo-numerics.txt | testo a tre clausole; versione da reperire |
| LiberaLean | dati font incorporati secondo recipe; versione NON VERIFICABILE | PoDoFo-LiberaLean.txt | SIL OFL 1.1 scritto nel testo; Copyright include 2026, non prova provenienza del sorgente |
| Foxit fonts | dati incorporati secondo recipe; versione NON VERIFICABILE | PoDoFo-Foxit.txt e PoDoFo-PDFium.txt | rinvio BSD-style censito insieme al testo PDFium; scope/file corrispondenti da attestare |

La matrice di componenti incorporati deriva dalla recipe e dai materiali installati. Senza albero sorgente originale non è un inventario esaustivo a livello di ogni translation unit o modulo FreeType. Il controllo closure→notice è tecnico e conservativo; non certifica completezza legale.

## Sorgenti, patch e corrispondenza

Archivio PoDoFo originale: **NON VERIFICABILE: da reperire** nei percorsi consentiti. Il digest dichiarato nel metadata è un identificatore atteso, non prova che il binario sia stato ottenuto da quei byte. Non si è ispezionato alcun percorso del checkout originale fuori dal prefix autorizzato. Non si usano sorgenti di altre versioni o bottle Homebrew al posto dell'archivio approvato.

Patch locali e diff rispetto all'upstream: **NON VERIFICABILE: da reperire**. La recipe corrente non contiene un passo esplicito di patch PoDoFo; ciò non attesta che il binario preesistente non sia stato modificato. Sono documentate configurazione CMake, librerie disabilitate, file-prefix-map e riscritture degli install name OpenSSL; non confonderle con un confronto del sorgente upstream. Occorrono archivio verificato, estrazione di riferimento, diff completo rispetto ai sorgenti usati e registro dei comandi/toolchain.

Corrispondenza binario ↔ sorgente: **NON ATTESTATA**. L'helper Signum è stato ricostruito dal worktree con il prefix già disponibile e CTest Debug/Release eseguito; la libreria PoDoFo del prefix non è stata ricostruita in questa fase. Nessuna promessa di riproducibilità bit per bit. Per completare il dossier registrare anche hash dei sorgenti FreeType/OpenSSL/libxml2 e dei sottocomponenti PoDoFo, toolchain/SDK, flag, modifiche e output prima/dopo firma o install-name rewrite.

## Comandi di ricostruzione/ricollegamento

Comandi preparati, **NON ESEGUITI** per la ricostruzione di PoDoFo: richiedono sorgenti corrispondenti approvati, già disponibili offline. Impostare `SOURCE_ROOT`, `BUILD_ROOT`, `NATIVE_PREFIX`, `CMAKE` a percorsi assoluti esterni al checkout; `BUILD_ROOT` deve essere nuovo. `NATIVE_PREFIX` deve contenere OpenSSL 3.5.6, FreeType 2.13.3 statico, libxml2 2.15.4 e i relativi header/CMake metadata corrispondenti, non librerie di altre versioni. Il prefix originale resta in sola lettura: usare un nuovo staging per una ricostruzione completa.

```sh
/usr/bin/shasum -a 256 "$SOURCE_ROOT/podofo.tar.gz"
# Verificare il digest d6ffe6fc... prima di estrarre l'archivio approvato.
/usr/bin/tar -xzf "$SOURCE_ROOT/podofo.tar.gz" -C "$SOURCE_ROOT"
SDKROOT=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
MACOSX_DEPLOYMENT_TARGET=13.0 "$CMAKE" \
  -S "$SOURCE_ROOT/podofo-1.1.2" -B "$BUILD_ROOT/podofo" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$BUILD_ROOT/relinked-prefix" \
  -DCMAKE_PREFIX_PATH="$NATIVE_PREFIX" -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT="$SDKROOT" \
  -DCMAKE_C_FLAGS="-ffile-prefix-map=$SOURCE_ROOT=." \
  -DCMAKE_CXX_FLAGS="-ffile-prefix-map=$SOURCE_ROOT=." \
  '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local' \
  -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF \
  -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=TRUE \
  -DPODOFO_BUILD_LIB_ONLY=ON -DPODOFO_BUILD_STATIC=OFF \
  -DPODOFO_WITH_FONTMANAGER=OFF -DPODOFO_WITH_AFDKO=OFF \
  -DOPENSSL_ROOT_DIR="$NATIVE_PREFIX" -DOPENSSL_USE_STATIC_LIBS=FALSE \
  -DFREETYPE_LIBRARY_RELEASE="$NATIVE_PREFIX/lib/libfreetype.a" \
  -DFREETYPE_INCLUDE_DIRS="$NATIVE_PREFIX/include/freetype2" \
  -DLIBXML2_INCLUDE_DIR="$NATIVE_PREFIX/include/libxml2" \
  -DLIBXML2_LIBRARY="$NATIVE_PREFIX/lib/libxml2.dylib" \
  -DCMAKE_DISABLE_FIND_PACKAGE_JPEG=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_PNG=TRUE \
  -DCMAKE_DISABLE_FIND_PACKAGE_TIFF=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_LCMS2=TRUE \
  -DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=TRUE
"$CMAKE" --build "$BUILD_ROOT/podofo" --parallel 6
"$CMAKE" --install "$BUILD_ROOT/podofo"
```

Il ricollegamento dell'helper, dal checkout Signum autorizzato, usa `Tools/PAdESPrototype/CMakeLists.txt` e richiede il target `podofo::podofo` esattamente 1.1.2. Per verificare una libreria modificata usare il nuovo prefix come primo elemento di ricerca e un rpath coerente; verificare poi `otool -L`, install name, dipendenze private e test. Esempio preparato:

```sh
MACOSX_DEPLOYMENT_TARGET=13.0 "$CMAKE" \
  -S "$SIGNUM_ROOT/Tools/PAdESPrototype" -B "$BUILD_ROOT/helper" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DCMAKE_PREFIX_PATH="$BUILD_ROOT/relinked-prefix;$NATIVE_PREFIX" \
  -DOPENSSL_ROOT_DIR="$NATIVE_PREFIX" \
  -DCMAKE_BUILD_RPATH="$BUILD_ROOT/relinked-prefix/lib;$NATIVE_PREFIX/lib" \
  -DSIGNUM_BUILD_OFFLINE_TESTS=ON
"$CMAKE" --build "$BUILD_ROOT/helper" --parallel 4
"$CTEST" --test-dir "$BUILD_ROOT/helper" --output-on-failure
/usr/bin/otool -L "$BUILD_ROOT/helper/signum-pades-local"
```

Queste istruzioni descrivono un percorso tecnico per chi possiede il worktree. Non sono ancora un kit accessibile al destinatario di un repository privato. La recipe completa `scripts/build-preview-native.py` usa oggi archivi in `.build/preview-native-src` e default tool locali: non è stata lanciata qui, né si inventano flag esterni inesistenti; la predisposizione di scratch/archivi per la RC resta T07/Fase 5. I comandi realmente eseguiti in Fase 4, con timeout esterno e ambiente controllato, sono nei log esterni e nel rapporto.

## Fatti dai testi e rischi da verificare

MPL 2.0, §§3.1–3.2: il testo richiede disponibilità del Source Code Form del Covered Software e informazione ai destinatari su come ottenerlo con mezzi ragionevoli e tempestivi, a costo non superiore alla distribuzione; §§3.3–3.4 trattano Larger Work e conservazione dei notice. L'estensione ai file realmente coperti va verificata sull'albero sorgente corrispondente.

GNU Library GPL versione 2 locale, §§4–6: il testo tratta distribuzione della libreria in forma oggetto/eseguibile con sorgente corrispondente, opere che usano la libreria e condizioni per modifica/debug/ricollegamento. §6a descrive materiale sorgente e/o oggetto sufficiente a ricostruire l'eseguibile; §6b descrive un'offerta scritta valida almeno tre anni con costo limitato; §6c accesso equivalente e §6d materiali già ricevuti. La semplice presenza di una dylib non dimostra da sola ogni condizione né un'esenzione automatica. Applicabilità concreta, eccezione OpenSSL e compatibilità dei file incorporati richiedono verifica sulla via scelta.

FreeType-license.txt descrive FTL e alternativa GPL; FTL contiene condizioni e attribuzione documentale. Testi per singoli moduli/gzip/BDF/PCF e l'alternativa GPL citati dal file non sono tutti reperiti qui. S17 (credito esplicito) è assegnato ma non trattato; nessuna decisione di licenza FreeType è inferita. PoDoFo-PDFium.txt è composito; Foxit rimanda a PDFium; conservare entrambi e verificare l'ambito sui sorgenti. Non si deduce una licenza di tutte le risorse dalla licenza principale Signum.

## DECISIONI DELL'AUTORE

Il repository Signum è privato: un link ad esso non dà accesso ai destinatari. Il file LICENSE attuale di Signum resta Apache 2.0; non si sceglie qui un modello futuro né si pubblica l'intero prodotto. Occorre scegliere una via PoDoFo fra quelle effettivamente autorizzate dagli header e verificare il materiale corrispondente, senza presumere che una scelta renda automaticamente completa la distribuzione.

| Alternativa per offrire i sorgenti | Vantaggi | Conseguenze e verifiche |
|---|---|---|
| Sorgenti coperti, patch e recipe nello stesso DMG | accesso offline e versione congelata insieme ai binari | reperire/attestare tutti i sorgenti coperti; dimensione e manutenzione; definire perimetro senza esporre materiale privato estraneo |
| Offerta scritta | pacchetto iniziale più piccolo | non è una scorciatoia automatica MPL; verificare la via applicabile; nel testo LGPL §6b impegno almeno triennale e materiale §6a, canale reale e capacità di adempimento |
| Repository pubblico dei soli sorgenti coperti | accesso diretto e storico versionato | decisione di pubblicazione esplicita, tag/hash coerenti per artefatto e disponibilità mantenuta; nessuna pubblicazione svolta |

Impostazione conservativa e reversibile: directory predisposta senza archivi fittizi, stato pending incluso nel packaging locale, nessuna istruzione al destinatario inventata e nessuna approvazione di distribuzione. Completare il dossier e il gate `--require-ready` prima di valutare la RC. Anche quel passaggio controllerà dichiarazioni e hash, non emetterà un parere legale né proverà autonomamente la corrispondenza sorgente/binario.

## Controlli riutilizzabili

`scripts/notices_contract.py` deriva la closure Mach-O e controlla versioni e notice contro hash locali approvati, includendo le componenti incorporate censite. `scripts/podofo_source_contract.py` verifica la coerenza di questo dossier con quella prova e con il metadata nativo. Modalità ordinaria: verde strutturale consentito con elenco esplicito dei pending. `--require-ready`: rosso finché archivio verificato, inventario patch, attestazione di corrispondenza, scelta dell'autore e istruzioni al destinatario mancano. I casi sintetici corretti/errati del verificatore sono separati dalle prove sui binari reali.

## Aggiornamento Fase 5b — materiali mancanti, nessuna scelta automatica

Ricerca dei nomi archivio PoDoFo nell'albero Signum-Stabilization (esclusi i
database Git): nessun .tar/.tar.gz/.tar.xz/.tgz/.zip corrispondente presente.
Il checkout originale e gli altri repository non sono stati cercati. Mancano:
archivio1.1.2 SHA d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a,
albero effettivamente compilato, patch/diff, registri di build e corrispondenza
con il binario; archivi e notice per-file degli incorporati, revisioni PDFium/
numerics/font, elenco moduli FreeType realmente collegati.

Il credito FreeType è ora esplicito in FreeType-acknowledgment.txt, incluso nel
catalogo dei notice. Restano da decidere FTL/GPL per FreeType, MPL/LGPL per
PoDoFo e il canale effettivo per i sorgenti coperti, con istruzioni accessibili
ai destinatari. Nessun campo pending è promosso a verified. Non si sceglie una
via legale né si rende pubblico materiale. Vedere SCHEMA_LICENSE_DOSSIER.md
per XAdES/W3C/DSS: sono un perimetro separato dalla closure nativa.

## Fase 6 — raccomandazione all'autore e recupero documentale

**Raccomandazione condizionata, non selezione:** FreeType sotto **FTL** e
PoDoFo sotto **MPL 2.0**, dopo il recupero e l'attestazione dei materiali.
`podofo.json.selectedLicense`, `distributionRoute` e il campo FreeType
`licenseSelection` rimangono pendenti. Apache 2.0 principale invariata.

FreeType: [documentazione ufficiale](https://freetype.org/license.html) e testi
locali confermano la doppia via. FTL permette distribuzione binaria con il
credito FreeType Team già presente; conservare il testo e gli avvisi, senza
attribuire un anno inventato. In caso di sorgenti, mantenere FTL/copyright e
indicare le modifiche. La formula di copyright preferita è incoraggiata, non
obbligatoria. FTL non impone di ripubblicare tutto Signum sotto GPL. Restano da
verificare le licenze autonome dei moduli realmente incorporati. GPL-2.0-or-later
richiederebbe invece testo completo, scelta della versione applicabile e
verifica degli obblighi sull'opera combinata: [Apache chiarisce](https://www.apache.org/licenses/GPL-compatibility.html) che Apache 2.0 non è compatibile con
GPLv2-only; una via GPLv3 può essere valutata, senza dedurre che sia già scelta
né che FTL sia compatibile con ogni alternativa GPL. L'attuale preflight non
qualifica una via GPL FreeType senza ulteriore documentazione.

PoDoFo: [COPYING.MPL upstream 1.1.2](https://github.com/podofo/podofo/blob/1.1.2/COPYING.MPL)
e [FAQ ufficiale MPL](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) sono stati
consultati come documenti. La MPL consente un Larger Work con altri termini,
con copyleft sui file coperti: mantenere avvisi e testi, rendere disponibili
sorgenti corrispondenti e modifiche dei file coperti e dire ai destinatari
come ottenerli (§§3.1–3.4). Per questa Beta suggerisco un archivio completo dei
sorgenti coperti insieme all'artefatto, oppure un URL pubblico accessibile
che identifichi esattamente versione/patch. Un'offerta scritta generica o un
link al Signum privato non soddisfano automaticamente la MPL. I testi degli
incorporati PDFium/numerics/font/FreeType mantengono efficacia autonoma.
La via Library GPLv2-or-later resta possibile solo verificandone concretamente
sorgenti, avvisi, modifica/debug e ricollegamento (§6), compresa l'eccezione
OpenSSL applicabile. Il collegamento dinamico da solo non chiude tali obblighi.
È un confronto documentale, non una valutazione legale definitiva.

**Materiali esatti da fornire, senza ricostruzione automatica:**

| Materiale / provenienza attesa | Destinazione proposta o riferimento | Perché manca |
|---|---|---|
| `podofo.tar.gz` originale usato, URL d'origine e data di acquisizione | `Resources/ThirdPartySources/podofo.tar.gz`, SHA256 `d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a` | la recipe conserva nome/hash/versione, non l'URL; il tag pubblico non attesta l'archivio effettivo |
| Albero compilato, diff completo dall'archivio, eventuali patch o attestazione documentata di diff vuoto | nuovo dossier sorgenti fornito dall'autore, poi riferimenti in `podofo.json` | assenza di un passo patch nella recipe non prova assenza di modifiche |
| Registro build originale, toolchain/SDK/flag, hash prima/dopo install-name rewrite e binari del prefix | dossier esterno dell'autore, in sola lettura per il confronto | provare la catena sorgente/binario senza presumere riproducibilità bit per bit |
| Sorgenti FreeType2.13.3, moduli realmente collegati e notice per-file; sorgenti/revisioni PDFium, numerics, LiberaLean e Foxit effettivamente incorporati | archivio PoDoFo effettivo e archivi originali delle dipendenze | revisioni autonome e scope non attestati; non scaricare snapshot arbitrari |
| Decisione MPL/LGPL, FTL/GPL, modalità di accesso e istruzioni reali ai destinatari | `Resources/ThirdPartySources/podofo.json`, `scripts/third-party-notices.json` e istruzioni distribuite | decisione dell'autore e disponibilità effettiva, non automatizzabili con un flag |

OpenSSL3.5.6, libxml2 2.15.4 e xmlsec1.3.12 rimangono quelli censiti nella
recipe e nei notice. La nuova procedura riusa soltanto il prefix autorizzato,
non li installa né li aggiorna. Gli hash attesi della recipe non sostituiscono
la tracciabilità dei binari. Nessun pending è promosso ad attestato in Fase6.

## Fase6b — decisioni applicate e materiali effettivamente recuperati

**Stato corrente (supera i pending decisionali delle sezioni storiche):**
PoDoFo1.1.2 sotto **MPL2.0**, FreeType2.13.3 sotto **FTL**, su decisione esplicita
dell'autore. I termini autonomi degli incorporati restano conservati; Apache2.0
principale invariata. Non si applica MPL ai tools GPL né FTL all'intero archivio.

Archivio PoDoFo dal repository ufficiale:
https://github.com/podofo/podofo/archive/refs/tags/1.1.2.tar.gz
(endpoint codeload registrato in SOURCE_INVENTORY.json), **SHA256 esatto atteso**
`d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a`.
Conservato intero in Resources/ThirdPartySources/podofo.tar.gz. COPYING.MPL
SHA256 `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85`
identico al testo locale già distribuito; NOTICE originale conferma l'alternativa
MPL per src/. Recuperati anche tutti i sorgenti vendorizzati presenti e i loro
notice: PDFium, numerics, LiberaLean, Foxit, SASLprep, date, fmt, fast_float,
utf8proc, utf8cpp, tcb-span; incluso conservativamente il testo Adobe AFDKO,
senza dichiararne l'uso effettivo. Identità dei singoli snapshot fissata dagli
hash dei membri nell'archivio verificato, senza inventare revisioni autonome.

La fonte rivela termini autonomi aggiuntivi rispetto al vecchio inventario
ridotto. NOTICE upstream completo e testi leggibili sono ora nel catalogo dei
notice del bundle. SASLprep dichiara MIT nel proprio header SPDX: aggiunto il
testo standard MIT dalla fonte SPDX registrata, con copyright originale. Il
rinvio tcb-span a Boost è accompagnato dal grant Boost originale incluso nel
vicino utf8cpp. utf8proc.c richiama un copyright nel file dati che non è presente
in quel file dell'archivio: registrata la lacuna nell'inventario, senza attribuire
automaticamente una versione della licenza Unicode. Verificarne provenienza e
termini nel dossier del sorgente effettivamente compilato.

**Confronto non eseguibile:** 141 header PoDoFo installati sono identici agli
originali; podofo_config.h è generato. Otto testi licenza PoDoFo/FreeType
confrontati sono identici. Configurazioni FreeType confrontate separatamente.
Hash del binario PoDoFo esistente:
`507715d29303a86b9ecf1618e9219d1cef47021534916dce46826dc9b33ddb96`.
Hash di libfreetype.a esistente:
`2068e8a4fdee1c76ac1b8bb41b6f895a861ff80209ff08f3b22af2373fe116e0`.
Dettagli in Evidence/native-comparison.json. Questi riscontri NON provano i
sorgenti privati di ogni oggetto compilato: **patchStatus unknown e
sourceCorrespondence unattested restano aperti**. Nessuna ricostruzione.

Modalità concreta predisposta: **source-with-artifact**, archivi originali e
istruzioni in Resources/ThirdPartySources/SOURCE_ACCESS.md, copiati dalla recipe
esistente dentro l'app. Il destinatario non dipende dal repository Signum
privato. Prima di consegnare occorrono albero realmente compilato, patch/diff o
prova documentata di diff vuoto, log originale toolchain/SDK/flag e collegamento
ai binari. Il kit è quindi predisposto ma non ancora qualificato come sorgente
corrispondente. Il gate rimane rosso su quelle due attestazioni mancanti.

## Fase7 — nuova catena controllata, checkpoint manuale

La carenza del vecchio build non viene sanata inventando un registro:
`rebuild-beta-native.py` prepara una NUOVA compilazione esterna FreeType/PoDoFo
con gli archivi verificati, confronto integrale sorgenti prima/dopo, zero patch
soltanto se quel confronto riesce, toolchain/SDK/flag e dipendenze registrati.
OpenSSL/libxml2/xmlsec vengono copiati dal prefix approvato in sola lettura,
identificati con hash e riscritti soltanto sulle copie; non si dichiara che
siano stati ricompilati. Vecchi FreeType/PoDoFo non vengono copiati nel nuovo
prefix. Tutto resta isolato; nessuna adozione automatica del vecchio binario.

Il problema Unicode è ora documentato: i tre file utf8proc.c/.h/_data.c vendorizzati
sono identici all'upstream ufficiale JuliaStrings/utf8proc v2.11.3, recuperato
come archivio SHA256abfed50b6d4da51345713661370290f4f4747263ee73dc90356299dfc7990c78.
La LICENSE.md di quella esatta versione include espressamente utf8proc_data.c
e i suoi termini Unicode. Testo completo aggiunto ai notice con hash; confronto
conservato in Evidence/utf8proc-2.11.3-comparison.json. Nessun ricorso alla licenza
Unicode corrente per analogia. Nella nuova build il modulo è compilato dentro
PoDoFo secondo la recipe; è previsto anche un controllo mirato di normalizzazione
compatibile e rifiuto UTF8 non valido. Non dichiarato eseguito in questa fase.

Il driver deve verificare collegamento/caricamento della nuova PoDoFo tramite
l'helper Signum e il CTest offline esistente, oltre a architettura, minOS13,
closure e notice. Solo dopo TUTTI i controlli e il cleanup riusciti produce
`verified-native-checkpoint`, kit sorgenti con attestazione limitata al NUOVO
prefix e manifest portabile. Il dossier globale e il prefix originale restano
unattested. I risultati reali vanno letti al checkpoint prima di selezionare
il nuovo kit per il candidato; non si indebolisce il gate di packaging.
