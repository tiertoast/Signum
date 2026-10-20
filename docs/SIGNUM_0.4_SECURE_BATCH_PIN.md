# Signum 0.4-A.4.1 — Secure Batch PIN, sperimentale

## M1 — Baseline

18 ottobre 2026. Branch `codex/signum-0.4-secure-batch-pin` da HEAD effettivo
build 5 `4366ed7`, codice `7596f50`. Main resta `be84a1e`; worktree verificati
senza aprire altri checkout. Tracciati inizialmente puliti, review non tracciata
`docs/CODE_REVIEW_SIGNUM_0.3.3_2026-10-17.md` preservata, SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
Alpha/build 4/build 5 preservate. Nessun accesso a HalleyMac.

L'utente riferisce sette CAdES riusciti sulla build 4 e richieste PIN ancora
ripetute sulla build 5, con DigitalDNA/Bit4id/DS3. Non è stata riprodotta questa
osservazione con hardware, né ne viene attribuita la causa.
Regressione baseline Swift avviata con helper PAdES esplicito; esito registrato
in M7 insieme alle altre verifiche. Nessun token/PIN personale/documento reale.

## M2 — Threat analysis e decisioni prima del codice

Un inserimento UI, login USER, login CONTEXT_SPECIFIC e consenso applicativo sono
eventi distinti. In modalità sperimentale possono avvenire **più C_Login** con un
solo inserimento UI. Non viene saltata ALWAYS_AUTHENTICATE.
Riferimento: [OASIS PKCS#11 3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).

| Minaccia | Controllo progettato / limite |
| --- | --- |
| PIN persistente in GUI/coordinatore/job/manifesto | Campo svuotato al submit; nessuna proprietà PIN tra job. Payload binario iniziale separato dal JSON pubblico, stessa pipe privata |
| Copie Swift/JSON/Data | Nuova modalità non serializza il PIN in JSON/Data. String iniziale UI/transitoria inevitabile: azzeramento completo non dimostrabile |
| Swap e letture oltre buffer | Worker riceve direttamente in pagina nativa dedicata, mlock obbligatorio, guard page, lunghezza 1…64, NUL rifiutato; fallimento chiude senza login |
| Riuso su altro contesto | Worker esclusivo per batch/approval ID, modulo canonico e identità, seriale/slot, DER/ID e handle chiave, manifesto immutabile e sequencing |
| Credenziali errate o stato ambiguo | Un tentativo per autenticazione prescritta, nessun retry/relogin dopo errore, sessione perduta o attributo cambiato/indeterminato |
| Memoria vendor / processo compromesso | Isolamento processo, core dump disabilitato, stdout/stderr silenziati; vendor può copiare PIN e un attaccante con privilegi sul processo può leggerlo. Non eliminabile da questo buffer |
| Cancel, timeout, finestra chiusa, crash | Revoca canale e terminazione supervisionata, buffer azzerato prima del teardown normale; SIGKILL/crash affidano rilascio pagine al kernel, non promettono esecuzione di cleanup |
| Esposizione prolungata | Idle massimo 60s e batch massimo 600s con clock monotono, supervisione padre; buffer eliminato appena non serve, sempre prima dell'ultimo commit |

Priorità CAdES, opt-in disattivo per default; Auto e PIN per firma invariati.
True noto permette CONTEXT_SPECIFIC dopo ogni SignInit con lo stesso buffer
worker. False noto elimina subito il buffer dopo il primo job e mantiene solo
la sessione USER. Unknown non riutilizza il PIN; prima firma conserva la policy
precedente e poi chiude. USER perso/sessione invalidata interrompono: non è
dimostrabile una policy sicura di riapertura/riautenticazione automatica (caso C
rinviato). Nessun trasferimento fra worker, PAdES/misti restano per documento.

L'handle della chiave e la policy letta devono restare identici tra job. Il PIN
non autorizza attributi nuovi: ogni richiesta deve corrispondere al manifesto
approvato, verificato nel padre prima di commit senza sovrascrittura. I cambi di
contesto o il fallimento ritirano definitivamente la capability.

## M3 — Buffer nativo

Target `CSecurePIN`: mmap privato, pagina dati tra due guard page, mlock
obbligatorio, ricezione diretta dalla pipe con lunghezza binaria e timeout
monotono. Clear riscrive l'intera pagina con store volatile non eliminabili;
destroy esegue clear prima di munlock/munmap. Nessun percorso di logging.
`explicit_bzero` non è dichiarato dall'SDK macOS usato: il primo tentativo di
compilazione lo ha rilevato, sostituito con l'equivalente a store volatile.
Non dichiarata la cancellazione di eventuali copie Swift/vendor/kernel.

**3/3** test buffer passati: limiti/NUL, ricezione valida/parziale/timeout,
osservazione dei byte posseduti dopo clear, cicli allocazione/distruzione e
processo isolato con RLIMIT_MEMLOCK=0 che rifiuta l'allocazione. Baseline Swift
completa **265/265**, zero skip/fallimenti (`04a41-baseline-swift.log`).

## M4 — Autenticazione nativa

Entry point sperimentali separati, primitive RSA/CMS invariate. Lo shim conserva
solo handle e policy della chiave, mai PIN. True noto: USER iniziale e CONTEXT
dopo ogni SignInit; false: nessun login aggiuntivo. DER/policy locale/token/sessione
controllati ogni volta; cambio handle o attributo ritira la sessione. Errori PIN
incorrect/expired/locked/generici sono terminali. Nessun USER relogin automatico.

Il test nativo iniziale ha esposto prima un conflitto di accesso esclusivo nella
fixture Swift (inout e closure sullo stesso handle), poi una differenza reale
tra la base temporale Foundation uptime e CLOCK_MONOTONIC macOS: il PIN risultava
già scaduto. Fixture corretta; deadline dello shim ora costruita e controllata
con la stessa funzione CLOCK_MONOTONIC. La supervisione usa separatamente la
propria durata uptime. Nessuna riduzione del controllo di scadenza.

Run finale M4 **15/15**: cinque test nativi nuovi (inclusi quattro RV di errore
PIN, nessun retry) e dieci regressioni worker Auto. Log `04a41-m4-auth-clock-fixed.log`.

## M5 — Worker e batch CAdES

Avvio interno v3: manifesto pubblico senza PIN, poi lunghezza 4 byte e PIN
binario (1…64 byte), stessa pipe privata. Il padre usa writev atomico <=68 byte,
senza conversione JSON/Data del segreto; il worker legge direttamente nella
pagina bloccata. Resta una String iniziale transitoria nel submit/stack Swift,
rilasciata dopo la prima operazione, mai catturata dalla continuazione. Il
percorso Auto v2 è conservato; nessuna migrazione del protocollo pubblico.

Batch ID coincide con approval ID e vincola il manifesto; gli attributi CMS
immutabili derivano dai job approvati con snapshot/hash/formato/destinazione
nel padre. Provider canonico/identità, token/slot/DER e handle chiave restano
vincolati. Il worker non riceve documenti né destinazioni. Ogni firma è
verificata RSA/CMS e pubblicata atomicamente prima di richiedere la successiva.

Buffer eliminato dopo la prima firma se non servono altre autenticazioni,
altrimenti subito dopo l'ultima Sign, prima della sua risposta e del commit
finale. Su errore/EOF/finish scade prima di CloseSession/Finalize potenzialmente
bloccanti. Timeout idle 60s e vita massima 600s (limiti interni riducibili nei
manifesti sintetici), supervisione monotona del padre anche durante Sign.
mlock non disponibile produce un rifiuto esplicito **prima di caricare il
provider**, nessun login: serve una nuova sessione con PIN per firma. Gli altri
errori senza firma verificabile mantengono la gestione conservativa dell'incertezza.

Run M5 **40/40**, zero skip/fallimenti (`04a41-m5-delivery.log`): 3/7 CAdES
con un solo valore UI, USER una volta e CONTEXT 3/7 volte, verifica di tutti gli
output, Auto e per-firma, attributo sconosciuto, timeout idle/durata, autenticazione
fallita senza retry, crash/hang/cancel, collisione secondo output, batch/job/ordine
estranei, nuova sessione senza segreto, mlock rifiutato nel worker via limite
risorse ereditato. Il mock sperimentale richiede effettivamente un nuovo CONTEXT
tra SignInit e ogni Sign; non basta contarne le chiamate.

## M6 — Opt-in e UI

Terza modalità «PIN temporaneo per il batch», default ancora Automatica. Solo
il valore della preferenza viene persistito, mai un segreto; la scelta viene
congelata all'approvazione. Descrizione esplicita della conservazione temporanea
e della maggiore esposizione rispetto al PIN per firma. Durante la continuazione
non viene più mostrata la frase «Nessun PIN riutilizzato» in modalità temporanea.
Nessun redesign o conferma modale aggiuntiva. PAdES/misti/identità insufficiente
restano per documento, con spiegazione. Candidata portata a **0.4.0/build 6**.

Run M6 **27/27**, zero skip/fallimenti (`04a41-m6-ui.log`): preferenze isolate,
opt-in/default, modalità congelata come valore, policy formati, coordinatore,
interazione PIN, riepilogo e viste native. Nessun Finder, token o app esterna
avviati. L'accettazione interattiva completa resta da eseguire.

## M7 — Security review mirata

Review locale dell'agente sul diff limitata a buffer/IPC/autenticazione/lifetime,
ownership, bounds, revoca e teardown; **non audit indipendente**. Clang Static
Analyzer eseguito su `secure_pin.c` e `pkcs11_shim.c`, nessuna diagnostica.

Correzioni emerse e verificate prima della consegna:

- Unificato CLOCK_MONOTONIC anche per worker e canale sperimentale: nessun
  confronto tra epoche differenti né prolungamento della durata dopo sleep.
  Scadenza ricontrollata immediatamente prima di C_Login e C_Sign.
- Prima chiamata temporanea restituisce ownership della sessione anche su
  errore: il worker può cancellare il PIN **prima** di CloseSession/Finalize,
  anziché conservarlo durante un eventuale blocco del cleanup nativo.
- Canale inizialmente ritirato fino all'acquisizione dello slot processi:
  inizializzazione rifiutata non rilascia uno slot posseduto da altri canali.
- Buffer: test osserva l'intera pagina dopo clear e i byte parziali dopo errore
  di ricezione; nessun accesso dopo destroy. Test nativo verifica che cleanup
  non sia stato avviato prima che il worker abbia ripreso il controllo.

Test aggiunti: certificato sostituito, handle chiave cambiato, sessione invalida,
USER perso, device removed, modulo mutato, errori PIN USER e CONTEXT, scadenza
prima di ulteriori autenticazioni, manifesto v3 con PIN/limiti invalidi.
Run mirato finale di questa revisione **47/47**, zero skip/fallimenti
(`04a41-m7-security.log`). Un errore di compilazione nella nuova fixture DER
(Data passato a funzione C a puntatore) è stato corretto prima di questo run.
Il successivo controllo completo e sanitizer usa anche le ultime guard di
scadenza prima di Sign e di ownership del contatore processi.

Primo run completo **293/293**, zero skip/fallimenti. I primi run ASAN/TSAN
hanno segnalato quattro assert falliti ciascuno nel solo test di rifiuto mlock:
entrambi i runtime intercettano mlock come no-op. Riprodotto con un probe C senza
PIN e RLIMIT_MEMLOCK=0: il buffer è rifiutato normalmente ma accettato da entrambi
i binari strumentati (`04a41-lock-interceptor.log`). Il controllo OS è quindi
eseguito con un worker **non strumentato esplicito**, anche nei run sanitizer;
tutti gli altri test worker restano strumentati. Override solo nel test,
`SIGNUM_TEST_LOCK_REFUSAL_WORKER`; nessuna eccezione o modifica a mlock nel prodotto.
Non si deduce dai sanitizer che le pagine siano realmente bloccate: questo è
provato separatamente dal runner normale. Log dei primi fallimenti preservati.

## M8 — Candidata e consegna

**Signum 0.4.0/build 6**, macOS arm64, codice **`37d21e8`**, tracciati puliti al
packaging. Rispetto al core verificato `eec717d`, `40eb5ee` corregge soltanto la
fixture sanitizer e `37d21e8` rende dinamica la descrizione del PIN accanto al
consenso: individuata nel rendering una vecchia frase che negava la conservazione
anche in modalità temporanea. Corretta usando la policy congelata del batch,
**14/14** test interazione/preferenze/viste ripassati. Bundle rigenerati su questo
commit in directory delivery nuove; i primi bundle final non sono la consegna.
Rendering nativo della vista con 32 documenti ispezionato, PIN raggiungibile a
650 punti; PNG in `.build/04a41-ui`. La versione 16.0/build 25229 nei PNG è
quella dell'host XCTest, non della candidata. Test PDFKit preservato; nessuna
accettazione interattiva completa o acquisizione pixel completa del PDF dichiarata.

| Controllo finale | Esito |
| --- | --- |
| Swift completo, ripetuto con worker batch e helper PAdES del bundle Release | **293/293**, zero skip/fallimenti, 28 nuovi test rispetto alla baseline |
| PKCS#11 nativo | **40/40** |
| PAdES Debug/Release | **63/63** per configurazione, ripetuti sul bundle e copia rilocata |
| Packaging Python | **10/10** |
| ASAN mirato | **92/92**, zero skip/fallimenti; leak detection disabilitata |
| TSAN mirato | **92/92**, zero skip/fallimenti, nessuna race segnalata |
| Build Swift Debug/Release | Passate |
| Bundle Debug/Release | Passati: firma ad hoc stretta, hash, rilocazione, dipendenze portabili |
| Metadata/Mach-O | 0.4.0/build 6, minimo dichiarato 13.0 e cinque Mach-O minimo 13.0 |
| Analyzer C | Nessuna diagnostica sui due file analizzati |

Sanitizer su buffer C, shim e componenti batch/worker/lifecycle/coordinamento/UI:
non sull'intera suite di 293 casi. Simboli ASAN/TSAN verificati nei due oggetti C;
il mock/vendor e il probe risorse compilati separatamente non sono strumentati.
Il solo test di rifiuto mlock usa un worker normale esplicito, come spiegato in
M7. Nei worker delle candidate verificato il riferimento reale a mlock e
l'assenza dei runtime sanitizer. Nessuna garanzia di pulizia forense della memoria.

Percorsi assoluti delle app, **senza sostituire Alpha o build 5**:

- `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a41-bundles/delivery-release/Signum.app`
- `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a41-bundles/delivery-debug/Signum.app`

Firma locale ad hoc, nessun Developer ID, hardened runtime, notarizzazione o
distribuzione. Verificata anche la firma intatta dei due bundle precedenti
build 5. CLI dei due nuovi bundle provata in discovery solo con provider sintetico.
Target 13 statico: runtime macOS 13/14 e Mac pulito non collaudati.

Evidenze `.build/reliability/evidence/04a41-*`: baseline e milestone, finali
`delivery-swift.log`, `final-swift-validated.log`, `final-asan-validated.log`,
`final-tsan-validated.log`, `final-pkcs.log`, `final-packaging-tests.log`,
`final-build-{debug,release}.log`, `package-{debug,release}.log`,
`delivery-package-{debug,release}.log`, `delivery-bundle-audit.log`,
`bundle-audit.log`, `native-analyzer.log`, `lock-interceptor.log`. I primi log
sanitizer senza suffisso `-validated` conservano il problema del test mlock.

### Riproduzione

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
SIGNUM_TEST_BATCH_WORKER="$PWD/.build/04a41-bundles/delivery-release/Signum.app/Contents/Helpers/SignumPKCS11Worker" SIGNUM_TEST_PADES_HELPER="$PWD/.build/04a41-bundles/delivery-release/Signum.app/Contents/Helpers/signum-pades-local" swift test --scratch-path .build/reliability --jobs 4
scripts/test-pkcs11-local.sh
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build --scratch-path .build/reliability --jobs 4 -c debug
swift build --scratch-path .build/reliability --jobs 4 -c release
```

Per i sanitizer usare scratch distinti, `--sanitize=address`/`thread` e filtro
`SecurePINBufferTests|SecureBatchNativeTests|BatchAuthenticationTests|BatchAuthIntegrationTests|BatchAuthenticationPreferenceTests|BatchWorkspaceSummaryTests|BatchSigningTests|SigningInteractionTests|SigningWorkspaceTests|PKCS11LifecycleIntegrationTests|PKCS11WorkerTests|ProcessCoordinationTests`.
Esplicitare l'helper PAdES come sopra e `SIGNUM_TEST_LOCK_REFUSAL_WORKER` verso il
worker Release normale; **non** impostare SIGNUM_TEST_BATCH_WORKER nel run
sanitizer, altrimenti tutti i test batch userebbero il worker normale. Per ASAN
`ASAN_OPTIONS=detect_leaks=0`. Per PAdES/packaging ripetere
`scripts/build-beta-app.py --configuration debug`/`release`, con
`--native-prefix .build/pr2-native-macos13/prefix` e `--output` nuovo per ogni app;
il packager ricompila e verifica anche helper e copia rilocata. Nessuna
installazione globale necessaria, non sovrascrivere le candidate consegnate.

### Collaudo manuale preparato, non eseguito

Demo `.build/04a41-demo`: sette `.txt` sintetici, PDF, certificato sintetico valido
sette giorni e modulo software. Per questa demo il modulo è ricompilato con
`SIGNUM_MOCK_DEFAULT_ALWAYS_AUTH=1` e `SIGNUM_MOCK_STRICT_CONTEXT=1`: richiede davvero
CONTEXT_SPECIFIC per ogni Sign. Non rappresenta la policy di DigitalDNA o CNS.
Solo preparazione e discovery CLI effettuate, nessuna GUI avviata interattivamente.

1. Solo software: scollegare token reali, aprire l'app **delivery-release** esatta,
   configurare `.build/04a41-demo/synthetic-provider.dylib` e scegliere il
   certificato della demo. Utilizzare esclusivamente una stringa PIN fittizia.
   Impostare «PIN temporaneo per il batch», controllare la descrizione, aggiungere
   tre `.txt`, verificare le destinazioni e approvare una volta. Un inserimento
   deve completare tre firme verificate; ripetere con sette file e destinazioni
   nuove. In Auto/PIN per firma questa fixture deve invece chiedere nuovi PIN.
2. Nuova sessione deve richiedere un nuovo inserimento. Provare annullamento e
   chiusura finestra con documenti sintetici; nessuna prosecuzione dopo revoca.
   PAdES e batch misti devono spiegare la limitazione e chiedere PIN individuali.
3. **Solo dopo intervento/autorizzazione hardware espliciti dell'utente**:
   DigitalDNA + Bit4id + DS3, cartella nuova e documenti sintetici. Ripetere
   prima tre, poi sette CAdES in modalità temporanea. Annotare solo numero
   richieste UI, messaggi di policy, esiti e verifiche con lo strumento abituale;
   mai PIN o trace sensibili. Un inserimento UI non prova un singolo C_Login.
4. Confrontare Auto/PIN per firma in sessioni distinte. Se attributo illeggibile,
   sessione persa o policy non compatibile, è corretto interrompere o passare
   esplicitamente a PIN per documento. Su PIN errato/bloccato/scaduto, errore
   o incertezza fermarsi: nessun tentativo automatico o riuso del vecchio PIN.
5. Ripetere separatamente su CNS se autorizzato; nessun risultato DigitalDNA
   viene trasferito per presunzione a CNS. Verificare tutti gli output e il
   comportamento di cancellazione/nuova sessione prima dell'uso quotidiano.

### Limiti residui

Prototipo verificato solo con provider sintetici: nessun esito hardware nuovo.
PAdES/misti e riapertura automatica di sessioni USER non implementati. Attributo
unknown, inizializzazione non posseduta e identità insufficiente impediscono il
riuso; cambi di handle/policy sono terminali. Timeout/crash possono lasciare
incerta l'operazione hardware, mai un output non verificato: niente retry.

mlock protegge dalla normale paginazione, non da debugger/processo compromesso,
middleware che copia credenziali, letture privilegiate o tutte le diagnostiche
del sistema. Nessun crash report applicativo contiene deliberatamente il PIN;
non si garantisce l'azzeramento di Swift/AppKit/vendor o del kernel. Su kill/crash
il kernel rilascia le pagine: il cleanup esplicito potrebbe non essere eseguito.
Se un processo è non terminabile dal kernel, lo slot resta riservato fino
all'uscita e la chiusura non confermata richiede controllo. Opt-in aumenta la
finestra di esposizione rispetto al PIN per firma. GUI interattiva completa,
middleware reali e comportamento dopo sleep reale restano da collaudare.

SG-01/14, SG-02, SG-03, SG-04, SG-05 e SG-06 preservati dai runner locali.
Nessuna nuova primitiva, formato o integrazione pubblica. Non è un audit
indipendente né una release pubblica.

### Commit e stato finale

M1 `5cbc389`; M2 `31355ce`; M3 `5f49bb4`; M4 `dc07bc3`; M5 `82ee4f5`;
M6 `c4b1b89`; M7 `eec717d`; correzione fixture sanitizer `40eb5ee`;
correzione descrizione consenso `37d21e8`;
M8: commit che contiene questa consegna.

Branch `codex/signum-0.4-secure-batch-pin`. Main invariato `be84a1e` e branch
build 5 invariato `4366ed7`. Unico residuo intenzionale: review non tracciata
preservata con hash M1. Nessun push/merge/tag/release, GitHub Actions,
installazione globale, hardware/PIN reale, altro repository o HalleyMac.
