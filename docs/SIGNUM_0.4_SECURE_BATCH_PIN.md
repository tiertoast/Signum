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
