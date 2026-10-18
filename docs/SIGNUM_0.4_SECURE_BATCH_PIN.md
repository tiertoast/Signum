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
