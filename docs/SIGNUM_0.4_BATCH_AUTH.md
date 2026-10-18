# Signum 0.4-A.4 — Batch Authentication & Signing Workspace

## M1 — Baseline

18 ottobre 2026. HEAD effettivo build 4 `51e9d22`, codice candidato `daca4cf`.
Nuovo branch `codex/signum-0.4-batch-auth`. Tracciati puliti, review non tracciata
preservata (SHA-256 `2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`).
Worktree verificati senza aprire altri checkout; main resta `be84a1e`.
Nessun accesso a HalleyMac. Il collaudo di sette CAdES DigitalDNA/Bit4id/DS3
riusciti sulla build 4 è riferito dall'utente, non eseguito qui.

Baseline locale: Swift **240/240**, PKCS#11 **40/40**, PAdES Debug/Release
**63/63** ciascuno; build Swift Debug/Release passate. Helper esplicito, fixture
solo sintetiche; log `.build/reliability/evidence/04a4-baseline-*`.
Alpha e candidati precedenti preservati. Nessun PIN reale/hardware/CI remoto.

## M2 — Analisi e confine architetturale

Riferimento funzionale aggiunto dall'utente: InfoCamere consente più documenti
con un solo inserimento PIN, sia DigitalDNA sia CNS. Evidenza d'uso, non prova
di sessioni PKCS#11, cache PIN, servizi o protocolli interni. Nessuna attribuzione
di un meccanismo a InfoCamere o capability dedotta da marca/label.

Riferimento normativo: [OASIS PKCS#11 3.1, C_Login e CKA_ALWAYS_AUTHENTICATE](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).
USER e CONTEXT_SPECIFIC hanno ruoli distinti; ALWAYS_AUTHENTICATE true richiede
autenticazione per uso dopo SignInit. Il riuso di una sessione USER non autorizza
a saltarla. Un login già esistente non prova la verifica del PIN appena fornito.

Il percorso attuale avvia SignumPKCS11Worker per ogni job, acquisisce lease,
Initialize/OpenSession, verifica DER/policy, login USER, FindObjects/SignInit,
eventuale login CONTEXT_SPECIFIC, Sign, CloseSession e Finalize. Nessun Logout
indiscriminato. Registry in-process distingue ownership Initialize, ma non unisce
processi. Il lease provider/slot coordina solo processi Signum cooperanti.

Decisione: prototipo **CAdES** con worker dedicato al batch e protocollo interno
incorniciato/bounded. Manifesto immutabile di job e attributi CMS, nessun documento
o percorso input/output nel worker. Padre conserva snapshot, verifica RSA/CMS e
pubblicazione atomica. Un job successivo viene richiesto soltanto dopo il commit
verificato del precedente: nessuna pre-firma della coda e nessun retry di Sign.

Primo PIN autentica USER e il primo job. Attributo leggibile false, identità
token stabile, inizializzazione posseduta e sessione valida consentono il riuso.
True richiede CONTEXT_SPECIFIC per il primo job e chiusura, poi percorso one-shot
con un nuovo PIN per ogni documento; attributo sconosciuto conserva il percorso
conservativo. PIN non mantenuto per le richieste successive. Errori/disconnessione/
timeout/crash interrompono il canale; nessun fallback automatico di un job incerto.

PAdES usa un altro processo/lease e non può condividere un handle PKCS#11.
Deferita la modifica del protocollo PoDoFo; batch PAdES e misti restano one-shot,
con spiegazione esplicita. Nessuna promessa di ottimizzazione universale o di
compatibilità hardware prima del collaudo autorizzato.
