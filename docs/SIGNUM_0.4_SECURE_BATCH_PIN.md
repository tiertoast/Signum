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
