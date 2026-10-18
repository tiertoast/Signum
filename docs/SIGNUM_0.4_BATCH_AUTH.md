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
