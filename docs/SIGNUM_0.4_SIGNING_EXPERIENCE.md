# Signum 0.4-A.3 — Signing Experience

## M1 — Baseline e perimetro

18 ottobre 2026. Branch `codex/signum-0.4-signing-experience` creato da
`a468c42`, candidata 0.4.0/build 2 della Device Discovery. Stato tracciato pulito;
review originale non tracciata preservata, SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
Main rimane `be84a1e`; nessun accesso ad altri repository o a HalleyMac.
Letti i rapporti Device Discovery/progressi e i componenti coinvolti, senza una
nuova review generale. Il collaudo DigitalDNA/DS3 della 0.4-A.2 (discovery,
autenticazione distinta, firme e InfoCamere positivi) è riferito dall'utente.

**Baseline realmente eseguita prima del codice:** Swift **197/197**, zero skip,
con helper nativo esplicito; PKCS#11 **40/40**; PAdES Debug/Release **63/63**.
Evidenze locali `.build/reliability/evidence/04a3-baseline-*.log`.
Solo fixture sintetiche, nessun hardware o PIN personale.

Prima: certificati esclusi visibili, destinazione comune chiesta dentro il
percorso di conferma, colonna sinistra lunga e area CAdES destra poco utilizzata.
Intervento limitato a filtro/preferenze, pianificazione destinazioni, consenso e
workspace. Si conservano policy SG-04, snapshot, worker, lease, verifica e commit
Foundation. Nessun worker batch persistente o ottimizzazione PIN in questa fase.

Milestone: M2 filtro; M3 destinazioni; M4 conferma/PIN; M5 workspace;
M6 regressioni, packaging e istruzioni manuali. Ogni passaggio ha un commit locale.
