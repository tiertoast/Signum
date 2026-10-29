# Preparazione manuale Signum 0.7.0 Beta (arm64, macOS 13.0)

Procedura predisposta in Fase6, **build completa e DMG non eseguiti**.
L'attuale preflight resta bloccato da licenze/schema e dossier sorgenti.
Non equivale al gate RC (NON SUPERATO) né approva una distribuzione Stable.

## Prima di eseguire

Completare i due dossier licenze/schema e PoDoFo, decisioni FTL/MPL o altra
via documentata, sorgenti/patch corrispondenti e accesso reale dei destinatari.
Il gate rifiuta i pending; non modificarli per rendere verde un test.
Confermare numero build Beta, bundle identifier definitivo, inclusione o
esclusione di TrustProbe e note di rilascio approvate. Le note devono indicare
limiti della Beta, requisiti esterni e stato noto M3–M6, senza dichiararli risolti.
Un controllo tecnico dei campi non certifica l'adempimento delle licenze.

Serve un checkout congelato e pulito (anche ignorati), il prefix validato
**in sola lettura**, CMake già disponibile e Xcode/actool già funzionanti.
La procedura non scarica dipendenze, non ricostruisce PoDoFo, non installa tool.
Il solo helper Signum CMake viene costruito, insieme ai prodotti Swift.

## Preflight (default, senza costruire applicazione)

Esempio per Terminale: scegliere percorsi/valori espliciti prima di eseguire;
`BETA_WORK` deve essere un percorso assoluto NUOVO esterno al checkout e agli
alberi preservati, `NATIVE_PREFIX` e `CMAKE` quelli già validati.

```sh
/usr/bin/python3 /Users/andreaoregioni/Developer/Signum-Stabilization/worktree/scripts/prepare-public-beta.py \
  --native-prefix "$NATIVE_PREFIX" --cmake "$CMAKE" \
  --output-root "$BETA_WORK" --build-number "$BETA_BUILD" \
  --bundle-id "$BETA_BUNDLE_ID" --trust-probe exclude \
  --budget-seconds 900
```

Questo comando crea soltanto la nuova cartella e `summary.json`; nessuna app,
DMG, copia di codice nativo o firma. Un preflight rosso termina exit1 ed elenca
i documenti mancanti. Per un successivo tentativo usare una **nuova** cartella:
nessun output esistente è sovrascritto. Il preflight non esegue SDK/build/runtime;
la presenza dei tool non prova ancora l'esito della compilazione.

## Staging futuro, solo su decisione dell'autore

Aggiungere `--build --release-notes "$BETA_NOTES" --signing-mode none` allo
stesso comando, con un nuovo `BETA_WORK`. Default 900s complessivi configurabili,
comprensivi di build, audit e cleanup; timeout del gruppo figli, stop al primo
fallimento. Se il budget non consente il cleanup, `summary.json` riporta
`cleanupIncomplete` e fallimento: recuperare solo quei percorsi di questo run.
Nessuna supervisione lunga Codex è prevista. Usare questo entrypoint per il
limite complessivo: invocare direttamente le recipe storiche non lo fornisce.

Modalità `none`: rimozione delle eventuali firme ereditate sulle copie nello
staging, nessuna identità Apple. Su Apple Silicon il risultato unsigned non è
qualificato per l'esecuzione: runtime smoke saltati esplicitamente. Una prova
locale eseguibile può usare **`--signing-mode adhoc`**, che mantiene smoke e
verifiche di firma locali: non è Developer ID né notarizzazione. La configurazione
storica dei preview e il default ad-hoc delle vecchie recipe restano preservati.
Nessuna delle due modalità autorizza automaticamente la pubblicazione.

## Output e controlli

- `Signum.app`: Release, versione 0.7.0 / nome Beta, build e identifier espliciti;
  macOS13.0, arm64, TrustProbe secondo scelta; scratch Swift/CMake/temp esterno.
- `Signum-0.7.0-beta-arm64.dmg` e `.dmg.sha256`: checksum dei byte del DMG.
- `Signum.app.SHA256SUMS`: hash dei singoli file regolari, relativi alla radice
  dell'app; `Signum.app.symlinks.json` registra i target dei link. Non è un hash
  ambiguo della directory. Il DMG contiene anche un suo inventario SHA256SUMS.
- NOTICE/testi/copyright, dossier sorgenti, catalogo schemi/provenienza e
  BuildManifest nel bundle; note di rilascio e manifest anche nel volume DMG.
- `summary.json`: esito, conteggi, durata, blocchi/fallimenti; sempre
  `publicationQualified:false`. Dettagli stdout/stderr solo dei passi falliti;
  scratch/temp rimossi. Artefatti completati prima di un errore restano per
  diagnosi e non sono promossi a pubblicabili.

I controlli della recipe verificano closure Mach-O, librerie solo nel prefix,
notice/versioni/hash, install name, rpath, assenza di percorsi di sviluppo,
minimo OS misurato, architettura, risorse icona e integrità. Il gate documentale
precede build/copia delle librerie; l'audit della closure reale precede la copia
nello staging. Ad-hoc conserva i controlli runtime e di rilocazione esistenti;
unsigned conserva quelli statici e gli hash, senza simulare un runtime riuscito.

Prima di pubblicare occorrono ancora un candidato effettivo, audit di tutti i
materiali inclusi e sorgenti accessibili, prova di apertura/esecuzione sul minimo
macOS13 e macchina pulita, controllo dell'esperienza Gatekeeper e decisione
esplicita sul canale/firma. Non disabilitare automaticamente le protezioni utente.
Developer ID/notarizzazione restano una decisione di distribuzione, non una
conseguenza del nome Beta. Nessun comando di pubblicazione è contenuto qui.
