# Signum 0.6 — Final consolidation, Development Preview Build 2

Baseline `14d959fc76e093806ebcceaf1ec83cbeefbb53b4`; existing branch
`feature/signum-0.6e-verification-reports`.

## Provenienza

Commit sorgente verificato e costruito: `5942ff5fc674a37e512c8371f6f7d486fbe4581e`.
Il manifest sigillato registra `sourceTrackedDirty=false`, versione `0.6.0`,
build `2`, arm64, target minimo `13.0`. Questo rapporto è un successivo commit
esclusivamente documentale: non modifica i sorgenti costruiti e non richiede rebuild.
La provenienza dell’artefatto resta il commit sopra, non il commit di consegna.

Uniche modifiche di consolidamento: abilitazione Build 2 nei packager/smoke
esistenti e relativo controllo di identità. Nessuna modifica a motori, GUI,
crittografia o worker. A/B/C/D/E.1 sono presenti nella campagna integrata.
Burgundy `#64313E` rimane esclusivamente nei rapporti.

## Campagna completa unica

Runner ufficiale `scripts/test-local.py --group complete --skip-sanitizers
--native-prefix ../a3-native-v3/prefix --output-root ../06-build2-campaign`;
ambiente privato PKG_CONFIG_PATH, SIGNUM_TEST_XMLSEC e SIGNUM_TEST_PYTHON come
nella 0.6 precedente. Nessuna installazione o CI remota.

- **631 test Swift**: Core 472, CertificateValidation 101, TrustAuthentication 34,
  TrustCore 19, TrustIntegration 5. Inclusi CAdES avanzato, XAdES, ASiC,
  validazione corrente/storica ed esportazione PDF/TXT (17 test rapporti).
- PAdES: **81 casi Debug + 81 Release**.
- PKCS#11: **58 casi provider + 2 contratti loader**, worker sintetico nei test Swift.
- **19 contratti runner/packaging**.
- **0 fallimenti, 0 skip**; nessuna correzione successiva o ripetizione di suite.
  Sanitizer non ripetuti: nessuna modifica ai motori o al codice nativo.

Log originali: `work/06-build2-campaign/20261022T062618Z-670b746b3a`.
Evidenze e riepilogo: `outputs/signum-0.6-build2/results.json`,
`runner-results.json`, `campaign.log`, `build.log`, `validation/`.
Warning non bloccanti conservati: define pkg-config xmlsec filtrati da SwiftPM;
percorsi PCM rimappati non trovati da dsymutil. Build, audit binari e firma superati.

## Packaging e avvio

Controlli superati: chiusura dipendenze native incorporate, arm64 e minimum OS di
ogni Mach-O, loader-relative dependencies/rpath, rifiuto percorsi di sviluppo,
hash del codice annidato, codesign ad hoc strict/deep, helper/worker sintetico,
rilocazione e avvio GUI con PATH solo di sistema e audit delle librerie caricate.
Il processo GUI di smoke viene terminato al termine: i log diagnostici sono finali.

Cache e preferenze isolate nel dominio
`io.github.tiertoast.Signum.DevelopmentPreview.V06.B2`, distinto da 0.5 e Build 1.
Per il solo smoke è stata copiata nel dominio nuovo la cache pubblica EU/IT già
presente della Build 1; riautenticata offline, freshness corrente, byte invariati.
Nessuna preferenza precedente importata; nessuna migrazione automatica aggiunta.
ZIP estratto: byte, permessi e symlink identici, manifest intatto, codesign verificato.
Host effettivo macOS 27.2; esecuzione su macOS 13 **non testata**.
Nessun token reale, PIN o documento personale utilizzato.

## Consegna e limiti

Directory `outputs/signum-0.6-build2/`:

- `Signum 0.6 Development Preview — Build 2.app`
- `Signum 0.6 Development Preview — Build 2.zip`
- `BuildManifest.json`, `SHA256SUMS.txt`, `bundle-inventory.json`, `results.json`
- `RELEASE_NOTES_PRELIMINARY.md`, `MANUAL_ACCEPTANCE.md`

ZIP SHA-256: `4ad6a8b625af27449ee0963f0608f957d56d80109ec69e2b1f7b82e093424c75`.

Note preliminari e checklist: `docs/archive/SIGNUM_0.6_BUILD2_RELEASE_NOTES.md`.
Restano i sottoinsiemi XAdES/ASiC/CAdES avanzato dichiarati, i limiti eIDAS
IT/AT/DE/BE/FR/ES diretti CA/QC post-2016 con evidenze sufficienti, la firma ad hoc
senza notarizzazione e il collaudo manuale hardware ancora da eseguire.
Nessuna equivalenza DSS, certificazione generale, LTV o LT/LTA dichiarata.

Beta 0.5 e Preview Build 1 conservate; nessuna PR, merge, tag, release, GitHub
Action, redesign o modifica a HalleyMac. Attendere il collaudo prima di pubblicare.
