# Development Preview — Build 5

Sorgente eseguibile: `30056c83c6f2438954dde61fedf90fe102a7f84b`
(`0.5-D: eIDAS qualification`), worktree pulito al packaging. Questa nota è un
commit separato di documentazione: non cambia eseguibili o comportamento.

Bundle locale:
`outputs/Signum 0.5 Development Preview — Build 5.app`, nella directory del task
che contiene `work/Signum`. Identificativo
`io.github.tiertoast.Signum.DevelopmentPreview.B5`, versione 0.5.0, build 5,
arm64, deployment target 13.0, firma ad hoc. Dipendenze native private A.3 riusate;
nessuna installazione Java/Homebrew richiesta a runtime. Build 4, A.3 e Beta 0.4
non sono state sovrascritte. Cache TL e revoche separate mediante ID B5.

Collaudo finale: packaging Release, audit della chiusura Mach-O e rpath, codesign
`--deep --strict`, copia del bundle in un altro percorso, verifica della copia,
avvio GUI (viva dopo quattro secondi, poi terminata dal test) e verifica del solo
documento InfoCamere indicato dall’utente. PATH esclusivamente di sistema,
nessun override delle directory di ricerca dylib; caricamenti runtime controllati.
Il catalogo LOTL/AgID di produzione è stato riautenticato dalla cache corrente.
Il documento personale non è copiato nel repo, nel bundle o negli archivi.

Esito InfoCamere: una firma, integrità verificata, catena verificata verso il
servizio CA/QC italiano autenticato, revoca good. Nessuna signature-time-stamp
utilizzabile: tempo notProven e qualificazione indeterminate. La data dichiarata
non è stata usata per produrre QES. Non si pretende una classificazione positiva
in assenza delle evidenze richieste.

La campagna completa e i limiti sono registrati in
[SIGNUM_0.5D_QUALIFICATION.md](SIGNUM_0.5D_QUALIFICATION.md).
Confronto esecutivo DSS offline non effettuato. Il test runtime è su macOS 27.2;
macOS 13 non è stato eseguito. Firma locale non notarizzata.

Riproduzione del solo collaudo del bundle (il percorso di output deve essere nuovo):

```sh
python3 scripts/test-preview5-bundle.py \
  --bundle '/percorso/Signum 0.5 Development Preview — Build 5.app' \
  --output-root /percorso/nuovo-collaudo \
  --trusted-cache /percorso/cache-autenticata/verified.json \
  --infocamere-document /percorso/documento-locale.pdf.p7m
```

I log locali `work/d-final-campaign`, `work/d-final-sanitizers.log`,
`work/d-preview-package-final.log` e `work/d-preview-validation-final` conservano
le evidenze. Nessuna nuova revisione generale, merge, tag, release o GitHub Action.
