# Fase8 — primo DMG locale, checkpoint manuale

Prerequisito adottato: nuovo prefix `diagnostics/fase7-native-001/prefix`.
Nessuna ricompilazione PoDoFo/FreeType. Il verificatore conserva il run nativo
in sola lettura e rifiuta file modificati/non registrati, summary fallito,
passaggi/test mancanti o proof non corrispondente. Il dossier storico del vecchio
prefix rimane unattested; non viene usato per aggirare i gate.

## Comando esatto nel Terminale dell'autore

```sh
/usr/bin/python3 /Users/andreaoregioni/Developer/Signum-Stabilization/worktree/scripts/prepare-public-beta.py \
  --native-prefix /Users/andreaoregioni/Developer/Signum-Stabilization/diagnostics/fase7-native-001/prefix \
  --cmake /opt/homebrew/bin/cmake \
  --output-root /Users/andreaoregioni/Developer/Signum-Stabilization/diagnostics/fase8-beta-001 \
  --build-number 14 --bundle-id io.github.tiertoast.Signum --trust-probe include \
  --signing-mode adhoc --release-notes /Users/andreaoregioni/Developer/Signum-Stabilization/worktree/docs/BETA_LOCAL_RELEASE_NOTES.md \
  --verify-local-beta --build --budget-seconds 900
```

Per il solo preflight omettere `--build` e scegliere un'altra cartella NUOVA.
La cartella del run non può esistere. Il budget complessivo massimo è900s,
inclusi controlli; nessun download/installazione. Non vengono eseguite suite
Swift, stress o M3–M6. Si costruiscono i prodotti dell'app e il suo helper,
collegandoli esclusivamente al nuovo prefix già compilato.

Chiudere eventuali altre istanze Signum prima del collaudo per evitare ambiguità
nell'avvio. La procedura avvia il candidato, verifica tramite AppKit che QUEL PID
abbia concluso il lancio con l'identifier atteso e resti vivo almeno2s, controlla
le librerie caricate, poi termina soltanto il processo di prova. Nessuna
interazione GUI, firma di documenti, PIN o operazione hardware è simulata come
superata. Non servono autorizzazioni Accessibility/System Events.

## Sequenza obbligatoria

1. Preflight e gate di provenienza/licenze.
2. App Release0.7.0 Beta/build14/arm64/minimo13.0; firma ad-hoc e risorse originali.
3. Audit app: metadata, codice/sigilli/hash, loader/rpath, sorgenti/notice/XSD
   effettivi, assenza di vecchio prefix e percorsi di sviluppo nei Mach-O;
   lancio base dell'app. Il kit del nuovo prefix viene incluso senza alterarlo.
4. DMG e sidecar SHA256; mount readonly/nobrowse, inventario completo checksum,
   app identica a quella avviata/auditata e verifica firma dal volume; detach.

Timeout/SIGINT/SIGTERM/SIGHUP interrompono i processi posseduti. Cleanup di
scratch/temp e dell'eventuale mount esclusivo; se incompleto è riportato e il
run fallisce. Log dettagliati dei soli passi falliti, più eventuale log di
startup fallito. Artefatti completati prima di un errore rimangono diagnostici,
non promossi a verificati.

## Output e ripresa

- `Signum.app`, `Signum-0.7.0-beta-arm64.dmg`, `.dmg.sha256`.
- `Signum.app.SHA256SUMS` per file e inventario separato dei link.
- `AppAudit.json`: binari/risorse, avvio e inventario completo dell'app.
- `ArtifactManifest.json`: hash DMG, riferimento/hash AppAudit, dati native e
  prova di confronto del volume; checksum interno e manifest anche nel DMG.
- `summary.json`: quattro passi, errori, durata e manifest; successo atteso
  `verified-local-beta`. Sempre `publicationQualified:false`.

Dopo il run fornire **summary.json e ArtifactManifest.json**; AppAudit è
referenziato con hash e si consulta solo se necessario. Se fallisce, summary
indica il log pertinente. Nessuna ripetizione automatica di Fase7/build nativa.
Il successo qualifica il candidato locale nel perimetro indicato, non una
pubblicazione o una prova su macOS13 reale/hardware. Nessun Developer ID,
notarizzazione, rimozione quarantena o pubblicazione è incluso.
