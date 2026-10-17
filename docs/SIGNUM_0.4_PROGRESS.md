# Signum 0.4 — sviluppo funzionale

Base verificata dopo fetch: `origin/main ec8c6b2`, merge Foundation `50e2473`,
README `f8ab186`. Branch `codex/signum-0.4-functional`; review non tracciata
preservata. Letti README, rapporti Foundation/PR2 e RELEASE_READINESS.

## Analisi iniziale (prima del codice)

| Milestone | Riuso / modifica minima | Rischio e criterio di completamento |
|---|---|---|
| **A — firma multipla, priorità** | Snapshot, SigningJob, SigningOperation, worker e helper v4. Coordinatore separato dalla View, coda ordinata e limitata, approvazione congelata, autorizzazione esplicita per singolo documento | PIN non conservato fra job; collisioni/no overwrite; cleanup e risultati indipendenti. Completa con tre CAdES e batch misto software, duplicati/errori/cancel/provenienza, GUI collegata e regressioni/build passate |
| **B — appearance** | PDFKit/PAdESPlacementPane, preferenze, appearance PoDoFo già incorporata. Modello limitato per testo/data/immagine, stesso layout fra preview e PDF | Immagini malformate/enormi, rotazione/coordinate e differenze preview. Non completa senza appearance nel PDF e verifica crittografica su fixture testo/immagine/data/invisibile/rotazioni |
| **C — verifica PAdES** | Verificatore nativo SG-03, parser PDF/CMS e supervisore. Risultato Core distinto dalla View | Revisioni/ByteRange/CMS non supportati non diventano validi. Completa con GUI e fixture alterate, non firmate, revisioni multiple; nessun claim CA/revoca/eIDAS |

Si completa e verifica A prima di iniziare B; C solo dopo B verificata.
Nessuna nuova primitiva crittografica, renderer parallelo o integrazione esterna.

## 0.4-A — implementato e verificato automaticamente

- Selezione multipla NSOpenPanel e drop ordinato (callback limitati a 10 s),
  elenco nome/formato/dimensione/stato/destinazione, rimozione prima del consenso.
- `BatchSigningCoordinator` Core separato dalla View: snapshot singoli, ordine
  stabile, massimo 32 documenti e 128 MiB complessivi. Duplicati per percorso o
  SHA-256 nello stesso formato rifiutati; limiti individuali Foundation invariati.
- Riepilogo «Conferma firma» con tutti i job congelati, firmatario/formati/destinazioni;
  SHA-256 e identificativi sotto «Dettagli tecnici». Nessuna aggiunta dopo conferma.
- Destinazioni collision-free con suffissi scelti **prima** del consenso; controllo
  nuovamente prima della richiesta privata e commit esclusivo Foundation invariato.
- CAdES e PAdES misti riusano esattamente worker e helper verificato v4. Ogni PDF
  deve essere aperto nell'anteprima degli stessi byte prima della conferma GUI.
  Posizioni/invisibilità disponibili nella baseline sono congelate per documento.
- Autorizzazione manuale di **un solo** documento per azione. Nessun PIN conservato
  nel coordinatore; campo svuotato a ogni invio/cancellazione. Nessuna prosecuzione
  automatica, nessun retry dello stesso job, nessuna sessione vendor condivisa.
  USER e CONTEXT_SPECIFIC restano gestiti dal bridge esistente per **quella** firma,
  secondo CKA_ALWAYS_AUTHENTICATE: non si presume una login valida per l'intero batch.
- Annullamento singolo/in blocco dei job in attesa; interruzione corrente tramite
  SigningOperation. Esito incerto blocca ulteriori autorizzazioni finché l'utente
  riconosce di aver controllato dispositivo/output. Il documento incerto non viene
  ripetuto. Risultati completati preservati; errori indipendenti e resoconto a video.
- «Nuova sessione» libera snapshot e riepilogo; il report non viene scritto su disco.
  Copie private eliminate a fine job/rimozione/reset; i byte in memoria restano
  limitati fino al reset. Nessuna garanzia di cancellazione forense/zeroizzazione.
- Metadati locali 0.4.0/build 1, target macOS 13 invariato; nessuna release.

**Test realmente passati sul codice aggiornato:** Swift **166/166**, inclusi
**12 nuovi test** batch; PKCS#11 **40/40**; PAdES Debug/Release **63/63** ciascuna;
packaging **10/10**. Build di tutti i prodotti Swift Debug/Release riuscite.
ASAN e TSAN mirati ai 12 test batch: **12/12** ciascuno, nessuna segnalazione nei
runner; leak detection ASAN disabilitata, terze parti non interamente strumentate.

Nuovi casi: tre CAdES con tre azioni distinte e conteggio Login/Sign; batch misto
CAdES/PAdES nativo; duplicati/ordine/rimozione; destinazione esistente e collisione
apparsa dopo consenso; nomi uguali; fallimento pre-commit del secondo con primo
preservato e terzo ancora autorizzabile; cancel durante coda; originali modificati
ma CMS sugli snapshot approvati; identità immutate; nessuna seconda autenticazione
automatica; consenso annullato/limite 32; richieste concorrenti e PIN vuoto;
ritorno del motore senza pubblicazione confermata non marcato «Completato».

## Non verificato e ripresa

**GUI interattiva non verificata:** il canale Computer Use restituisce
«Sky Computer Use native pipe closed before response», anche dopo riavvio Codex e
reset del runtime. L'avvio locale è stato richiesto con esito del comando positivo,
ma non sono stati osservati finestra/layout/click. Non si attribuisce una causa
certa ai permessi. Nessun token o PIN personale usato. Il collaudo GUI rimane un
gate esplicito per dichiarare A interamente collaudata.

**B e C non iniziate:** priorità alla porzione A coerente. Aspetto PAdES ancora
limitato alla baseline testuale/invisibile; nessuna nuova verifica PAdES nella GUI.
Nessuna regressione rilevata nelle suite; possibili regressioni GUI/middleware
richiedono collaudo manuale. Runtime macOS 13/14 e hardware non riesaminati.

Evidenze locali: `.build/reliability/evidence/04a-*.log`.

## Fixture per collaudo GUI senza hardware

`scripts/prepare-batch-demo.py` crea solo sotto `.build`, in una directory nuova
0700, un certificato/chiave RSA **sintetici**, il provider software di test e
quattro documenti (tre testi diversi e un PDF); aggiunge un duplicato intenzionale.
Il provider non accede a lettori o middleware installati. Il mock ignora la stringa
di autenticazione; **non inserire mai un PIN reale**. La chiave è di test, non usare
questo provider su documenti reali. La preparazione non firma e non autentica.

**Verificato:** esecuzione della preparazione, discovery/certificato tramite CLI e
worker, idoneità locale, firma PAdES nativa del PDF demo con verifica prima del
commit, un solo Login/Sign sintetico, originale invariato. Ripetere la preparazione
sulla stessa directory viene rifiutato e preserva il modulo esistente.
Log `04a-demo.log`. Questi test software non sostituiscono click GUI o hardware.

Fixture già pronta in `.build/04a-demo`. Per crearne un'altra:

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
/usr/bin/python3 scripts/prepare-batch-demo.py --output .build/04a-demo-new
```

Collaudo GUI manuale **senza collegare token**:
1. Aprire il candidato 0.4; impostare soltanto il percorso assoluto della
   `synthetic-provider.dylib` generata, premere Carica e scegliere lo slot/certificato
   sintetico. Non usare il percorso del middleware reale.
2. Aggiungere i tre testi con selezione multipla; aggiungere il duplicato per
   vedere il rifiuto e provare Rimuovi. Per batch misto passare a PAdES, aggiungere
   `synthetic.pdf` e aprirne l'anteprima dal nome nell'elenco.
3. Conferma firma → scegliere una cartella **demo** di output → controllare tutta
   la lista e i Dettagli tecnici. Annullare una prima volta: nessuna firma parte.
4. Confermare, inserire una stringa fittizia non vuota nel campo per il primo
   documento e premere Autorizza. Verificare che il successivo resti in attesa con
   campo vuoto. Ripetere esplicitamente per gli altri oppure annullarli.
5. Controllare il resoconto, i file nuovi e la conservazione di eventuali file
   preesistenti. Nuova sessione svuota il riepilogo e libera le copie private.

Hardware, PIN personale, macOS 13/14 e aspetto grafico completo restano fuori
questa prova. B va iniziata dopo il collaudo A, C dopo B verificata.

## Consegna locale e riproduzione

Commit:
- `4440e8b`: firma multipla, GUI e 12 test, con primitive Foundation invariate.
- `996dad1`: fixture software per collaudo GUI senza hardware.
- Il commit documentale successivo registra questa consegna.

Candidati **finali** (non usare i precedenti candidati debug/release intermedi):
- `.build/04a-bundles/final-debug/Signum.app`
- `.build/04a-bundles/final-release/Signum.app`

Manifesto: commit sorgente `996dad1`, albero tracciato pulito alla build,
versione 0.4.0/build 1, minos massimo 13.0. Entrambe le configurazioni superano
verifica codesign, audit byte/load-command, discovery mock e PAdES **63/63**
anche dopo rilocazione. Firma solo ad hoc; Alpha e prefissi precedenti preservati.
Nessuna distribuzione, Developer ID, notarizzazione o validazione eIDAS.

Comandi locali (CMake/toolchain e prefisso macOS 13 già presenti):

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
SIGNUM_TEST_PADES_HELPER="$PWD/.build/pr2-pades-debug/signum-pades-local" swift test --scratch-path .build/reliability
scripts/test-pkcs11-local.sh
SIGNUM_NATIVE_PREFIX="$PWD/.build/pr2-native-macos13/prefix" SIGNUM_PADES_TEST_BUILD="$PWD/.build/pr2-pades-debug" scripts/test-pades-local.sh
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build -c debug --scratch-path .build/reliability
swift build -c release --scratch-path .build/reliability
```

Il test misto e quello nativo PR2 richiedono SIGNUM_TEST_PADES_HELPER; qui sono
stati eseguiti, senza skip. Per nuovi bundle usare sempre percorsi non esistenti:

```sh
/usr/bin/python3 scripts/build-beta-app.py --configuration release --native-prefix .build/pr2-native-macos13/prefix --output .build/04a-rebuild/Signum.app
```

Per collaudo GUI manuale sintetico:

```sh
open -n "$PWD/.build/04a-bundles/final-release/Signum.app"
```

Impostare nella GUI il percorso
`/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a-demo/synthetic-provider.dylib`
**prima di Carica**, quindi seguire i passi della fixture sopra. Il certificato
demo scade in 7 giorni: rigenerare in una directory nuova se necessario.

**Stato:** A implementata e verificata software, gate GUI interattiva ancora aperto;
B e C non iniziate. Non dichiarare la 0.4 completa o hardware-collaudata.
Riprendere da GUI A, poi appearance B con test sul PDF realmente firmato, poi C.
Nessun push/merge/tag/release/GitHub Actions; nessun accesso a HalleyMac.
`main` locale resta `be84a1e`; branch Beta precedente resta `b48b3ae`. Review non
tracciata preservata con SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
