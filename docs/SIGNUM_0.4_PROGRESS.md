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

## 18 ottobre 2026 — 0.4-A.2 Device Discovery

L'utente riferisce completato il collaudo hardware **della precedente 0.4-A**:
DigitalDNA, tre documenti, tre firme valide InfoCamere, tre richieste PIN. È un
riscontro manuale della baseline, non una prova automatica o del nuovo candidato.

Nuovo branch `codex/signum-0.4-device-discovery` da `dd1e786`, senza toccare main,
Alpha o integrazioni. **Implementati M1–M4:** registro Bit4id/OpenSC, discovery
pubblica nei worker con controlli root/permessi/ACL e identità file, token/seriali,
certificati raggruppati per DER con route esplicite, selezione senza fallback,
GUI centrata sul certificato e configurazione manuale avanzata. Ricerca al lancio
oppure esplicita; nessun monitoraggio USB continuo o autenticazione di discovery.
Consenso batch semplificato, nomi omonimi distinguibili, dettagli tecnici separati.
Valutazione X.509 e raggruppamento preparati off-main in un risultato immutabile.
Verificato anche un batch di tre PDF PAdES da route scelta, con originali modificati
e tre sole autorizzazioni esplicite, senza riuso PIN.

**M5 analizzata:** sessione batch/autenticazione unica non dimostrate sicure sui
percorsi CAdES/PAdES, quindi rimangono autorizzazioni per documento, nessuna cache
PIN, nessun retry e nessun toggle ingannevole. Causa della policy hardware non
attribuita al produttore senza prove.

**M6 verificata sul codice `2a27cad`:** Swift **197/197**, 31 nuovi test;
PKCS#11 **40/40**; PAdES Debug/Release **63/63**; packaging **10/10**;
ASAN e TSAN mirati **35/35** ciascuno. Zero skip/fallimenti nei runner finali;
build Swift Debug/Release e nuovi bundle ad hoc/rilocati passati, 0.4.0/build 2,
minimo dichiarato/Mach-O 13.0. Nessun hardware o middleware installato caricato
nelle prove. GUI interattiva, compatibilità reale OpenSC/Bit4id del nuovo flusso,
macOS 13/14 e Mac pulito restano da collaudare. Non è una release pubblica.

Candidato: `.build/04a2-bundles/final-release/Signum.app` (final-debug separato);
demo manuale sintetica pronta in `.build/04a2-demo`. Precedenti bundle preservati.
Architettura, policy, esiti, commit, limiti e procedura di collaudo sono nel
[rapporto Device Discovery](SIGNUM_0.4_DEVICE_DISCOVERY.md). B/C della roadmap
funzionale non iniziate in questa porzione. Nessun push/merge/tag o CI remoto.

## 18 ottobre 2026 — 0.4-A.3 Signing Experience

Baseline A.2 `a468c42`, collaudo DigitalDNA/DS3/InfoCamere positivo riferito
dall'utente per quella versione. Nuovo branch `codex/signum-0.4-signing-experience`;
nessun trasferimento automatico del collaudo hardware alla nuova candidata.

**M1–M6 implementate e verificate software:** filtro predefinito solo idonei
SG-04 con preferenza persistente e accesso distinto agli indeterminati; output
accanto a ogni originale o in cartella comune scelta prima del consenso; nomi
senza collisioni fissati nell'approvazione; una conferma per tutto il batch;
PIN monouso vincolato al documento corrente, senza retry/riuso; workspace destra
per documenti/progressi/esiti e campo PIN fuori dallo scorrimento. PDFKit mantiene
l'anteprima dello snapshot. Primitive, worker, lifecycle e pubblicazione Foundation
preservati; nessuna ottimizzazione dell'autenticazione batch.

Sul codice `68bf61b`: Swift **221/221**, 24 nuovi test; PKCS#11 **40/40**;
PAdES Debug/Release **63/63**; packaging **10/10**; ASAN/TSAN mirati **37/37**
ciascuno. Zero skip/fallimenti finali. Build Debug/Release e bundle rilocati passati;
versione **0.4.0/build 3**, firma ad hoc e Mach-O minimo 13.0 verificati.
Due test nativi/rendering ispezionati: PIN raggiungibile con 32 documenti a 650
punti e PDFView sullo snapshot. Non equivalgono a un collaudo interattivo completo.

Candidata: `.build/04a3-bundles/final-release/Signum.app`, Debug separata;
demo sintetica `.build/04a3-demo` preparata con discovery CLI verificata.
Alpha e A.2 preservate. Report, commit, comandi, limiti e istruzioni nel
[rapporto Signing Experience](SIGNUM_0.4_SIGNING_EXPERIENCE.md).
PIN ancora per documento; A.4, B/C non iniziate. Hardware, GUI interattiva del
bundle, macOS 13/14 e Mac pulito restano da collaudare. Nessun push/merge/tag,
release, CI remoto o accesso a HalleyMac. Main invariato `be84a1e`.

## 18 ottobre 2026 — 0.4-A.3.1 Signing Workflow & File Handling

Branch `codex/signum-0.4-file-handling` da HEAD A.3 `22fc4e0`; collaudo reale
positivo della build 3 riferito dall'utente, preservato senza riutilizzarlo come
prova della nuova candidata. **M1–M5 completate software.**

Riprodotto prima del fix il falso positivo da aggiornamento xattr/ctime con byte
invariati. CoW conservato; monitor vnode su descriptor, controlli identità/mtime
e corroborazione dei byte separano metadati da scritture, anche transitorie con
ripristino. Errori lettura/spazio/dimensione/timeout distinti, dettagli espandibili.
Riepilogo immutabile preparato prima del clic, che ora è il consenso diretto;
conferma modale opzionale persistente OFF. Revisione documenti/provider/certificato/
destinazione/discovery vincolata e selezione riservata prima di accodare la Task.

Limite intermedio **100 MiB per documento CAdES/PAdES**, **128 MiB per sessione**,
output/verifica 132 MiB. Firme sintetiche da 100 MiB verificate e pubblicate;
200 MiB respinti esplicitamente. Memoria misurata e copie documentate: serve
un ulteriore intervento su streaming/cache prima di aumentare ancora.

Sul codice `daca4cf`: Swift **240/240** (19 nuovi), PKCS#11 **40/40**, PAdES
Debug/Release **63/63**, packaging **10/10**, ASAN/TSAN mirati **63/63** ciascuno.
Zero skip/fallimenti finali. Build Debug/Release, bundle rilocati, firma ad hoc,
hash e Mach-O minimo 13.0 verificati; candidata **0.4.0/build 4**.

Usare `.build/04a31-bundles/delivery-release/Signum.app` (Debug separata);
demo `.build/04a31-demo` pronta. Alpha e build 2/3 preservate. Cause riprodotte,
commit, limiti, memoria, comandi ed esatta procedura nel
[rapporto File Handling](SIGNUM_0.4_FILE_HANDLING.md).
Nessuna regressione software rilevata; GUI interattiva, casi reali Download,
hardware e runtime macOS 13/14 restano da collaudare. Main invariato; nessun
push/merge/tag/release, GitHub Actions o accesso a HalleyMac.

## 18 ottobre 2026 — 0.4-A.4 Batch Authentication & Signing Workspace

Branch `codex/signum-0.4-batch-auth` da HEAD build 4 `51e9d22` (codice `daca4cf`).
Baseline ripetuta positiva; collaudo DigitalDNA/DS3 di sette CAdES e comportamento
InfoCamere DigitalDNA/CNS sono evidenze riferite dall'utente, non nuove prove
hardware. **M1–M7 completate nel perimetro software.**

Worker isolato dedicato al batch CAdES approvato, lease esclusivo e sequenza
immutabile. Un solo PIN nei test quando ALWAYS_AUTHENTICATE è leggibile false,
USER fresco resta valido e Initialize è posseduta; true/unknown conservano il
percorso sicuro per documento. Nessun PIN nei comandi successivi o nel coordinatore,
nessun retry, login altrui rifiutata. Verifica RSA/CMS e commit atomico precedono
ogni richiesta successiva. Errori, cancellazione e chiusura revocano la sessione;
esiti incerti visibili. PAdES e batch misti restano one-shot, esplicitamente.

Preferenza Automatica, quando supportata / PIN per firma. Workspace compatto con
dettagli espandibili, destinazione prima del consenso, progressi/esiti, Apri
cartella/Nuova sessione; PIN accessibile e anteprima PDFKit sullo snapshot.

Codice **`7596f50`**: Swift **265/265**, PKCS#11 **40/40**, PAdES Debug/Release
**63/63** per configurazione anche nei bundle/rilocati, packaging **10/10**,
ASAN/TSAN mirati **64/64** ciascuno, auth con worker impacchettato **20/20**.
Zero skip/fallimenti nei runner finali. Build e bundle Debug/Release passati;
firma ad hoc, hash, dipendenze e cinque Mach-O minimo 13.0 verificati.

Candidata **0.4.0/build 5**: `.build/04a4-bundles/final-release/Signum.app`
(Debug separata), demo sintetica `.build/04a4-demo`. Alpha e candidati precedenti
preservati. [Rapporto, commit, limiti e procedura manuale](SIGNUM_0.4_BATCH_AUTH.md).
Nuova autenticazione reale DigitalDNA/CNS, runtime macOS 13/14 e accettazione GUI
completa non eseguiti. Nessun hardware/PIN reale, push/merge/tag/release, CI remoto,
installazione globale o accesso a HalleyMac; main e branch build 4 invariati.

## 18 ottobre 2026 — 0.4-A.4.1 Secure Batch PIN, sperimentale

Branch `codex/signum-0.4-secure-batch-pin` da HEAD build 5 `4366ed7`. Richieste
PIN ripetute nel collaudo build 5 riferite dall'utente: causa non attribuita.
**M1–M8 implementate nel perimetro software**, prima di qualsiasi nuovo hardware.

Terza modalità opt-in «PIN temporaneo per il batch», default sempre Automatica.
PIN persistente solo nella pagina nativa mlock del worker CAdES approvato;
payload binario iniziale separato dal manifesto, nessun PIN nei job, comandi
successivi o preferenze. True noto: un inserimento UI e CONTEXT_SPECIFIC dopo
ogni SignInit; false: buffer eliminato dopo il primo job, USER riutilizzato.
Unknown/sessione persa/errori interrompono il riuso; nessun retry o USER relogin.
Buffer cancellato prima del teardown e dell'ultimo commit. PAdES/misti rimangono
per documento. Dichiarati limiti Swift/vendor e maggiore esposizione dell'opt-in.

Verificati tre e sette CAdES con USER una volta, CONTEXT 3/7 volte e tutti gli
output verificati. Non equivale a una sola autenticazione hardware. Core
`eec717d`, fixture sanitizer `40eb5ee`, candidata finale **`37d21e8`** con ultima
descrizione consenso corretta, nessun cambiamento alle primitive validate.

Swift **293/293**, PKCS#11 **40/40**, PAdES Debug/Release **63/63** ciascuna
anche nei bundle/rilocati, packaging **10/10**, ASAN/TSAN mirati **92/92** ciascuno.
Primi sanitizer: quattro assert falliti ciascuno perché intercettano mlock come
no-op; probe isolato ne dimostra la causa. Nei run finali quel solo test OS usa
un worker normale esplicito, gli altri worker restano strumentati. Zero skip o
fallimenti finali; nessuna diagnostica nei due file C analizzati con Clang.

Build e bundle Debug/Release passati, firma ad hoc/hash/dipendenze e minimo 13.0
verificati. **0.4.0/build 6** in `.build/04a41-bundles/delivery-release/Signum.app`
(delivery-debug separata); demo sintetica ALWAYS_AUTHENTICATE true pronta.
[Threat model, limiti, commit, esiti e collaudo](SIGNUM_0.4_SECURE_BATCH_PIN.md).
Hardware DigitalDNA/CNS, GUI interattiva completa, sleep reale e runtime macOS
13/14 non verificati. Alpha e build precedenti preservate; main/build 5 invariati.
Nessun push/merge/tag/release, CI remoto, hardware/PIN reale, altro repository
o HalleyMac.


## 18 ottobre 2026 — 0.4-B PAdES Appearance

Branch `codex/signum-0.4-pades-verification`, da HEAD build 6 `72060b7`.
Appearance configurabile per documento, un solo rendering CoreGraphics/CoreText
condiviso da PDFKit e PoDoFo, risorse incorporate prima della firma. Testo,
nome dal DER, data locale opzionale, PNG/JPEG, geometria raw/CropBox/rotazioni,
visibile/invisibile; consenso invalida su ogni modifica e congela l'appearance.
Batch PAdES conserva autenticazione per documento. Nessuna nuova primitiva.

Swift **302/302**, PKCS#11 **40/40**, PAdES Debug/Release **63/63** ciascuna,
packaging unit **10/10**, build Debug/Release passate. ASAN/TSAN Swift mirati
**30/30** ciascuno; native ASAN **63/63** e appearance ASAN end-to-end **9/9**.
Confronto raster indipendente dei veri PDF firmati su quattro rotazioni: delta
medio zero. Fonte candidata **0.4.0/build 7**; build 6 preservata.
[Architettura, evidenze, limiti e collaudi](SIGNUM_0.4_PADES_APPEARANCE.md).
C non sviluppata prima del checkpoint B. Nessun hardware/PIN reale, push, merge,
tag, release, PR #3, GitHub Actions o accesso ad altri repository.

Checkpoint B **`9f7684b`**, seguito da bundle Debug/Release build 7 verificati
anche dopo rilocazione; manifest senza modifiche tracciate pendenti. Disponibili
in `.build/04b-bundles/checkpoint-{debug,release}/Signum.app`. Da qui inizia C.


## 18 ottobre 2026 — 0.4-C Unified Verification

Dopo B `9f7684b`/bundle verificati `d7d02d4`, nuova sezione **Verifica** autonoma
e senza PIN/provider: riconoscimento strutturale CAdES/PAdES nel processo
supervisionato, firma per firma, certificati, revisioni, modifiche successive,
preview PDFKit in memoria ed estrazione esplicita/no-overwrite del CMS verificato.
Backend OpenSSL già incorporato/SG-03, niente nuovo parser CMS; CLI `verify`.
Fiducia, revoca, qualificazione e accettabilità DocMDP/FieldMDP non valutate.

Swift **317/317**, PKCS#11 **40/40**, PAdES Debug/Release **63/63** ciascuna,
packaging **10/10**, build Debug/Release passate. ASAN/TSAN mirati **54/54**
ciascuno, native ASAN **63/63**, confronto crittografico indipendente positivo.
Ulteriori regressioni scroll reale e pagine differenti: suite B/C **24/24**.
Zero skip/fallimenti finali; fixture da 100 MiB incluse. Fonte build **8**.

[Architettura, policy effettiva, test, limiti e collaudo](SIGNUM_0.4_UNIFIED_VERIFICATION.md).
Profilo PDF deliberatamente limitato a quello SG-03; niente validazione legale,
XAdES operativo o hardware nuovo. Runtime macOS 13/14 e GUI interattiva completa
ancora da collaudare. Main, Alpha/build 6, review non tracciata e PR #3 preservati;
nessun push/merge/tag/release, GitHub Actions o altro repository.

Checkpoint C **`89dfb14`**, build 8 Debug/Release impacchettate e verificate,
39/39 integrazioni con helper del bundle e 15/15 esempi CLI. Controllo finale:
OID di algoritmo non supportato classificato impropriamente come integrità
non valida; corretto distinguendo prima OID, tipo chiave e digest. Regressione
CAdES/PAdES 15/15; candidata incrementata a build 9, preservando build 8.

Dopo la correzione OID: Swift 317/317, PKCS#11 40/40, PAdES Debug/Release
63/63, packaging 10/10, ASAN/TSAN mirati 54/54 ciascuno e native ASAN 63/63;
Build Debug/Release riuscite. Zero skip/fallimenti finali (`04c-build9-*`).

**Candidata finale 0.4.0/build 9**, codice **`9c7477b`**:
`.build/04bc-bundles/build9-release/Signum.app` (Debug `build9-debug`).
Entrambi i bundle firmati ad hoc, manifest clean, hash/dipendenze/helper,
minimo Mach-O 13.0 e rilocazione verificati. **39/39** integrazioni con helper
impacchettati e **16/16** esempi CLI passati. Demo `.build/04bc-demo` pronta.
B/C completate nel perimetro supportato; profili PDF ulteriori, trust e runtime
13/14 restano nei limiti/collaudi documentati. Working tree tracciato pulito;
review non tracciata preservata, nessuna operazione remota o hardware reale.
