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

## M2 — Filtro certificati

Default persistente OFF per «Mostra certificati non idonei». La presentazione usa
`CertificateVisibility`, senza cambiare SG-04: OFF mostra solo eligible; ON mostra
anche ineligible e indeterminate, mantenendo stati e motivi distinti. Gli
indeterminati hanno un accesso avanzato esplicito anche a filtro chiuso. Una
selezione esclusa nascosta viene cancellata insieme al PIN; nessuna preselezione
al refresh e nessuna possibilità di firmare con un certificato escluso.

Test mirati filtro/preferenza/selezione/provider: **17/17**. Cinque nuovi casi:
OFF/ON, stati e motivi, persistenza isolata senza credenziali, blocco SG-04 anche
quando il certificato è visibile, refresh senza preselezione. GUI compilata;
nessun collaudo interattivo o hardware implicato da questi test.

## M3 — Destinazioni prima del consenso

`BatchOutputDestination` pianifica in Core, off-main e senza creare output/probe:
- default `.originalFolders`: ogni copia accanto al proprio originale;
- `.commonDirectory`: cartella scelta in anticipo con Sfoglia, mai durante il consenso.

La preferenza originale è ON inizialmente; la cartella comune ricordata è un
percorso, non un'autorizzazione permanente. L'app attuale non ha App Sandbox:
nessun nuovo entitlement/bookmark, permessi OS ricontrollati a ogni pianificazione.
Se manca la cartella comune, il pulsante non è abilitabile. Cartelle mancanti,
non scrivibili o negate da ACL sono rifiutate prima dell'approvazione/PIN.

Percorsi canonici e identità device/inode del parent approvati e ricontrollati
prima dell'autenticazione; descriptor directory temporanei in sola lettura,
nessuno staging/output creato dal piano. Prenotazioni
per directory fisica e nome, incluso collisioni fra cartelle alias; lstat considera
anche symlink pendenti. CAdES `Relazione.pdf.p7m`, poi `Relazione (2).pdf.p7m`;
PAdES conserva la convenzione esistente `Relazione-firmato.pdf`. Un solo assert
legacy sui suffissi CAdES aggiornato alla nuova convenzione richiesta, mantenendo
il test e i suoi invarianti. Destinazioni e job immutabili dopo il consenso.

Collisione tardiva o parent sostituito: nessuna autenticazione, nessun rename
silenzioso; nuova sessione/approvazione prima di un nome diverso. Verifica e
pubblicazione atomica/no-overwrite Foundation restano obbligatorie e immutate.
Core CAdES e wrapper PAdES riusano il controllo di disponibilità del job prima
operazioni private; nessuna modifica a RSA/CMS/PDF o ai protocolli hardware.

**Test mirati M3 + batch/job: 36/36**, inclusi 11 nuovi casi: originale singolo,
cartelle diverse/nomi uguali, cartella comune con file e symlink già esistenti,
PAdES, directory assente/file/read-only/ACL, collisione dopo consenso, sostituzione
parent, preferenze incomplete/persistite, output congelati e tre CAdES verificati
accanto agli originali senza modificarli. Primo run: sette assert confrontavano
alias `/var` e `/private/var` invece della directory fisica; fixture normalizzata
con realpath e confronto coerente, poi suite ripetuta positiva. Nessuna deroga ai
controlli di percorso per far passare il test.

## M4 — Una conferma, autenticazione corrente

Pulsante «Firma documento» / «Firma N documenti», una sola conferma con firmatario,
certificato, lista/formati/destinazioni effettive. NSOpenPanel è esclusivamente
nell'azione Sfoglia precedente. SHA-256, percorsi, dimensioni, job/snapshot/provider/
slot e certificato nel dettaglio tecnico. Nessun popup documentale dopo il consenso.
Il pulsante/Invio nel campo PIN invia l'autenticazione, non richiede un altro consenso.

`SigningInteraction` separa consenso e invio da job e stato provider: niente PIN
memorizzato nel modello, campo svuotato sincronicamente prima della Task privata,
una sola richiesta in volo. Prompt «Firma i di N — Inserisci PIN» e focus quando
la firma successiva è pronta. Il documento corrente è vincolato anche nel guard
atomico Core: se viene annullato prima dell'avvio, il PIN non passa al successivo.
Nessun worker persistente, retry o riuso PIN fra documenti; ALWAYS_AUTHENTICATE,
worker/helper, timeout e gestione incerta restano invariati. Il riconoscimento di
un esito incerto rimane una misura Foundation, non un nuovo consenso ai documenti.

`SigningPresentation` distingue vuoto/destinazione incompleta/selezione incompleta,
pronto/preparazione/conferma/PIN/in corso/incerto/concluso. Non presenta fallimenti
o annullamenti come firme riuscite. Nuova sessione libera snapshot e piani.

**Test M4 + batch: 19/19**, sei nuovi casi: unica presentazione e tre CAdES reali
software, tre campi PIN consumati senza ulteriori conferme, seconda richiesta
concorrente rifiutata, consenso annullato, errore prima della conferma, annullamento
prima della Task senza retarget PIN, blocco dopo incertezza e stati/reset.
Nessun PIN personale e nessuna autenticazione hardware.

## M5 — Workspace funzionale

Lista documenti, avanzamento ed esiti nella colonna destra CAdES, senza la seconda
lista nella colonna sinistra. Selezionando un PDF: «Documenti ed esiti» / «Anteprima
PDF», con PDFKit sullo stesso snapshot e pannello scorribile quando lo spazio è
ridotto. Il primo tentativo di split verticale comprimendo coda e PDF è stato
scartato dopo l'ispezione del rendering: i controlli del preview erano tagliati.
La visualizzazione alternativa preserva lo spazio necessario al pannello esistente.
All'invio del PIN si torna agli esiti, senza alterare i job o i campi già approvati.

Selezioni e preferenze scorrono nella parte superiore sinistra; firma/PIN e stato
restano in un'area separata, fuori da NSScrollView. Non viene richiesto un nuovo
consenso per leggere anteprime o risultati. Candidato locale 0.4.0/build 3, macOS
13 invariato; nessuna modifica alle funzioni grafiche di firma o alle primitive.

**Test M5 + interazione: 8/8**, inclusi due test nativi NSHostingView/NSWindow:
PIN unico e vuoto, nel viewport e senza antenati NSScrollView con 32 documenti,
anche a 650 punti di altezza; PDFView reale con documento dello snapshot (una
pagina, nessuna riapertura dell'originale). Discovery disabilitata solo tramite
iniezione interna al test, con provider/certificati/preferenze sintetici: nessun
flag di prodotto o caricamento automatico di moduli utente. I PNG di queste viste
sono stati ispezionati localmente (`.build/04a3-ui`); i primi PNG trasparenti non
consentivano una valutazione completa, poi corretti fondo/finestra e ripetuta la
verifica. Le etichette versione dei rendering appartengono all'host XCTest, non
al candidato .app; i metadati di quest'ultimo saranno verificati nel packaging.

Limite: rendering e gerarchia nativa non provano tutta l'interazione operatore,
Focus/Invio su un token reale o l'intero disegno GPU del contenuto PDFKit. Rimane
necessario il collaudo manuale del bundle. Non è stata avviata discovery hardware.

## M6 — Verifica finale e candidata

Verifiche locali del 18 ottobre 2026 su macOS **27.2 arm64**, Swift **6.4**.
Sorgenti del candidato: `68bf61b`, albero tracciato pulito durante il packaging.
Il successivo commit M6 modifica solo questo rapporto e il registro progressi.

| Verifica realmente eseguita | Risultato |
| --- | --- |
| Swift completo, helper PAdES esplicito | **221/221**, zero skip/fallimenti |
| PKCS#11 lifecycle/provider simulato | **40/40** |
| PAdES Debug e Release | **63/63** ciascuno |
| Test Python packaging | **10/10** |
| Swift build Debug e Release | entrambe passate |
| Packaging Debug e Release | entrambi passati, incluse copie rilocate |
| ASAN sui nuovi componenti e regressioni batch | **37/37**, zero skip/fallimenti |
| TSAN sugli stessi componenti | **37/37**, zero skip/fallimenti |
| Metadata, firme ad hoc, hash, portabilità, target dei cinque Mach-O per bundle | passati |
| Discovery CLI candidata su provider della nuova demo sintetica | slot 7 riconosciuto |

I 24 nuovi test comprendono 5 filtro, 11 destinazioni, 6 interazione e 2 layout
nativo. Le suite precedenti includono CAdES/PAdES singoli, batch misto, discovery,
selezione vincolata, crash/timeout/cancellazione, snapshot e pubblicazione verificata
senza sovrascrittura. In Release i 63 casi PAdES sono eseguiti dal packager, anche
contro l'helper nel bundle e nella copia rilocata; analogamente per Debug.
Per i test Swift è stato usato l'helper della candidata A.2: il suo SHA-256 coincide
esattamente con quello del nuovo bundle Release
(`6c3a6adb20aa239bef465cbe17401a41950cfb904c4581d6613ebfb563df4c8a`).
Il codice nativo crittografico non è stato modificato.

ASAN eseguito con `detect_leaks=0`: controllo errori di memoria, non prova di
assenza di leak AppKit o del middleware. Nessuna diagnostica di errore ASAN o race
TSAN nei run finali. Avvisi presenti: risultato inutilizzato in un test precedente
ProviderSelection; riferimenti PCM mancanti nei dati debug della toolchain Release;
invalidazione delle firme intermedie durante strip/install_name_tool. Il packager
firma nuovamente dopo questi passaggi; verifica finale strict e hash passano.
Gli avvisi non sono stati nascosti né aggirati con modifiche alle primitive.

Log conservati localmente in `.build/reliability/evidence/04a3-final-*.log`,
`04a3-package-{debug,release}.log`, `04a3-build-{debug,release}.log` e
`04a3-demo.log`. Rendering nativi in `.build/04a3-ui/`.
Nessuna regressione rilevata dalle verifiche eseguite.

### Bundle preservati e metadati

Nuova candidata **0.4.0 / build 3**, solo arm64, minimo dichiarato **macOS 13.0**
confermato nei cinque Mach-O di ciascun bundle. Percorsi esatti:

- Release: `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a3-bundles/final-release/Signum.app`
- Debug: `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a3-bundles/final-debug/Signum.app`

Manifesto `Contents/Resources/BuildManifest.json`: sourceCommit `68bf61b`,
sourceTrackedDirty false, versione/build coerenti con Info.plist. Verificati
`codesign --verify --deep --strict`, hash del codice annidato e assenza di
riferimenti locali vietati. Il packaging prova avvio helper/CLI/worker e IPC di
discovery esclusivamente sintetico, anche dopo rilocazione. Non avvia la GUI con
discovery dei middleware installati. Firma ad hoc: nessuna notarizzazione,
Developer ID o distribuzione. Alpha e candidati precedenti, inclusa la A.2,
non sono stati sostituiti.

### Riproduzione locale

Dal checkout, senza hardware e con le dipendenze private già disponibili:

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
SIGNUM_TEST_PADES_HELPER="$PWD/.build/04a3-bundles/final-release/Signum.app/Contents/Helpers/signum-pades-local" swift test --scratch-path .build/reliability
scripts/test-pkcs11-local.sh
SIGNUM_NATIVE_PREFIX="$PWD/.build/pr2-native-macos13/prefix" SIGNUM_PADES_TEST_BUILD="$PWD/.build/pr2-pades-debug" scripts/test-pades-local.sh
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build --scratch-path .build/reliability --configuration debug
swift build --scratch-path .build/reliability --configuration release
```

Comando sanitizer usato con `--filter
'CertificateVisibilityTests|BatchDestinationTests|SigningInteractionTests|SigningWorkspaceTests|BatchSigningTests'`:
`swift test --scratch-path .build/reliability-asan --sanitize address` con
`ASAN_OPTIONS=detect_leaks=0`, oppure scratch `.build/beta-tsan --sanitize thread`;
in entrambi i casi `SIGNUM_TEST_PADES_HELPER` esplicito come sopra.
Per ricreare un bundle usare una cartella **nuova**, mai sovrascrivere i candidati:

```sh
/usr/bin/python3 scripts/build-beta-app.py --configuration release --native-prefix .build/pr2-native-macos13/prefix --output .build/04a3-rebuild/Signum.app
```

### Collaudo manuale preparato, non eseguito

Fixture fresca in `.build/04a3-demo`: certificato/chiave software sintetici validi
sette giorni, provider simulato e documenti di esempio. Preparazione e discovery
pubblica con la CLI del candidato eseguite; nessuna firma manuale implicata.
Se necessario rigenerare con `scripts/prepare-batch-demo.py --output` in una nuova
cartella sotto `.build`.

1. Per una prova solo software, scollegare i token reali prima di aprire la
   candidata Release. Nella configurazione avanzata selezionare il solo modulo
   `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a3-demo/synthetic-provider.dylib`,
   caricarlo e scegliere il certificato sintetico. Non usare PIN personali.
2. Verificare default «Mostra certificati non idonei» OFF e «Salva nella cartella
   dell'originale» ON. Aggiungere i tre `.txt` di `.build/04a3-demo/documents`.
   Controllare la coda a destra e il pulsante «Firma 3 documenti» senza richiesta
   di cartella. Per la prova di cartelle diverse usare solo copie sintetiche.
3. Premere Firma: verificare una sola conferma, firmatario, certificato, formati,
   origini/destinazioni distinguibili e dettagli tecnici. Annullare una prima
   volta: nessuna firma/output deve partire e la selezione deve restare modificabile.
4. Ripetere e confermare. Per ciascun «Firma i di N — Inserisci PIN» inserire una
   stringa fittizia non vuota e usare Invio o «Firma». Il campo deve svuotarsi,
   rimanere raggiungibile senza scorrere e non comparire altre conferme documentali.
   Controllare risultati e copie `.txt.p7m` accanto agli originali, rimasti invariati.
5. Nuova sessione: deselezionare il salvataggio accanto all'originale; prima di
   Sfoglia la firma resta disabilitata. Scegliere `.build/04a3-demo/output` e
   ripetere, controllando percorso e nomi nella conferma. Ripetere con file già
   presenti: suffissi `(2)`, nessuna sovrascrittura. Se un nome viene occupato dopo
   il consenso, l'operazione fallisce senza cambiarlo: preparare una nuova sessione.
6. Nuova sessione con `synthetic.pdf` in formato PAdES: controllare anteprima,
   passaggio Documenti/esiti, destinazione `synthetic-firmato.pdf`, esito e originale.
   Verificare anche preferenze persistite al riavvio, annullamento e nuova sessione.

La demo singola ha solo un certificato idoneo: ON/OFF con certificati non idonei e
indeterminati è coperto dai test sintetici dedicati, non dimostrato da questa demo.
Il collaudo DigitalDNA reale richiede una successiva autorizzazione esplicita;
non è stato avviato in questa porzione.

### Limiti e checkpoint

- Una sola conferma applicativa, **PIN ancora per documento**: niente worker
  persistente, riuso PIN o modifica ALWAYS_AUTHENTICATE. A.4 non iniziata.
- GUI verificata tramite gerarchia/rendering nativi nei casi descritti, non tramite
  sequenza completa di click/Invio sul bundle. Interazione operatore, resa GPU
  completa PDFKit, hardware e middleware reali restano da collaudare.
- Target 13 verificato staticamente e nel packaging; nessuna esecuzione su
  macOS 13/14 o Mac pulito. Nessuna pretesa di nuova validazione InfoCamere.
- La cartella ricordata non concede permessi; permessi e identità ricontrollati.
  Il piano non mantiene un descriptor fino al commit: la protezione finale delle
  race resta nella pubblicazione Foundation. Non promette protezione da un
  attaccante con controllo dell'account o zeroizzazione garantita delle String Swift.
- In caso di collisione tardiva occorre una nuova sessione e un nuovo consenso;
  nessun rinomina automatica dopo l'approvazione.

Commit locali per milestone:

| Milestone | Commit |
| --- | --- |
| M1 baseline/perimetro | `4e2ba7f` |
| M2 filtro/preferenze | `4c764b0` |
| M3 destinazioni/job immutabili | `ef3f73b` |
| M4 conferma/PIN | `5390ebf` |
| M5 workspace/build 3 | `68bf61b` |
| M6 validazione/consegna | commit documentale contenente questa sezione |

Branch finale `codex/signum-0.4-signing-experience`; main ancora `be84a1e`, branch
A.2 ancora `a468c42`. Review non tracciata preservata con hash iniziale invariato.
Nessun altro file tracciato pendente dopo il commit M6. Nessun push/merge/tag/release,
GitHub Actions, installazione globale, hardware o accesso a HalleyMac.
**M1–M6 completate sul piano software; fermata prima del collaudo hardware.**
