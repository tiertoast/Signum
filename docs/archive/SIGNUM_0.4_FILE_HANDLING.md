# Signum 0.4-A.3.1 — Signing Workflow & File Handling

## M1 — Diagnosi riproducibile

18 ottobre 2026. Branch `codex/signum-0.4-file-handling` da HEAD effettivo A.3
`22fc4e0` (codice candidata build 3: `68bf61b`). Main `be84a1e`, file review
non tracciato preservato. Worktree verificati senza aprire altri checkout.
Il collaudo DigitalDNA positivo della build 3 è riferito dall'utente.

Baseline rieseguita prima delle modifiche al prodotto: Swift **221/221**, PKCS#11
**40/40**, PAdES Debug **63/63**. Release verificata con configurazione CMake
esplicita: lo script storico test-pades-local.sh imposta sempre Debug, anche
se CMAKE_BUILD_TYPE viene passato come variabile ambiente. Non confondere quel
run con Release; evidenza corretta separata `04a31-baseline-native-release.log`.
Release corretta **63/63**, build Swift baseline Debug/Release entrambe passate.

Percorso: NSOpenPanel/FileDropResolution → addDocuments MainActor → capture su
Task separata → fclonefileat dal descriptor originale → lettura/hash del clone
privato → DocumentSnapshot → batch → SigningJob. L'originale non è un input della
firma successiva. Il codice già usa descriptor stabili, clone CoW sullo stesso
volume, symlink rifiutati e snapshot 0700/0400. Non usa birthtime come condizione.

**Causa dimostrata del falso positivo:** DocumentSnapshot.unchanged confronta
device/inode/dimensione/mtime/**ctime**. L'ultimo guard di capture attribuisce a
una modifica del documento qualsiasi variazione di questi campi, ma anche errori
di fstat o mancato binding al percorso finiscono nello stesso messaggio.
Un aggiornamento xattr può cambiare solo ctime, lasciando byte e mtime invariati.

Test deterministico `FileAcquisitionTests.testMetadataOnlyChangeDoesNotRejectCoherentPDF`:
al primo read del clone, fsetxattr sul descriptor dell'originale. Assert su
dimensione/mtime invariati e ctime variato, poi verifica byte originali/snapshot.
**Eseguito sulla baseline del prodotto: 1 test, 1 fallimento**, proprio con
«Il documento è cambiato durante l'acquisizione». Nessun sleep casuale o file
personale. Log `04a31-m1-reproduction.log`. Il commit M1 contiene intenzionalmente
questa regressione ancora rossa, prima del fix M2.

Questa è una causa riprodotta, non una prova che Spotlight/quarantena/browser
abbiano modificato i metadati dei PDF del collaudo. Quei file non sono stati letti.
Limiti individuati separatamente: CAdES 16 MiB, PAdES 64 MiB, sessione 128 MiB;
IPC firma trasporta attributi/digest e certificato, non l'intero documento.
Il clone è su disco ma DocumentSnapshot conserva anche una Data completa; CMS
costruisce ulteriori Data. Non basta alzare una costante per promettere 200 MiB.

## M2 — Acquisizione coerente e diagnosi distinta

Registrazione vnode kqueue/kevent64 sul descriptor prima dello stat iniziale;
NOTE_WRITE/EXTEND/RENAME/DELETE/REVOKE causano rifiuto. NOTE_ATTRIB da solo non è
una scrittura. Il clone CoW conserva un'immagine coerente; device/inode/size/mtime
e binding del percorso restano controllati. Se cambia soltanto ctime, confronto
completo sul descriptor originale con il clone, con stat prima/dopo la lettura.
Non basta che due hash coincidano: il test scrive/ripristina byte e mtime e viene
comunque rifiutato per evento WRITE. Nessun fallback streaming su filesystem che
non supportano clone/eventi. Errori di monitoraggio falliscono in sicurezza.

La garanzia è uno snapshot coerente del clone approvato, non l'immobilità eterna
dell'originale: modifiche successive non vengono firmate. Non protegge da un
avversario con controllo del processo/kernel/account. Aggiornamenti continui
durante la lettura di corroborazione possono ancora causare un rifiuto conservativo.

DocumentAcquisitionFailure separa changed/unavailable/read/tooLarge/space/timeout/
cancelled/unsupported. Messaggi semplici in GUI; syscall/errno in dettagli tecnici
espandibili, senza contenuto, credenziali o stack trace. Read EINTR ripetuto, EIO e
permessi non trasformati in «documento modificato». Deadline monotona 30 secondi,
controllata fra chunk/fasi; un syscall bloccato non può essere interrotto da questa
deadline. Annullamento cooperativo ora passa anche all'acquisizione del batch.
Callback obsoleta chiude lo snapshot e non ripopola la sessione annullata.

Regressioni deterministiche aggiunte: metadati xattr innocui, scrittura transitoria
con ripristino, troncamento, rename/sostituzione, EINTR/EIO/EACCES/ENOSPC, file
assente, timeout con clock iniettato, annullamento e callback tardiva/concorrenza
con barriera. Le 18 regressioni snapshot precedenti restano attive, incluse symlink,
corruzione e cleanup crash. Prima compilazione del monitor corretta da kevent
(collisione nome tipo/funzione Swift) a kevent64; nessuna rinuncia al controllo.

M2 verificata: **37/37** Swift mirati, PKCS#11 **40/40**, PAdES Debug/Release
**63/63** ciascuno, build Debug/Release passate. Un primo run mirato ometteva
SIGNUM_TEST_PADES_HELPER e saltava due integrazioni: ripetuto con helper esplicito,
zero skip nella verifica registrata `04a31-m2-acquisition-final.log`.

## M3 — Il pulsante principale è il consenso

Nuovo preflight read-only Core prepareReview: verifica gli snapshot e SG-04,
determina nomi reali/collisioni prima del clic e produce job immutabili, senza
congelare le selezioni, creare output o chiedere PIN. Il riepilogo ordinario mostra
firmatario/certificato, documenti/formati, origini e destinazioni effettive;
hash e identità/provider nei dettagli espandibili. Nessun nome nominale viene
presentato come piano approvabile mentre il preflight è incompleto.

SigningReviewContext lega revisione documenti, provider/slot/ID/DER certificato,
destinazione, route e generazione discovery. Qualsiasi variazione disabilita
immediatamente il pulsante anche prima dell'aggiornamento asincrono della vista.
Callback cancellate/obsolete non pubblicano un piano nuovo sotto un vecchio
contesto. Il clic chiama freezeReview e confirm sincronicamente sul MainActor,
approvando solo l'ID già mostrato, senza altro lavoro asincrono tra verifica e
consenso. Hash/integrità sono ricontrollati prima dell'operazione privata.

Default persistente OFF: «Richiedi conferma aggiuntiva prima della firma», nella
sezione Impostazioni. OFF non presenta alcun secondo popup; ON congela il medesimo
piano, presenta il riepilogo modale e consente annullamento. Un cambio selezione
durante il modal viene rifiutato prima di confirm. Preferenze successive non
modificano job già approvati. PIN e consenso restano due atti distinti.

Per ogni PAdES resta obbligatoria l'anteprima dello snapshot. Prima del clic
occorre tornare a «Documenti ed esiti», rendendo visibile il riepilogo ordinario.
Nessuna autenticazione automatica, cache PIN o nuovo worker persistente.
Collisioni dopo il preflight/consenso bloccano la richiesta privata; non viene
scelto silenziosamente un nuovo nome.

M3: **38/38** Swift mirati (sei nuovi casi review/consenso), PKCS#11 **40/40**,
PAdES Debug/Release **63/63** ciascuno, build Debug/Release passate. Test:
zero modal nel percorso diretto, nessun PIN prima del clic, piano congelato,
preferenza persistita/annullamento, sette cambi di contesto, rimozione con callback
tardiva deterministica, cambio nel modal e collisioni pre/post clic. Restano attivi
i test interazione/PIN e due test di gerarchia/rendering nativi. Non equivalgono
ancora a un collaudo manuale completo del nuovo bundle.

## M4 — Ampliamento controllato a 100 MiB

Soluzione intermedia, senza riscrivere CMS/PDF o lo snapshot: **100 MiB per
documento** sia CAdES sia PAdES; **128 MiB totali** per sessione, massimo 32 elementi.
Output/verifica CMS e output PAdES limitati a **132 MiB**. Valori Swift centralizzati
in SigningResourceLimits; limiti corrispondenti nell'helper C++ aggiornati. Solo
guard dimensionali, nessun algoritmo o formato crittografico cambiato. 200 MiB
e 100 MiB+1 non sono supportati e ricevono errore dimensionale prima di allocare.

Architettura: clone privato su disco e Data immutabile in memoria per snapshot;
sessione trattiene al massimo 128 MiB di contenuti approvati. Durante acquisizione
può esistere temporaneamente un altro documento fino a 100 MiB prima del controllo
del budget batch; nessun job privato parte per il documento respinto. CMS e parser
creano copie ulteriori: il budget sessione **non è un limite RSS di processo**.
Riservata capacità della Data dopo lo stat limitato, evitando riallocazioni di
crescita nelle letture snapshot e CAdES esterno.

IPC invariato: request supervisor 128 KiB, attributi da firmare <=4096 byte,
certificato <=65536 byte, risposta <=2 MiB; documenti mai serializzati nel JSON.
PAdES riceve percorso snapshot/hash e legge il file privato; riserva firma
dimensionata dal certificato come prima. Timeout acquisizione 30s cooperativo;
worker/helper firma 120s e verifica OpenSSL 30s invariati. Lunghezze validate prima
di conversione/allocazione, sottrazioni limitate nelle letture; DER fino a 132 MiB
resta entro il limite delle lunghezze già supportate. Limiti del grafo risorse PDF
e verifica restano attivi, ora con il tetto output dichiarato.

**M4: 37/37** Swift mirati, PKCS#11 **40/40**, PAdES Debug/Release **63/63**
ciascuno, build Debug/Release passate. Sei nuovi test generano/eliminano fixture
temporanee: 1 MiB, 16 MiB, 16 MiB+1 byte, 50 MiB e 100 MiB nei due formati; esclusione 100 MiB+1 byte e
200 MiB; CAdES da 100 MiB tramite worker sintetico con verifica CMS/payload;
PAdES da 100 MiB con helper/CoW/hash/receipt verificata; batch 50+50 accettato e
terzo 50 respinto dal budget sessione; timeout/annullamento durante lettura grande;
output CAdES parziale con ENOSPC, cleanup e nessun file finale. Collisioni, errori
prima/dopo firma e altri failure path restano coperti dalle suite Foundation.
Questi test non dimostrano compatibilità di ogni PDF complesso sotto 100 MiB.

**Misure reali** sul Mac di sviluppo, macOS 27.2 arm64, 24 GiB RAM:
- primo run grandi prima di reserveCapacity: picco processo XCTest circa 2,08 GB;
- run M4 finale, 37 casi inclusi i grandi: CAdES ~895 MB, massimo suite ~911 MB
  RSS (getrusage RUSAGE_SELF, include runner/allocator; non un tetto garantito GUI);
- helper PAdES Release da 100 MiB isolato sotto `/usr/bin/time -l`: RSS massimo
  **673.021.952 byte**, footprint **663.602.232 byte**, exit 0, pubblicazione
  verificata 104.861.277 byte. Input e output grandi eliminati dopo la misura.

Log `04a31-m4-final.log` e `04a31-native-memory.log`. Il consumo del processo GUI
e quello dell'helper possono sommarsi: non sono intercambiabili. Nessuna prova
su Mac con poca RAM, nessuna promessa di 200 MiB. Per arrivarci in sicurezza serve
ridurre le copie CMS/parser e rendere lo snapshot prevalentemente su disco o
streaming, con ulteriori test; refactoring rinviato al checkpoint successivo.

### Controllo finale M5: prenotazione della selezione

Individuato nel controllo finale un ulteriore intervallo da chiudere: la GUI
accettava NSOpenPanel e schedulava una Task prima che Core segnalasse acquisizione
in corso. enqueueDocuments ora invalida il riepilogo e riserva la selezione
sincronicamente, prima della Task. Il test deterministico tenta subito il vecchio
consenso, una seconda selezione e un annullamento prima che la Task parta: nessun
vecchio piano approvabile, nessun file aggiunto dalla callback annullata.
Le verifiche/bundle iniziali su `9e830a5` saranno sostituiti come riferimento di
consegna da nuovi bundle separati contenenti questa correzione, senza sovrascriverli.

## M5 — Risultati finali e consegna

Codice finale `daca4cf`, candidata **0.4.0/build 4**, albero tracciato pulito al
packaging. Il commit di consegna successivo aggiorna solo i due rapporti.

| Verifica eseguita localmente | Esito |
| --- | --- |
| Swift completo, helper Release esplicito | **240/240**, zero skip/fallimenti |
| PKCS#11 provider/lifecycle sintetico | **40/40** |
| PAdES Debug e Release | **63/63** ciascuno |
| Packaging Python | **10/10** |
| Swift build Debug/Release | passate |
| Bundle Debug/Release, originali e rilocati | passati |
| ASAN mirato | **63/63**, zero skip/fallimenti |
| TSAN mirato | **63/63**, zero skip/fallimenti |
| Firma ad hoc strict, hash annidati, portabilità, metadata e minos | passati |

19 nuovi test: 6 acquisizione, 7 review/consenso e 6 file grandi. Regresse anche
le suite precedenti: CAdES/PAdES singoli, batch misto, discovery/selezione,
snapshot immutabili, certificati, lifecycle/lease, crash/timeout/cancel, esiti
incerti, ACL, output atomico e no-overwrite. Nessuna regressione rilevata.
I 63 casi PAdES girano anche nell'esatta copia di ciascun bundle e dopo rilocazione.
Una verifica aggiuntiva del PDF da 100 MiB usa l'helper del bundle Release di
consegna, non soltanto quello nella cartella di sviluppo.

Sanitizer sui componenti acquisizione/review/consenso/PIN/workspace/destinazioni
e regressioni batch/snapshot; i sei test grandi sono misurati nei run normali.
ASAN con `detect_leaks=0`, quindi nessuna attestazione di assenza di leak; TSAN
senza segnalazioni di race. Avvisi non fatali: risultato inutilizzato nel test
ProviderSelection precedente, PCM debug mancanti nella toolchain Release,
invalidazione delle firme intermedie durante strip/install_name_tool seguita da
firma finale valida. Non soppressi con deroghe ai controlli.

Due rendering nativi NSHostingView/NSWindow prodotti e ispezionati in
`.build/04a31-ui`: campo PIN vuoto raggiungibile con 32 documenti a 650 punti,
PDFView sullo snapshot e controlli preservati. La versione 16.0/build 25229
visibile nei PNG appartiene a XCTest; i bundle consegnati sono 0.4.0/build 4.
PDFKit usa rendering GPU non interamente catturato dal PNG: pagina/doc verificati
nella gerarchia nativa, non dichiarato un collaudo visivo completo del PDF.
Discovery reale disattivata tramite iniezione interna ai test, nessun middleware
installato caricato. Nessuna interazione automatica con altre applicazioni.

### Candidati da usare

- **Release:** `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a31-bundles/delivery-release/Signum.app`
- **Debug:** `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a31-bundles/delivery-debug/Signum.app`

SourceCommit `daca4cf`, sourceTrackedDirty false, version/build/Info.plist coerenti;
cinque Mach-O per bundle arm64 con target **13.0**, verificati anche i rispettivi
hash e `codesign --verify --deep --strict`. Solo firma ad hoc locale, nessuna
notarizzazione o distribuzione. I percorsi `04a31-bundles/final-*` sono candidati
intermedi precedenti alla correzione della selezione accodata: usare delivery-*.
Alpha e build 2/3 preservate, nessuna sostituzione della versione originale.

Evidenze: `.build/reliability/evidence/04a31-*`; risultati definitivi nei log
`04a31-delivery-*`, suite native `04a31-final-{pkcs,pades-debug,pades-release}.log`.
Le misure M4 separate restano osservazioni, non limiti di memoria garantiti.

### Riproduzione software locale

```sh
cd /Users/andreaoregioni/Developer/Signum-Reliability
SIGNUM_TEST_PADES_HELPER="$PWD/.build/04a31-bundles/delivery-release/Signum.app/Contents/Helpers/signum-pades-local" swift test --scratch-path .build/reliability
scripts/test-pkcs11-local.sh
.build/native-tools/cmake/data/bin/ctest --test-dir .build/04a31-pades-debug --output-on-failure --verbose
.build/native-tools/cmake/data/bin/ctest --test-dir .build/04a31-pades-release --output-on-failure --verbose
/usr/bin/python3 -m unittest discover -s scripts/tests -v
swift build --scratch-path .build/reliability -c debug
swift build --scratch-path .build/reliability -c release
```

Le cartelle native sono state configurate esplicitamente Debug/Release sul
prefisso privato macOS 13 `.build/pr2-native-macos13/prefix`. Per nuove build
native ripetere configure/build prima di ctest; il solo ctest non ricompila.
Per il packaging usare sempre un percorso nuovo, per esempio:

```sh
/usr/bin/python3 scripts/build-beta-app.py --configuration release --native-prefix .build/pr2-native-macos13/prefix --output .build/04a31-rebuild/Signum.app
```

### Procedura di collaudo manuale, ancora da eseguire

Demo sintetica fresca `.build/04a31-demo` preparata, discovery pubblica CLI/worker
del candidato verificata senza hardware. Certificato valido sette giorni; se
scaduto rigenerare con `scripts/prepare-batch-demo.py --output` in directory nuova.

1. Per il collaudo solo software scollegare i token reali, aprire la candidata
   **delivery-release** e configurare esplicitamente il modulo
   `/Users/andreaoregioni/Developer/Signum-Reliability/.build/04a31-demo/synthetic-provider.dylib`.
   Selezionare il certificato sintetico. Utilizzare solo stringhe PIN fittizie.
2. Lasciare OFF «Richiedi conferma aggiuntiva prima della firma». Aggiungere i tre
   `.txt` della demo; attendere il riepilogo con destinazioni effettive. Verificare
   che Firma resti disabilitato durante acquisizione/preflight e che non compaia
   alcun campo PIN prima dell'approvazione.
3. Premere «Firma 3 documenti»: deve apparire direttamente «Firma 1 di 3 — Inserisci
   PIN», senza popup Conferma firma. Autenticare esplicitamente ogni documento
   con una stringa fittizia; campo svuotato e nessun retry/riuso automatico.
4. Nuova sessione; provare un documento `.pdf` in PAdES, aprire l'anteprima e
   tornare a Documenti ed esiti prima di Firma. Verificare copia `-firmato.pdf`,
   esiti e originale invariato. Provare anche cartella comune e nomi già occupati.
5. Nuova sessione; nelle Impostazioni attivare la conferma aggiuntiva e tornare
   alla firma: provare Annulla nel modal, poi confermare. Nessun output se annullato.
   Verificare persistenza OFF/ON al riavvio; cambiamenti prima del clic devono
   invalidare il vecchio riepilogo, mai aggiornare silenziosamente job approvati.
6. I test LargeDocumentTests generano temporaneamente le taglie fino a 100 MiB,
   eseguono le due firme da 100 MiB e ripuliscono le fixture. Per un ulteriore
   collaudo manuale dimensionale usare solo nuovi PDF sintetici: sopra 100 MiB
   deve apparire l'errore dimensionale, senza classificarli come modificati.

### Problemi aperti e stato Git

- Causa del falso positivo **riprodotta nel codice**, ma non identificato quale
  processo/servizio aggiornasse i metadati dei PDF reali in Download. Nessun file
  personale esaminato; il riscontro su quei casi resta un collaudo successivo.
- Scritture osservate, sostituzioni e metadati che cambiano continuamente durante
  la corroborazione fanno fallire in sicurezza; filesystem/volumi senza CoW o
  diverso volume dell'area privata restano esclusi. Nessun confronto hash usato
  come unica prova di assenza di modifiche transitorie.
- **200 MiB non supportati**; snapshot ancora con cache Data e copie CMS/PDF.
  Budget batch 128 MiB, non 32×100 MiB. GUI/preview di PDF complessi e uso su Mac
  con poca RAM non misurati; serve ulteriore architettura prima di aumentare.
- Deadline cooperativa non interrompe un syscall bloccato; nessuna cancellazione
  forense promessa. PIN per documento e limiti di zeroizzazione Swift invariati.
- GUI interattiva completa, hardware, macOS 13/14 e Mac pulito non collaudati.
  Target 13 dimostrato staticamente e nel packaging, non come prova runtime.

Commit locali: M1 `866a749`; M2 `8fdcea4`; M3 `ef7e147`; M4 `a43162c`;
preparazione M5/build 4 `9e830a5`; correzione finale selezione `daca4cf`;
seguiti dal commit documentale contenente questa consegna.
Branch `codex/signum-0.4-file-handling`; main `be84a1e` e A.3 `22fc4e0` invariati.
Review non tracciata preservata, SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
Nessun push/merge/tag/release/CI remoto, installazione globale, accesso a HalleyMac,
PIN reale o test hardware. Fermata al checkpoint software M1–M5 completato.
