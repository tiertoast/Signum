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
temporanee: 1, 16, 16+1 byte, 50 e 100 MiB nei due formati; esclusione 100+1 e
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
