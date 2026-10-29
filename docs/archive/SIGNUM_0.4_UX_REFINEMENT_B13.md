# Signum 0.4 — UX refinement, build 13

## Baseline e perimetro

19 ottobre 2026. Workspace ~/Developer/Signum-Reliability. Branch creato codex/signum-0.4-ux-refinement-b13 dall’HEAD effettivo B12 **82e76949bd5e6066c3d616374ea98ef4457830a1**, successivo al sorgente dei bundle B12 **4b00b2c2f596792bc984d954da8fd688d5ea9565**. Letti i rapporti B10/B11/B12 e il progress pertinente. La conferma manuale della rotazione B12 è dell’utente, non un test hardware eseguito in questa sessione.

Prima delle modifiche: file tracciati puliti. I due documenti già non tracciati CODE_REVIEW_SIGNUM_0.3.3_2026-10-17.md e SIGNUM_0.4_PADES_PERFORMANCE_DIAGNOSIS.md restano esclusi dai commit. Censiti in .build/04stabilization-b13/evidence/baseline.json 57 file (documenti, manifest, eseguibili e plist delle build precedenti) e 6 ref protetti. Nessun accesso ad altri repository, HalleyMac, PR #3, hardware o documenti personali; nessun push/merge/tag/release/Actions/installazione globale.

## UX-01: default visibile e geometria fisica

La GUI non offre più “Mostra firma nel PDF”: il normale percorso PAdES prepara subito un timbro visibile con orientamento Automatico, anche senza certificato. In quest’ultimo caso l’anteprima mostra la dicitura generica senza inventare un firmatario; un avviso spiega che il nome sarà aggiornato con il certificato. Il desiderio di mostrare il nome rimane nel draft. L’arrivo/cambio del DER prepara risorse nuove, revoca la readiness precedente e vincola l’AP al fingerprint effettivo. Senza certificato idoneo il consenso rimane impossibile. Core/API/CLI conservano il supporto invisibile.

PAdESPageGeometry è una funzione geometrica indipendente da SwiftUI/PDFKit. Input: MediaBox, CropBox, /Rotate e /UserUnit dello snapshot approvato, dimensioni fisiche logiche e orientamento. Usa l’intersezione dei box e riutilizza le matrici ortogonali B12 con la rotazione inversa per mappare il crop grezzo nella pagina visibile. Restituisce configurazione, pagina, orientamento e /Rect grezzo, oppure errore esplicito. Supporta origini traslate/negative e rotazioni 0/90/180/270; non analizza l’orientamento del testo dentro una scansione.

Dimensioni iniziali **240 × 90 pt fisici**, indipendenti dal formato pagina. Il margine superiore e destro nel viewer è **10 × 72 / 25,4 = 28,3464567 pt fisici**. Dimensioni e margini vengono divisi per UserUnit prima della conversione nelle coordinate grezze. UserUnit deve essere numerico, finito, positivo e al massimo 75000. Non viene ignorato o sostituito se malformato.

Fallback: senza spazio per 10 mm riduce separatamente ogni margine allo spazio disponibile, fino a zero; dimensioni e proporzioni restano invariate. Se il timbro non entra nemmeno senza margine, anteprima non pronta e messaggio esplicito. Nessun ridimensionamento proporzionale alla tavola, clipping o riposizionamento silenzioso di configurazioni esistenti.

Il renderer genera ancora un singolo PDF vettoriale zero-origin e senza /Rotate. La tipografia, i bordi, gli inset e l’immagine vengono impaginati in punti fisici e trasformati in unità grezze; AP, preview e helper usano le stesse risorse. I controlli larghezza/altezza e i limiti del resize sono fisici anche su pagine con UserUnit diverso da 1. Nel cambio pagina si conserva la dimensione fisica; nel cambio orientamento si conservano centro e dimensioni logiche, applicando solo il clamp necessario.

UserUnit è metadata approvato nell’appearance e nella sua identità di consenso; SigningJob lo confronta con la pagina dello snapshot prima del consenso. I chiamanti legacy con userUnit=nil mantengono il contratto grezzo precedente. La GUI fornisce sempre il valore della pagina.

### Adeguamento necessario dell’helper

Le firme sintetiche hanno dimostrato che il controllo preesistente dell’helper rifiutava un AP fisicamente corretto, per esempio 90 × 240 pt su /Rotate=90 e UserUnit=2: il footprint grezzo 45 × 120 scendeva sotto il vecchio minimo di 80 unità in larghezza. Questo avrebbe impedito di firmare alcuni nuovi default.

Il percorso AP vettoriale GUI passa quindi --appearance-user-unit. L’helper verifica il valore sulla pagina dello snapshot e applica i limiti fisici 80–800 × 40–500 pt, ammettendo il footprint scambiato per i quarti di giro. Conserva il controllo di contenimento nel crop effettivo, AP/Rect corrispondenti e limiti sui byte; il controllo avviene prima di C_Login. Senza l’opzione rimangono i limiti grezzi legacy. Nessuna modifica alle primitive di firma, gestione PIN, transazioni di output o lifecycle PKCS#11.

### Persistenza e rendering

PAdESPlacement conserva un draft separato dall’AP pronta. Ogni modifica aggiorna subito il draft e invalida readiness/appearance approvabile prima della preparazione asincrona. Chiusura/riapertura e riselezione dello stesso documento ripristinano il draft, compreso un edit il cui render non era ancora terminato. Zoom e scroll non riscrivono la configurazione. I controlli di generazione del workspace e del render scartano callback obsolete.

Spostare mantiene il riuso dei byte/hash/artwork B11/B12; non ricrea PDF/immagini o raster durante il drag. Il consenso torna disponibile soltanto quando l’overlay ha effettivamente disegnato l’AP corrente, e non durante un’interazione. Errori di geometria/render/presentazione rimangono espliciti e non pronti. PAdES→CAdES elimina l’AP come nella B11/B12; il ritorno a PAdES ricomincia dai default. Nessuna persistenza globale delle geometrie o nuovo protocollo di integrazione.

## UX-02: selezione univoca di una route osservata

La policy appartiene a SignumCore/DeviceSelection, non alla sola GUI. Il risultato di discovery viene valutato off-main usando ESATTAMENTE CertificateEligibility/SG-04 già esistente. L’unicità si conta sulle route complete provider canonico/identità file/slot/token/CKA_ID/DER, non sui gruppi grafici per DER o su label, CN, DS3/CNL0, ordine di arrivo o ultimo provider usato.

- Zero route localmente idonee: nessuna selezione automatica, inclusi sola autenticazione, scaduti e indeterminati.
- Una route idonea dopo scan completo: selezione automatica, visibile con identità estratta dal DER, anche prima di caricare documenti.
- Due o più: scelta manuale. Stesso DER su due provider/slot resta ambiguo. Osservazioni identiche della stessa route vengono deduplicate.
- Scelta manuale ancora osservata con intero binding e idoneità valida: conservata. Scelta automatica: rivalutata a ogni ricerca; la comparsa di alternative richiede scelta manuale.
- La selezione può essere modificata esplicitamente attraverso i controlli esistenti. I certificati esclusi possono ancora essere ispezionati; SG-04 continua a vietarne la firma.

Ogni scan GUI include provider noti e percorsi manuali configurati, compreso quello eventualmente appena aggiunto. expectedPaths è congelato PRIMA del worker. La selezione automatica richiede copertura esatta dell’insieme configurato e assenza di errori, cancellazioni, slot non leggibili, token non ispezionati, certificati nascosti/autenticazione richiesta. Anche un token senza certificati pubblici leggibili non prova l’unicità. Software mancante e assenza verificata di token sono esiti completi; errori di caricamento/sicurezza/comunicazione sono esiti incerti. I limiti dello scan non possono produrre una falsa completezza. Un semplice array senza expectedPaths permette solo ispezione/scelta manuale.

La GUI applica un solo risultato finale della generazione corrente; risultati tardivi, duplicati o dopo cancellazione non possono selezionare nulla. Refresh rimuove subito i binding attivi e PIN e invalida il preflight; un consenso precedente non può sopravvivere. Rimozione/reinserimento, slot/provider o DER cambiato producono nuove osservazioni, mai il riuso implicito di un vecchio binding. Durante un job approvato/frozen la GUI vieta refresh e cambi di selezione; un modello di discovery separato non può mutarne i job immutabili.

### Disponibilità e limiti della chiave privata

Prima di preparare il consenso la GUI richiama requireCurrentCredential off-main: ricontrolla l’identità del modulo, esegue soltanto scan/lettura pubblica tramite worker isolati, confronta slot, serial/model/manufacturer/reader, CKA_ID e DER esatti e rivaluta SG-04. Un fallimento invalida selezione/provider/preflight e richiede nuova ricerca. Nessun login, PIN o firma viene eseguito dal discovery, autoselezione o questo controllo.

L’associazione approvata è il binding pubblico CKA_ID+DER alla route osservata. L’accessibilità di una chiave privata nascosta fino al login e il successo dei meccanismi del middleware non si possono dimostrare universalmente senza autenticazione: l’autoselezione NON li dichiara provati. Si conserva il controllo effettivo già presente nei motori dopo l’autorizzazione, con ricerca della chiave per ID, confronto del DER e verifica matematica della firma contro la chiave pubblica approvata. Nessuna euristica sostitutiva o autenticazione anticipata. La compatibilità algoritmo RSA è quella di SG-04 esistente; non si aggiungono algoritmi/meccanismi.

Non c’è un nuovo monitor hardware continuo: rimozioni vengono recepite al refresh, nel preflight pubblico o nei controlli al momento della firma. Un dispositivo può sempre sparire tra preflight e firma: l’errore fallisce senza pubblicare output incompleti o ritentare il PIN. Idoneità locale non significa fiducia CA, revoca, qualificazione eIDAS o validità giuridica.

## Verifiche

Fixture esclusivamente sintetiche, chiavi software effimere e provider mock compilati localmente. Nessun PIN o token personale. I primi run hanno evidenziato un errore di compilazione dei nuovi test (corretto) e un’attesa pixel errata che presumeva l’upscale di CGPDF.getDrawingTransform: le attese finali usano dimensioni fisiche indipendenti; la geometria resta anche confrontata con CGPDF in scala 1. Il test di firma ha inoltre rilevato e guidato l’adeguamento del limite grezzo nell’helper descritto sopra. I log preliminari restano separati dagli esiti finali.

Regressioni finali sul codice di questa porzione:

| Verifica locale | Esito |
|---|---:|
| Swift completa (incluse GUI native, consenso, formati, batch, snapshot, atomicità e Secure PIN sintetico) | **378/378** |
| Provider PKCS#11 sintetico | **40/40** |
| PAdES nativo Debug | **65/65** |
| PAdES nativo Release | **65/65** |
| Packaging Python | **10/10** |
| ASAN Swift mirato | **38/38** |
| TSAN Swift mirato | **38/38** |

Zero skip/fallimenti nei run finali; nessun risultato storico B12 riutilizzato. Log in .build/04stabilization-b13/evidence: final-swift.log, final-asan.log, final-tsan.log, pkcs11.log, pades-debug.log, pades-release.log e final-packaging-tests.log (rieseguito anche dopo il solo cambio versione).

Le 22 nuove regressioni Swift comprendono 300 combinazioni geometriche (5 formati × 4 rotazioni × 3 UserUnit × 5 orientamenti), 12 confronti pixel nativi a posizione iniziale indipendente, equivalenza pixel della tipografia fisica, piccoli crop/fallback/errori, draft/zoom/drag/ripristino, errori di rendering e vincolo UserUnit del job. Le 16 nuove firme software (4 rotazioni × UserUnit 1/2/0,5/0,1, anche tavole complesse) controllano AP/N, Rect/BBox, Rotate/UserUnit, integrità con motore unificato, ByteRange/CMS con OpenSSL indipendente, originale invariato, margini e direzione asimmetrica con Poppler. Si aggiungono le 20 firme orientate B12 rieseguite nella suite completa e le regressioni CAdES/invisibili esistenti.

Test native GUI: timbro testuale effettivamente dipinto senza clic e senza DER, pixel non bianchi misurati nella vista dell’artwork, readiness dopo presentazione, zoom 25/100/200%, drag e remount con draft di dimensione/orientamento personalizzati; gli esistenti test nativi coprono resize, scroll e cambio pagina/documento/formato e callback tardive. Lo switch è rimosso dal View: controllo del codice compilato; nessuna dichiarazione di click-test umano del menu. La cattura native-default.png è una rasterizzazione del test host (alcuni layer SwiftUI restano trasparenti), non una cattura completa dello schermo. Non sostituisce il collaudo manuale.

Le prove discovery includono copertura configurata incompleta, errori/slot oscuri, unicità indipendente da ordine, duplicati/route distinte, refresh/removal/reinsert/slot/DER, manualità conservata e autoselezione invalidata, risposte obsolete e duplicate, immutabilità approvata e revoca del preflight. Audit del provider mock verifica zero Login e zero Sign nel discovery/autoselezione/rivalidazione pubblica.

Versione avanzata a **0.4.0/build 13 soltanto dopo** questi run. Build Debug/Release e confezionamento locale completati nelle nuove directory, senza sovrascrivere bundle precedenti. Firma ad hoc deep/strict valida, architettura arm64, minimo dichiarato e misurato nei Mach-O 13.0, closure dipendenze interna/di sistema, notices e hash annidati verificati. La ricetta ha rieseguito i 65 casi nativi per configurazione, con helper impacchettato e sulla copia rilocata; avvio CLI/worker/helper e discovery pubblico esclusivamente mock riusciti. Nessun lancio automatico della GUI con discovery hardware. Log bundle-debug.log e bundle-release.log.

Le integrazioni Swift con gli helper effettivamente inclusi sono **72/72 Debug e 72/72 Release**, zero skip/fallimenti, registrate in bundle-debug-integration.log e bundle-release-integration.log. I 72 includono i nuovi 22 metodi e le precedenti 50 integrazioni (batch, AP, formati, verifica e orientamento).

## File coinvolti

Core: PAdESDefaultPlacement.swift, PAdESAppearance.swift, PAdESAppearanceOrientation.swift, SigningJob.swift; DeviceSelection.swift e DeviceCertificate.swift. App: PAdESPlacementPane.swift, SignumPAdESHelper.swift, ProviderSelection.swift, SigningReview.swift e main.swift. Helper: PAdESAppearance.h, signum_pades_local.cpp e test nativi. Nuove suite PAdESDefaultPlacementTests, PAdESDefaultSigningTests, AutomaticCertificateSelectionTests e AutomaticSelectionConsentTests; aggiornate solo aspettative storiche incompatibili con l’autoselezione ora richiesta e il nome di un test dei percorsi configurati.

## Limiti e collaudo manuale richiesto

Il collaudo dei controlli/menu con persona, tavola reale e dispositivo DigitalDNA/CNS rimane successivo. Nessuna prova su runtime macOS 13/14: target minimo 13 e audit Mach-O/SDK non equivalgono a esecuzione su tali sistemi. Lo scan è sequenziale e limitato, non una fotografia fisica simultanea di tutti i dispositivi; il nuovo controllo pubblico e il binding durante la firma riducono la finestra residua senza promettere hotplug atomico.

Il default non individua spazio bianco nella tavola: può coprire contenuto e va spostato se necessario. Preview senza DER è esplicitamente provvisoria rispetto al nome del firmatario; solo il render successivo vincolato al certificato può essere approvato. I Core/API legacy devono fornire geometry/pageRotation/userUnit per usare i nuovi invarianti fisici; la compatibilità grezza/invisibile resta intenzionale.

Commit locali implementazione:
- 220c59b — UX-01, geometria/default visibile, conservazione draft, UserUnit nel renderer/job/helper e regressioni.
- 0336d0b — UX-02, scan completo, provenienza auto/manuale, rivalidazione pubblica e regressioni di consenso.
- **a6247ab8a04e37b58ccb36371404c5a236ea8d0c** — versione/documentazione dopo le regressioni, fonte dei bundle 13 con sourceTrackedDirty=false.
- Successivo commit solo documentale — risultati finali e consegna; nessuna modifica al codice dei bundle.

Nessuna distribuzione pubblica.

### Sequenza di collaudo manuale successivo (non eseguito)

1. Aprire soltanto il nuovo bundle Release e controllare 0.4.0/build 13. Con una sola route di firma localmente idonea verificare la selezione prima di scegliere documenti e l’assenza di richieste PIN; con più route verificare la scelta manuale. La sola presenza di un certificato di autenticazione non deve produrre selezione.
2. Caricare un PDF anche senza certificato. In PAdES il timbro deve apparire subito nell’angolo superiore destro, senza switch, con il messaggio provvisorio se manca il DER. Sulla tavola reale controllare Automatico e gli orientamenti manuali, quindi zoom/scroll, drag e Option-resize.
3. Chiudere e riaprire l’anteprima, alternare documenti/pagine e controllare il mantenimento della configurazione. PAdES→CAdES→PAdES deve eliminare la vecchia appearance e ricominciare dai default, come già concordato. Se il certificato arriva/cambia dopo la chiusura, riaprire e attendere l’anteprima aggiornata prima del consenso.
4. Durante una ricerca non deve essere possibile usare il vecchio riepilogo. Rimuovere/reinserire un dispositivo e cercare nuovamente: nessun vecchio binding/consenso deve sopravvivere. Una route manuale valida può essere conservata; una auto con nuove alternative richiede una scelta.
5. Eventuali firme con DigitalDNA/CNS e PIN reali richiedono una sessione successiva espressamente autorizzata. Verificare separatamente su macOS 13/14 prima di dichiarare compatibilità runtime collaudata. Nessuna di queste prove hardware è stata automatizzata qui.


## Bundle di consegna

Fonte: **a6247ab8a04e37b58ccb36371404c5a236ea8d0c**, 0.4.0/build 13, sourceTrackedDirty=false in entrambi i manifest.

| Bundle | Eseguibile principale SHA-256 |
|---|---|
| .build/04stabilization-b13/final-release/Signum.app | c7b3a55d06b4508fff0728f020f882987519b64e50cd94e438ccd54f88391cbf |
| .build/04stabilization-b13/final-debug/Signum.app | 0420685a45ea9cdd91a40d0639014399ff7189be653586fb0ee33e8055ba5044 |

Firma ad hoc per uso locale, senza Developer ID/notarizzazione/distribuzione. Dettagli riproducibili, hash manifest e quattro codici annidati in evidence/final-bundles.json. Controllo conclusivo dopo entrambe le integrazioni: tutti i **57 file e 6 ref protetti invariati**; eseguibili/manifest/codice annidato dei nuovi bundle invariati e codesign strict nuovamente valido. Evidenza in final-verification.json.


## Stato finale

UX-01 e UX-02 implementate e verificate nel perimetro documentato. Nessuna regressione nelle suite finali. A invio di 30/120 eventi a 60 Hz, il pannello reale mantiene **zero render, zero costruzioni artwork e zero rasterizzazioni durante il drag**, con readiness solo dopo il rilascio. Nel run completo normale mediana evento→binding circa 2,5–3,3 ms e p95 circa 3,5–3,8 ms, senza promessa di frame rate o stima del consumo dell’app basata sull’RSS del processo di test.

Working tree tracciato pulito dopo il commit documentale finale; restano esclusivamente i due documenti preesistenti non tracciati, con hash originali. Branch locale codex/signum-0.4-ux-refinement-b13. Nessuna modifica a main, PR #3, altre build o altri repository. Nessun push/merge/tag/release/Actions, hardware/PIN reale o documento personale. Fermo prima del collaudo hardware. I limiti sulla disponibilità della chiave privata, hotplug, fiducia/revoca e runtime 13/14 restano quelli esplicitati sopra.
