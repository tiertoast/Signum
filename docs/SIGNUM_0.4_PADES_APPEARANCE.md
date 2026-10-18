# Signum 0.4-B — Appearance PAdES

Baseline 18 ottobre 2026: HEAD build 6 `72060b7`, codice `37d21e8`.
Branch `codex/signum-0.4-pades-verification`, main `be84a1e` e build 6 preservati;
review non tracciata preservata. PR #3 soltanto riferimento, nessuna modifica.
Colloquio hardware positivo su CAdES/PIN temporaneo/InfoCamere riferito
dall'utente, non trasferito per presunzione a questo sviluppo.

## Design B prima del codice

Il renderer testuale PoDoFo e l'overlay freeText PDFKit attuali sono differenti.
La nuova appearance usa un unico PDF autonomo prodotto da CoreGraphics/CoreText:
gli stessi byte vengono disegnati nella preview e incorporati da PoDoFo in /AP
prima della firma. Nessun salvataggio dello snapshot PDFKit. Il percorso testuale
legacy resta compatibile, non è il renderer della nuova GUI.

Configurazione per documento, geometria PDF non ruotata, nome dal DER selezionato,
data locale congelata (non timestamp qualificato), testo opzionale, PNG/JPEG
validati e allineamento. Risorse incorporate, nessun riferimento esterno.
La configurazione e il PDF appearance vengono congelati al consenso; dopo il
consenso non viene riletto il percorso dell'immagine. Coordinate raw esplicite
anche nel widget PoDoFo per evitare una seconda rotazione.

C non iniziata: si procede alla verifica unificata soltanto dopo test/build e
commit B. Nessun nuovo hardware/PIN reale, rete documentale o nuova primitiva.

## Implementazione B

`SignumCore/PAdESAppearance.swift` contiene modello, validazione immagine e renderer
CoreGraphics/CoreText. Un PDF autonomo, massimo 8 MiB, contiene font e immagini:
PDFKit disegna quei byte; PoDoFo importa la stessa pagina in un Form XObject e
assegna `/AP/N` al widget con coordinate raw prima di `SignDocument`. Nessuna
modifica dello snapshot e nessuna sovrapposizione aggiunta dopo la firma.

Il nome deriva dal DER selezionato, mai dalla label. Data locale opzionale e
congelata, testo personalizzato distinto dall'identità, allineamento, carattere
7–18 pt, rettangolo 80–800 × 40–500 pt interamente nel CropBox∩MediaBox. Immagine
opzionale PNG/JPEG, fino a 5 MiB, lato 4096 px e 8 milioni di pixel; decodifica
RGB/grigio/indexed e alpha. Profili ICC compressi/APP2 e metadati PNG compressi
sono rifiutati prima della decodifica: esportare senza tali metadati. Non è un
normalizzatore universale dei profili colore.

La GUI offre pagina, clic/drag, Option+drag per dimensionare, controlli espliciti
di dimensione e firma invisibile. Preferenza semplice per il nome; niente sistema
di template. Coordinate PDFKit convertite nelle coordinate raw del documento,
origine nonzero e rotazione incluse. Ogni modifica invalida il consenso corrente;
un actor serializza il rendering fuori dal main actor e scarta risultati superati.
L'immagine scelta è letta una volta in modo bounded/no-follow: la sua selezione
usa ancora una breve decodifica sincrona, entro i limiti indicati.

`SigningReviewContext` comprende impronta appearance, pagina, posizione e DER;
al consenso viene copiata una mappa immutabile per documento. Il motore controlla
nuovamente il fingerprint del certificato. Il percorso originale dell'immagine
non viene riletto. Il batch PAdES resta sequenziale e richiede il PIN per documento;
Secure Batch PIN rimane soltanto CAdES.

Il vecchio percorso testuale dell'helper e il relativo protocollo restano
compatibili. Il nuovo payload passa attraverso stdin privato con lunghezza
esplicita e limite 8 MiB; nessun nome o dato grafico nei log. Il limite precedente
di 512 byte resta predefinito per gli altri chiamanti dell'helper supervisionato.
SG-03, lease PKCS#11, snapshot, atomicità e no-overwrite non sono sostituiti.

## Prove dedicate realmente eseguite

9 nuovi metodi XCTest, tutti passati senza skip: testo/nome/data/Unicode,
invisibile, PNG/JPEG/alpha, input malformato e sovradimensionato (byte e pixel),
min/max e fuori pagina, identità del consenso, rotazioni/zoom, PDF multipagina,
prima/ultima pagina, CropBox≠MediaBox e origine nonzero. Vere firme software con
provider sintetico, risorse `/AP`/font/immagine e coordinate lette dal PDF finale,
SG-03 prima della pubblicazione, sorgente invariato, firme incrementali e batch
di tre documenti con appearance differenti e tre autenticazioni. Cambio DER
rifiutato prima dell'operazione privata, immagine sostituita non riaperta,
crash/timeout senza retry o output finale. I test preesistenti coprono anche
cancel, collisioni/no-overwrite e cleanup.

Verifica grafica: preview PDFKit confrontata con un riferimento appiattito che
contiene esattamente la stessa appearance; confronto indipendente tramite
Poppler `pdftoppm` a 144 dpi del vero PDF firmato contro quel riferimento:
rotazioni 0/90/180/270, differenza media per canale **0.00000** in tutti i casi.
In diagnostica PDFKit su questo host ometteva alcune appearance native nelle
thumbnail 180/270: la verifica indipendente dimostra la presenza nel PDF; la
preview personalizzata gestisce correttamente la trasformazione. Non si deduce
compatibilità universale di ogni visualizzatore da queste fixture.

Evidenze locali in `.build/reliability/evidence/04b-*`; fixture sintetiche e raster
in `.build/04b-rendered`. Nessun documento/PIN reale. Nessun nuovo collaudo
hardware o GUI interattiva completa, sleep e runtime macOS 13/14. Target dichiarato
13.0; compatibilità runtime da collaudare. Restano da verificare manualmente
scroll/zoom e trascinamento su PDF reali eterogenei e altri visualizzatori.

## Checkpoint B del 18 ottobre 2026

Swift **302/302**, zero skip/fallimenti; PKCS#11 **40/40**; PAdES Debug e
Release **63/63** ciascuna; test packaging **10/10**. Build SignumApp Debug e
Release riuscite. ASAN e TSAN Swift mirati **30/30** ciascuno; native ASAN
**63/63** e integrazione appearance con entrambi i processi strumentati
**9/9** (leak detection disabilitata; librerie terze non strumentate).
I sanitizer non costituiscono prova di pulizia forense della memoria.
Picco RSS del processo Swift nella suite completa circa **930 MiB**; include
le fixture da 100 MiB e non rappresenta il solo renderer o l'helper separato.
La fonte Info.plist avanza a **0.4.0/build 7**, mantenendo il minimo 13.0.
Commit design `3de3d31`; il successivo commit di implementazione è il checkpoint B.


Checkpoint codice **`9f7684b`**. Bundle build 7 Debug e Release costruiti dopo
quel commit, con `sourceTrackedDirty=false`, firma ad hoc verificata, hash,
Mach-O minimo 13.0, dipendenze incorporate, smoke e 63 casi PAdES anche nei
bundle rilocati. Percorsi `.build/04b-bundles/checkpoint-debug/Signum.app` e
`.build/04b-bundles/checkpoint-release/Signum.app`. Log `04b-package-{debug,release}`.
Questi bundle sono checkpoint B; la candidata finale includerà C se verificata.
