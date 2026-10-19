# Signum 0.4 — Orientamento PAdES, build 12

## Baseline e analisi

Branch dedicato codex/signum-0.4-pades-orientation-b12 dall’HEAD effettivo B11 **217611a**, successivo alla sorgente dei bundle **3a2e1dd**. Stato iniziale tracciato pulito, due file non tracciati preesistenti preservati. Worktree censiti senza accesso agli altri checkout. Ref protetti, manifest/eseguibili B11 e file precedenti registrati in .build/04stabilization-b12/evidence/baseline.json. Letti rapporti B11/stabilizzazione/appearance/diagnosi/progresso prima dell’intervento.

**Problema dimostrato dalla trasformazione B11 e confermato dal collaudo riferito dall’utente:** l’overlay mappa correttamente il rettangolo grezzo, ma il contenuto AP non compensa /Rotate. Su pagina 90 l’asse di lettura del timbro diventa verticale. MediaBox landscape e rotazione interna sono indipendenti: nessuna euristica basata sulle proporzioni.

Percorso analizzato: configurazione per documento → geometria CGPDFPage dello snapshot → renderer CoreGraphics/CoreText → RenderedPAdESAppearance → mapping PDFKit/overlay → approvalIdentity/preflight → SigningJob → stdin helper → PoDoFo. Il helper esistente importa la pagina artwork solo se Rotate=0 e dimensioni MediaBox uguali al Rect raw; FillFromPage crea AP/N prima di ByteRange/CMS. Non serve modificarlo, né ruotare la tavola.

## Semantica e architettura

PAdESAppearanceOrientation: Automatico (default), 0,90,180,270. Angoli manuali **orari rispetto alla normale direzione di lettura del visualizzatore**. Automatico e 0 hanno lo stesso risultato visivo, ma sono scelte distinte nel consenso. Compensazione pura: rotazione artwork antioraria nei byte PDF = (rotazione pagina − angolo manuale orario + 360) mod 360. Quattro trasformazioni esatte, nessuna trigonometria/zoom o inferenza dall’orientamento fisico.

Dimensioni del contenuto espresse prima della rotazione; rectangle è sempre l’ingombro assiale raw approvato /Rect. A 90/270 si scambiano gli assi; il cambio conserva il centro ove possibile e trasla soltanto per rientrare nel CropBox∩MediaBox, senza deformazione o ridimensionamento silenzioso. Se l’ingombro non entra, errore esplicito. Stepper e Option-resize rispettano limiti sulle dimensioni del contenuto.

Il renderer esistente genera una sola versione upright vettoriale, conservata immutabile. Orientare usa la stessa pagina PDF come contenuto, con trasformazione esatta dentro un nuovo PDF a origine zero e Rotate=0; niente secondo layout testo, lettura immagine o rasterizzazione della tavola. Rotazioni successive ripartono sempre dall’upright, senza accumulo di wrapper. L’overlay e PoDoFo ricevono gli stessi byte finali già orientati. Nessuna correzione indipendente nell’overlay o nel helper.

API precedenti conservate: chiamanti che passano soltanto CropBox continuano con rotazione pagina implicita 0 e metadata legacy nil; la GUI B12 passa sempre la rotazione effettiva. Il job verifica, per la nuova API, che la rotazione sia quella della pagina dello snapshot e che l’ingombro sia valido prima dell’approvazione/autenticazione.

Cambio orientamento invalida subito readiness, genera nuova approvalIdentity (scelta e angolo risolto inclusi), cancella callback obsolete tramite generation. Configurazione, rotazione pagina, AP e geometria sono valori immutabili nel job. Il drag condivide byte/hash/artworkID, non ricrea PDF o cache; orientare conserva contentArtworkID e riusa l’artwork upright nel worker asincrono.

## Prove mirate e prestazioni

Cinque test Core/grafici: risolutore, trasformazioni esatte, geometria/centro/clamp/limiti, riuso upright e identità del consenso; viewport nativo A4/A3/A1/A0, 4 rotazioni pagina × 5 orientamenti × zoom 25/100/200. Verificati pixel e direzione dell’indicatore asimmetrico nel vero contenuto disegnato della NSView, non soltanto il rettangolo. Trenta spostamenti per combinazione mantengono gli stessi contatori artwork/raster.

Output: **20 vere firme sintetiche** (4×5). /AP/N, /Rect e /BBox verificati; /Matrix identità quando esplicita, altrimenti default PDF identità. /Rotate originale conservato, ByteRange completo e CMS verificato dalla verifica unificata e **indipendentemente da /usr/bin/openssl cms -verify -binary -noverify** (sola integrità, nessuna fiducia CA). Poppler confronta i centroidi R/G/B con un riferimento upright senza /Rotate, ruotato soltanto dell’angolo manuale richiesto: tolleranza 2 pixel. Segni dell’asse R→G: destra, basso, sinistra, alto per 0/90/180/270; Automatico orizzontale su tutte le pagine. Il testo READ 123 e i quattro colori asimmetrici impediscono di mascherare errori di orientamento con un timbro simmetrico.

Quattro test workflow: due PAdES con orientamenti distinti più CAdES realmente firmati nello stesso batch; revoca Automatico→0 anche con byte identici, job congelati, orientamento pagina incompatibile rifiutato prima della firma, override AP del helper rifiutato; rendering superato e chiusura; ripristino per documento dopo teardown/remount del pannello. I test formato B11 coprono inoltre cambio CAdES/PAdES e generazioni revocate.

Prestazioni Debug isolate, 120 movimenti per orientamento su tavola 10.000 vettori, zoom fit della finestra 800×650:
| Misura | Testo | PNG 1024² | PNG 2800² |
|---|---:|---:|---:|
| Generazione iniziale, ms | 2,13 | 13,19 | 96,87 |
| Cambio orientamento da upright, ms | 0,05–0,85 | 0,06–5,18 | 0,22–35,28 |
| Aggiornamento overlay/cache, ms | circa 0,5 | 2,55–3,18 | 15,28–16,65 |
| Drag p95, ms | circa 0,06 | 0,047–0,061 | 0,050–0,077 |
| Resize completo orientato, ms | 1,46 | 16,38 | 108,12 |

Zero rigenerazioni PDF/raster e hash payload durante il drag; invariati artworkID/sha256. Cache misurata in questo fit: 13020 byte. Resta il limite B11 di 4096 per asse, massimo teorico 64 MiB per cache RGBA; upright e PDF finale sono al più 8 MiB ciascuno (Data condivise nei job, nessuna copia per movimento). Orientare/rigenerare avviene nel worker asincrono. La prima pittura/cache rimane sincrona sul MainActor, circa 16 ms nel caso grande; non sono stati misurati fps, energia o memoria isolata dell’intero processo. I costi PDFKit della tavola rimangono distinti.

Limite del collaudo interattivo: il collegamento desktop ha restituito due volte “Sky Computer Use native pipe closed before response”. Nessuna interazione manuale del menu dichiarata. Un primo test presumeva erroneamente che il Picker SwiftUI fosse un NSPopUpButton; un secondo condivideva il coordinatore fra due pannelli artificialmente rimontati. Corrette queste assunzioni del test, preservando i controlli di readiness/centro/ripristino. Nessuna modifica all’implementazione standard del Picker per adattarla al test. I test nativi di pixel/direzione passano; menu interattivo, tavola reale B12 e runtime macOS 13/14 restano da collaudare. La tavola personale non è stata firmata né riesaminata interattivamente in B12.

Prototipo locale facoltativo in Tools/OrientationProbe/ (solo anteprima, nessun provider/discovery/autenticazione/firma). --smoke usa esclusivamente una fixture sintetica e termina con cleanup; l’argomento PDF facoltativo è locale e in lettura. Le prove automatiche non aprono il documento reale.


Aggiunta anche una regressione dedicata alla navigazione fra pagine miste: da 0°/A0 a 270° con MediaBox nonzero e UserUnit 10. L’artwork della vecchia pagina scompare, il nuovo conserva il contenuto upright e cambia identità approvata, si limita al crop e segue lo scroll effettivo a zoom 200%. Resize al bordo non può uscire dal CropBox; lo stesso resize all’interno cambia correttamente le dimensioni logiche. La suite finale include questo caso aggiuntivo.

## Verifiche finali prima del packaging

Sorgente applicativa verificata: **356/356 Swift**, **40/40 PKCS#11**, **63/63 PAdES Debug e 63/63 Release**, **10/10 packaging unit**, **22/22 ASAN e 22/22 TSAN** mirati. Zero skip/fallimenti finali, nessuna segnalazione dei sanitizer. La prima suite completa era 355/355; dopo l’aggiunta della regressione pagine miste rieseguita interamente con 356 test, oltre ai due sanitizer.

I test includono CAdES/PAdES singoli e batch, formati dinamici/misti, Secure Batch PIN sintetico, discovery simulata, SG-01/14/02/03/04/05/06, timeout/cancel, snapshot e no-overwrite. Nessuna modifica alle primitive, ai protocolli credenziali, al lifecycle PKCS#11 o al helper PoDoFo. Il probe --smoke ha avviato l’anteprima sintetica, pubblicato la readiness e terminato normalmente con cleanup; non sostituisce il collaudo interattivo del menu.

Soltanto dopo queste verifiche la fonte viene avanzata a **0.4.0 / build 12**. Destinazioni nuove: .build/04stabilization-b12/final-debug/Signum.app e final-release/Signum.app. La consegna dei bundle sarà confermata dopo audit, codesign strict, rilocazione e integrazioni con helper effettivamente inclusi.

Log: .build/04stabilization-b12/evidence/final-complete-swift.log, final-complete-asan.log, final-complete-tsan.log, final-pkcs11.log, final-pades-debug.log, final-pades-release.log, final-packaging-tests.log. I run preliminari sono conservati separatamente e non sostituiscono questi esiti.
