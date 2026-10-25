# Signum 0.7 — Build 9 Verification

Base: `71e153c` (Build 8 DSS). Versione 0.7.0, numero interno 10, bundle ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B10`. Installazione e preferenze separate dalle preview precedenti.

## Presentazione

Elenco compatto dei documenti, selezione individuale e menu delle firme/controfirme. Riepilogo con identità dal certificato, prestatore dalla Trusted List autenticata quando il percorso è verificato, controlli indipendenti di integrità/revoca/qualificazione e date distinte. L'emittente del certificato è esplicitamente distinto dal prestatore riconosciuto. Nessuna spunta verde per risultati indeterminati. QES corrente è indicata «alla data di verifica»; una marca attendibile dimostra un limite di esistenza, non l'istante esatto di firma.

Dettagli richiudibili con tutte le informazioni del rapporto, OID/policy, QCStatements, OCSP/CRL, TSA, catena, revisioni e limitazioni. PDF/TXT mantengono tutti i contenuti precedenti e aggiungono informazioni certificatePolicies e QCStatements. Le date del riepilogo sono nel fuso locale; i rapporti conservano le date esplicitamente UTC per compatibilità e precisione.

## Sidebar e titlebar

Il contenitore della finestra usa NSSplitViewController, con item `.sidebar` e hosting controller SwiftUI persistenti per sidebar e contenuto. La toolbar è un solo NSToolbar per finestra con NSTrackingSeparatorToolbarItem collegato al divisore. Il titolo è quello nativo di NSWindow, i comandi sono a destra, separati da uno spazio flessibile AppKit. La chiusura usa `toggleSidebar` di NSSplitViewController e `.preferResizingSiblingsWithFixedSplitView`: nessun offset, animazione simulata o disabilitazione globale delle animazioni.

Gli hosting controller non richiedono modifiche alla dimensione preferita della finestra a ogni layout. Toolbar, item e pannelli non vengono ricreati durante apertura/chiusura. Test locali verificano identità degli oggetti, assenza di comandi duplicati, finestra stabile e blocco della sidebar durante una sessione approvata. Sidebar estesa sotto la titlebar, larghezza iniziale 200 pt; inspector Firma 300–360 pt con materiale regolare di sistema. Il sistema fornisce materiali, Light/Dark e impostazioni di accessibilità; nessuna imitazione Glass.

Riferimenti Apple:
- https://developer.apple.com/documentation/appkit/nssplitviewcontroller
- https://developer.apple.com/documentation/appkit/nstrackingseparatortoolbaritem

## Dichiarazione AgID: campo informativo, non verdetto

Un lettore DER limitato alla presentazione estrae CertificatePolicies, CPS e userNotice/explicitText. Nessuna modifica al validatore X.509 o alla policy di fiducia. Il testo «Raccomandazioni AgID: dichiarate dal certificatore» richiede il policy OID 1.3.76.16.6 e la dichiarazione italiana esplicita riconoscibile sulle raccomandazioni della Determinazione AgID 121/2019. OID isolato, testi negati, riferimenti CPS e formulazioni non interpretabili non bastano. Testo originale e provenienza OID sono riportati nei dettagli e nei rapporti. Un testo diverso resta consultabile ma non produce la dichiarazione sintetica.

La rettifica 147/2019 corregge nell'allegato il riferimento OID da 1.3.76.16.5 a 1.3.76.16.6. La Determinazione 189/2017 modifica la Deliberazione 45/2009: non viene utilizzata per inferire la dichiarazione sulle raccomandazioni 121/2019. Nessun verdetto «Conforme AgID» o giudizio globale di validità legale.

Fonti AgID:
- https://trasparenza.agid.gov.it/page/9/details/1374/determinazione-n-121-del-17-maggio-2019-linee-guida-contenenti-le-regole-tecniche-e-raccomandazioni-afferenti-la-generazione-di-certificati-elettronici-qualificati-firme-e-sigilli-elettronici-qualificati-e-validazioni-temporali-elettroniche-qualificate.html
- https://www.agid.gov.it/sites/default/files/repository_files/147_-_dt_dg_n._147_-_4_giu_2019_-_rettificadeterminazione121-2019_ter.pdf
- https://trasparenza.agid.gov.it/page/103/details/768/determinazione-n-1892017-del-23-giugno-2017-modifiche-alla-deliberazione-n-45-del-21-maggio-2009.html

## Checklist manuale

- Avviare Build 9 Verification e controllare che le altre versioni restino installate separatamente.
- Verifica vuota: contenuto centrato, apertura multipla e drag & drop.
- P7M di riferimento: nome/CF, InfoCamere da TL autenticata, integrità verificata, revoca non revocato, QES alla data corrente, marca assente; signingTime dichiarato e ora locale corretti.
- Aprire Dettagli: testo originale AgID 121/2019, riferimento 147/2019, OID, catena, date, revoca, QCStatements e limiti. Esportare PDF e TXT completi.
- Più documenti e firme/controfirme: cambiare selezione e verificare che gli esiti rimangano associati alla firma corretta.
- P7S con originale: verificare la coppia; provare originale errato. PAdES e ASiC supportati: controllare i rispettivi limiti.
- Certificato revocato, firma alterata, evidenze mancanti, prestatore sconosciuto: nessuna spunta verde sul controllo non dimostrato.
- Marca verificata: limite temporale esplicito; marca assente/invalida/non determinabile: etichetta distinta e nessuna data qualificata inventata.
- Anteprima in sola lettura ed estrazione dell'originale: nessuna sovrascrittura; estrazione non consentita con integrità non verificata.
- Sidebar: ripetere apertura/chiusura a 980, 1100 e 1320 pt, ridimensionare continuamente e alternare Firma, Verifica e Dispositivi. Titolo sempre a sinistra dopo la sidebar; nessun salto al centro o duplicazione.
- Light/Dark e Reduce Transparency: materiali nativi e testo leggibile. Ripristinare le preferenze di sistema iniziali.
- Firma: selezione, approvazione, PIN, annullamento e firma multipla senza regressioni. Le firme reali restano soggette al consenso dell'utente.

Motore DSS-corrected, policy di fiducia e motore di firma invariati. Nessun intervento su OpenSC o HalleyMac. Nessuna GitHub Action, merge, tag o release pubblica. STOP alla consegna per collaudo manuale.
