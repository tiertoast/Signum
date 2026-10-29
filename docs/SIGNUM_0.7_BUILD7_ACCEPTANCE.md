# Signum 0.7 — Native Experience · Build 7

Base Build 6 dc92298; branch feature/signum-0.7-ui-redesign, PR #8.

Picker con colori neutri di sistema: rimosso il tint ereditato dalla finestra;
Burgundy rimane su azioni primarie e icone della sidebar (variante leggibile Dark).
Elenco documenti con rientri orizzontali; percorso completo invariato.
Informazioni di formato e autenticazione direttamente sotto il Picker; rimosso
il popover Informazioni sulla firma. Durante il lavoro, comandi secondari
Annulla documenti in attesa/Interrompi firma corrente affiancati, progresso
indeterminato e pulsante Firma in corso… disabilitato. I due comandi conservano
le operazioni distinte del motore. Esiti incerti e sblocco automatico invariati.

## Finder

La scena SwiftUI usa una finestra unica e onOpenURL per evitare che gli eventi
finiscano in workspace nascosti. SystemDocuments riceve e accoda gli URL locali prima dell’esistenza della finestra,
limita ogni acquisizione a 32 e conserva gli eventi successivi. Il normale workspace
Firma acquisisce soltanto i file: nessun consenso o PIN viene fornito dal servizio.
Verifica usa VerificationWorkspace e SignumVerificationService esistenti, con il
catalogo Trusted Lists originario. Gli eventi attendono lo sblocco della firma.
P7S richiede un originale scelto esplicitamente per ciascuna firma; annullare il
pannello non avvia una verifica detached. Accessi security-scoped bilanciati per
la durata delle acquisizioni/verifiche; nessun nuovo motore o componente privilegiato.

Tipi importati P7M/P7S/ASiC-S/ASiC-E, ruolo Viewer e rank Alternate. PDF e XML
sono selezionabili con Apri con; non ricevono icone Signum. Non viene chiamata
alcuna API per modificare il gestore predefinito. Doppio clic rimane dipendente
dalla scelta dell’utente: se il file è associato ad altra app non si forza Signum.

Servizi nativi Firma con Signum e Verifica con Signum, disponibili nel sottomenu
Servizi ove macOS li abilita per la selezione. Non si promette una voce al primo
livello né una Quick Action/estensione separata. Per il riconoscimento dei Servizi
è prevista installazione in Applications (anche ~/Applications). Le preferenze
Servizi dell’utente possono impedirne la comparsa; non vengono forzate.

Icona documentale: Resources/DocumentIcons/SignedDocument.svg, foglio, piega,
penna e tratto Burgundy; ICNS con rappresentazioni 16/32 e risoluzioni Retina
fino a 1024. Identità coordinata condivisa dai contenitori firmati. Icona principale
Refined invariata. Il Finder può conservare icone/associazioni precedenti,
specialmente con più preview installate e gestori già scelti.

## Consegna e collaudo

Preview 0.7.0 build 7 arm64, ID V07.B7 distinto, minimo macOS 13 e SDK corrente.
Debug/Release locali, test mirati e audit dei bundle: esiti effettivi e limiti in
TestSummary.json e Report-consegna.md nella cartella di consegna. Screenshot
originali, fixture esplicitamente indicate. Il testo allegato non conteneva gli
screenshot di riferimento citati: icona costruita dal concept scritto.

Checklist:
- [ ] Avviare l’app installata; controllare Picker chiusi e aperti, Light/Dark.
- [ ] Documenti e percorsi lunghi, inspector stretto e largo, PDF e menu neutrali.
- [ ] Firma sintetica/reale: consenso e PIN obbligatori; comandi distinti in corso,
      output già completati conservati, esito incerto senza ripetizione automatica.
- [ ] Apri con Signum: P7M ad app chiusa/aperta, selezione multipla, PDF/XML/ASiC.
- [ ] P7S senza originale: richiesta esplicita, annullamento e originale errato.
- [ ] Finder → Servizi: Firma con Signum e Verifica con Signum sulla selezione.
      Verificare anche lancio a freddo e preferenze Servizi disabilitate.
- [ ] Icona P7M a 16/32 e vista icone, senza cambiare i gestori PDF/XML.
- [ ] macOS 13–15/26, Reduce Transparency/Motion e middleware/PIN reali.

Motore SignumCore, librerie Trust e Tools invariati; HalleyMac invariato.
Nessuna Action, merge, tag o release pubblica. STOP alla Build 7.

Riferimento Apple: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/Articles/properties.html
