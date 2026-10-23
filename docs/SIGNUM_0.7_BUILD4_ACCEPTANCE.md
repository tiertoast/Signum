# Signum 0.7 — UX Cleanup & Functional Fixes · Build 4

23 ottobre 2026 · `feature/signum-0.7-ui-redesign` · PR #8.
Base: Build 3 (`4a056e2`). STOP alla consegna della Build 4.

## Interfaccia

Il nuovo + resta accanto alle schede, fuori dallo scorrimento orizzontale, quando
sono presenti documenti. Usa la stessa acquisizione della toolbar e del drop;
non sostituisce la selezione o le configurazioni dei documenti già caricati.
Durante preparazione o sessione approvata rispetta i blocchi esistenti. Lo stato
vuoto mantiene un solo invito centrale oltre al comando della toolbar.

Inspector: un selettore del firmatario, uno del formato corrente e uno della
destinazione. Eliminati il secondo formato, la seconda destinazione, il nome del
documento ripetuto e l'emittente ridondante. Opzioni avanzate contiene il formato
per i nuovi documenti soltanto quando c'è una selezione corrente, e Dettagli per
le spiegazioni di formato/autenticazione e l'eventuale percorso di destinazione.
La firma CMS da controfirmare rimane accanto al formato quando necessaria; i
contenuti ASiC sono consultabili nei dettagli del documento. Nessuna opzione di
firma è stata rimossa. Stato e Firma rimangono nella barra fissa inferiore.

Aggiorna dispositivi è l'unico comando generale di ricerca. Rimossi Ripeti ricerca
dall'inspector e i duplicati nelle viste di configurazione. Carica manuale rimane
l'azione esplicita per autorizzare un modulo. L'inspector mostra un messaggio breve
e il collegamento Dispositivi; diagnostica e cause della ricerca incompleta sono
consolidate in Dispositivi → Dettagli.

La ricerca pubblica ha ora una propria operazione di annullamento: non imposta
il blocco dei lavori sui documenti e non impedisce navigazione o aggiunte.
Azzera comunque credenziali/PIN e review precedenti; fino alla nuova selezione e
review valida non è possibile approvare. Restano bloccati refresh concorrenti,
risposte obsolete e refresh durante firma/sessione approvata.

Per Impostazioni è stata scelta l'alternativa autorizzata: Indietro nativo nella
toolbar, con ritorno alla sezione di provenienza anche dopo ⌘, ripetuti. Le
preferenze rimangono legate alla finestra e ai suoi blocchi operativi. Schede
Generali, Firma grafica, Trusted Lists e Dispositivi separano gli usi comuni dai
dettagli. Non si introduce una seconda finestra con uno stato di firma separato.

Layout a tre colonne della Build 3, Burgundy #64313E, font/controlli/toolbar e
materiali di sistema preservati; nessun Glass simulato. Requisito minimo macOS 13.
Icona Refined di Icon Composer e fallback precedenti preservati.

## Selezione automatica e ricerca parziale

Una nuova selezione automatica richiede ancora copertura completa della ricerca,
un solo certificato idoneo e una sola route osservata utilizzabile. Più DER o più
route effettive restano una scelta esplicita. Stesso DER attraverso middleware,
slot o contesti differenti non dimostra identità fisica del dispositivo.

Corretto il caso degli alias: l'ID della route ora usa percorso canonico, identità
completa del file, slot/attributi del token, CKA_ID e DER. Non include più il nome
visualizzato del provider o la grafia dell'alias, che potevano creare un secondo
ID per lo stesso binding o invalidarlo al riordino della ricerca. File diversi,
modifiche all'identità del modulo, slot diversi e certificati diversi restano
separati. Una riga alias vale come copertura solo se lo stesso file ispezionato
ha una lettura pubblica riuscita nel medesimo risultato.

La selezione precedente, automatica o manuale, viene conservata soltanto se lo
stesso binding viene nuovamente osservato e risulta ancora idoneo. La sua origine
non viene trasformata artificialmente in manuale dal refresh. Se scompare il token,
cambia il contesto o il certificato non è più idoneo, il vecchio binding non viene
ripristinato. Discovery ID e review nuove impediscono riuso del consenso precedente.

Il messaggio «Ricerca non completa: l'unicità del certificato non è determinabile»
non era sempre un falso errore. Nella scansione pubblica locale registrata per
questa build: Bit4id segnalava uno slot non disponibile e OpenSC un token senza
certificati pubblici leggibili. Quella lettura è realmente incompleta; non prova
l'assenza di altri certificati e non giustifica una nuova selezione automatica.
Sono osservazioni di quella scansione, non una diagnosi generale dei driver.
Le cause ora sono consultabili in Dettagli, senza richiedere un PIN per la ricerca.

Modificati solo DeviceSelection/DeviceCertificate nella selezione pubblica e la
presentazione. Invariati controlli di sicurezza del caricamento, binding PKCS#11,
idoneità X.509, rilettura del certificato prima del consenso, controllo della
chiave dopo login e motore crittografico 0.6. Nessuna modifica a HalleyMac.

## Test locali

- 78 test Swift mirati passati. Dopo le ultime modifiche, 13 test mirati passati:
  9 ripetizioni e 4 nuovi, quindi 82 test distinti. Zero errori e zero skip nelle
  campagne finali. Non ripetuta l'intera regressione crittografica.
- Copertura: certificato unico, più certificati/dispositivi, stesso DER con route
  diverse, alias canonici e loro riordino con worker reale sintetico, alias senza
  lettura verificata, ricerca parziale, token rimosso, modulo cambiato sullo stesso
  inode, refresh successivo e origine della selezione conservata. Il test del
  discovery sintetico verifica l'assenza di login/firma privata nell'audit.
- UI/consenso: aggiunta successiva attraverso il metodo comune, snapshot/formato
  precedente conservati; ritorno Impostazioni da Firma/Verifica/Dispositivi e blocco
  in sessione; layout minimo Light/Dark, PIN con 32 documenti, PDFKit CAdES/PAdES,
  cambio formato, review obsolete rifiutate, rilascio sessione e refresh.
- Firma multipla: tre output verificati con un PIN, esito incerto senza retry e
  teardown non confermato bloccante. Restano i test del rilascio dopo ultimo output.
- 21 test Python packaging/runner passati, inclusa identità Build 4 separata dalle
  build precedenti e conservazione delle identità 0.6.

Debug/Release, 10 contratti sintetici per bundle, firma ad hoc, dipendenze,
rilocazione, avvio GUI, icona e DMG sono registrati nei log e in TestSummary.json
della consegna. BuildManifest.json identifica il commit pulito utilizzato.

## Collaudo visivo e interattivo

Catture native Light/Dark della candidata: stato vuoto, PDF, opzioni avanzate e
Impostazioni. Verificati il nuovo + con un secondo file e PDF ancora selezionato,
⌘, da Firma e Indietro con documenti/opzioni conservati. Ripristinato il tema
originale Chiaro. Nessuna modifica alle preferenze di sicurezza del sistema.

Con host di collaudo separato e vere viste del prodotto: il certificato sintetico
unico deve risultare selezionato automaticamente, senza forzatura manuale della
route. Percorsi UI completati: PDF singolo e tre file CAdES, approvazione → PIN
esclusivamente sintetico → esiti completati → scomparsa PIN e sblocco controlli.
Il nuovo + è stato osservato disabilitato dopo approvazione. Le PNG `fixture`
identificano questo host; non è incluso nell'app consegnata e non prova un token
personale. Nessun PIN personale o firma privata reale.

Il servizio di controllo computer si è disconnesso durante alcuni passaggi a
Verifica e all'anteprima interattiva PAdES (`Sky Computer Use native pipe closed`).
La candidata risultava ancora in esecuzione; questi tentativi non sono conteggiati
come collaudi interattivi superati. I test del componente PAdES passano; rimane il
gate manuale. Non è una certificazione su macOS 13/14 reali o su ogni dispositivo.

## Installazione e checklist manuale

`Signum 0.7 Development Preview — Build 4.app`, 0.7.0/build 4,
`io.github.tiertoast.Signum.DevelopmentPreview.V07.B4`. Copiare dal DMG in
Applicazioni mantenendo il nome completo. Identità/preferenze/cache isolate da
Beta 0.6 e Build 1/2/3. Apple Silicon, firma locale ad hoc, non notarizzata Developer ID.

- [ ] Aggiungere più file con +, toolbar e drop; verificare selezione, formato di
      ciascun file e limite documenti. Nessuna aggiunta dopo approvazione.
- [ ] Opzioni avanzate: un formato corrente e una destinazione; formato dei nuovi
      documenti indipendente, controfirma selezionabile, contenuti ASiC nei dettagli.
- [ ] ⌘, e Indietro da Firma/Verifica/Dispositivi, ritorno corretto senza perdere
      documenti/configurazione; verificare schede preferenze, tastiera e VoiceOver.
- [ ] Refresh: navigazione disponibile durante ricerca; nessun PIN. Certificato
      unico/ricerca completa automatico; più route/distinti certificati manuali;
      ricerca parziale spiegata in Dettagli, senza forzare una selezione.
- [ ] Rimuovere/reinserire token e aggiornare: nessuna credenziale scomparsa resta
      valida, selezione ancora osservata conservata, nessun consenso riutilizzato.
- [ ] PDF CAdES/PAdES Light/Dark, aspetto e conferma di ogni anteprima PAdES; cambio
      formato, cartella comune, formato dei file aggiunti successivamente.
- [ ] Con token reale: consenso, PIN errato/corretto, annullamento, firma singola e
      multipla, sblocco solo dopo teardown, esiti e apertura file/Finder.
- [ ] Errori/collisioni/esiti incerti: dettagli conservati, nessun overwrite o
      retry automatico, presa visione richiesta quando prevista dalla 0.6.
- [ ] Finestra ridotta, sidebar nascosta, inspector scorrevole: Firma/PIN visibili;
      avvio insieme alla Beta 0.6 e collaudo su macOS 13/14 reali.

Nessuna GitHub Action, merge, tag, release pubblica o intervento su HalleyMac.
STOP alla consegna della Build 4.
