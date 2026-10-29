# Signum 0.7 — Final Signing Polish · Build 8

Base Build 7 e4a9434, branch feature/signum-0.7-ui-redesign, PR #8.

## App predefinita

Impostazioni → Generali → Imposta Signum come app predefinita… apre un foglio
nativo. Mostra l’app attuale per P7M, P7S, ASiC-S, ASiC-E, PDF e XML. PDF/XML
inizialmente deselezionati; i quattro tipi firmati preselezionati solo se questa
build non risulta già predefinita. Nessuna scrittura all’apertura o con Annulla.
Dopo un’applicazione, Chiudi chiude il riepilogo senza promettere un ripristino.

Il servizio usa NSWorkspace.setDefaultApplication(at:toOpen:completion:) per i
soli tipi scelti, uno per volta; macOS gestisce le eventuali autorizzazioni.
Si verifica che il processo appartenga a un bundle Signum .app con Info.plist,
eseguibile e tipi documentali. Una rimozione del bundle prima di Applica impedisce
ogni richiesta. Nessun duti, shell, API di scrittura Launch Services o privilegio.

UTType preferito dal sistema per l’estensione, con fallback alle dichiarazioni
importate della Build 7: evita di impostare un tipo privato diverso da quello che
Finder usa già su un Mac con altri gestori. Errori e rifiuti sono per formato,
senza interrompere gli altri; dopo ogni completamento viene riletto il gestore
reale. Una callback senza errore ma senza cambio effettivo non è un successo.
Le selezioni riuscite vengono rimosse; gli errori rimangono selezionati per una
ripetizione esplicita. Non vengono modificati file o icone sui documenti.

L’accesso al sistema è iniettato: i test di applicazione usano soltanto un fake.
Il collaudo GUI apre e annulla il pannello reale, senza Applica. La conferma di
sistema e il cambio effettivo devono essere collaudati volontariamente dall’utente.

## Sidebar e firmatario

Prima il titolo automatico di NavigationSplitView veniva ricollocato tra colonne
al variare della sidebar. Ora un solo ToolbarItem principal mantiene l’identità
del titolo e la toolbar nativa ne gestisce il layout. Il titolo automatico viene
rimosso da macOS 15; su 13–14 si nasconde soltanto il titolo NSWindow visibile,
senza cambiarne il valore. Nessun offset, animazione sostitutiva o disattivazione
globale delle animazioni. Da macOS 26 il titolo non riceve uno sfondo Glass
proprio. Sidebar, pulsante nativo, background extension e materiali restano nativi.

Motto nella safe area inferiore della sidebar, SF 11 pt, colore secondario,
senza superficie decorativa. Scompare insieme alla sidebar; può andare su due
righe alla larghezza normale per conservare dimensione e leggibilità.

Il Picker mostra nome del titolare e dispositivo dai metadati token/model/reader
della singola route. DigitalDNA, CNS, smart card o USB sono indicati solo quando
i metadati lo esplicitano; altrimenti modello osservato o Dispositivo PKCS#11.
Il certificato e il nome del middleware non determinano il tipo di hardware.
Tooltip completo con dispositivo, provider e slot; tag e binding restano route.id,
senza cambiare selezione, approvazione o controlli di idoneità.

## Collaudo manuale

- [ ] Installare Build 8 accanto alla Beta 0.6; controllare il bundle ID V07.B8.
- [ ] Generali: verificare le sei app attuali, PDF/XML deselezionati; cambiare una
      spunta e Annulla, poi riaprire e verificare che le associazioni non cambino.
- [ ] Volontariamente scegliere un solo formato firmato, Applica; accettare/rifiutare
      la conferma macOS e verificare stato reale, messaggio per formato e Apri con.
- [ ] Ripetere con errore/annullamento e selezione multipla. PDF/XML soltanto dopo
      una scelta esplicita; ripristinare poi il gestore desiderato tramite macOS.
- [ ] Aprire/chiudere ripetutamente la sidebar, anche in Dispositivi e Impostazioni;
      trascinare continuamente finestra e divisori, osservando titolo e motto.
- [ ] Light/Dark, Reduce Motion/Transparency, macOS 13–15/26: fluidità e contrasto.
- [ ] Stesso certificato su due route: nome/dispositivo/tooltip corretti e selezione
      effettiva conservata. Metadati assenti: nessuna classificazione inventata.
- [ ] Firma singola/multipla: consenso, PIN, Invio, Annulla, pendenti/interruzione,
      output conservati, esiti incerti senza ripetizione automatica e sblocco.
- [ ] Verifica P7M/P7S/PDF/XML/ASiC e Finder: restano applicabili i limiti documentati
      nella Build 7, compresa la resa dell’icona documentale sul Mac del collaudo.

App e DMG locali arm64, minimo macOS 13, firma ad-hoc non notarizzata.
Risultati effettivi, screenshot e limiti in Report-consegna.md e TestSummary.json
nella cartella di consegna. Le schermate dei certificati con fixture sono distinte
esplicitamente dagli screenshot del bundle reale senza certificati collegati.

SignumCore, Trust, Tools e Package.swift invariati dalla Build 7. HalleyMac intatto.
Nessuna GitHub Action, merge, tag o release. STOP alla consegna per collaudo manuale.

API Apple: https://developer.apple.com/documentation/appkit/nsworkspace/setdefaultapplication(at:toopen:completion:)
