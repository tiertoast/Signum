# Signum 0.7 Development Preview — Build 1

Collaudo locale del 23 ottobre 2026, PR #8, branch `feature/signum-0.7-ui-redesign`.
Base UI esaminata: `d238595`; base motore: main `e9b0c1c` (0.6 più icona nativa).

## Cambiamenti e ambito

NavigationSplitView con Firma, Verifica, Dispositivi, Impostazioni; toolbar
contestuale; riepilogo e sezioni richiudibili; accento Burgundy RGB 100/49/62
(`#64313E`). Ripristinato il testo visibile sull'approvazione implicita nel clic
Firma. La toolbar usa lo stesso fallback Firma del contenuto quando la selezione
sidebar è nil. L'iniezione interna per i test permette di aprire le sezioni e
le opzioni senza caricare dispositivi reali; nessun flag produttivo è aggiunto.

Nessuna modifica al motore, ai coordinatori di approvazione/PIN/firma multipla,
alle fixture crittografiche o a HalleyMac. La logica dei blocchi e della gestione
errori resta la 0.6. Non sono stati richiesti né usati PIN reali.

Il packager risolve actool con xcrun e lo esegue direttamente, conservando
l'ambiente del solo strumento. Il DMG conserva il nome distinto della preview
anziché convertirlo in Signum.app, e usa il nome Development Preview nel volume.

## Risultati

- 105 test Swift mirati: 0 errori, 0 skip. AppVersion, consenso automatico,
  selezione certificati, approvazione, secure PIN, interazione, firma multipla,
  autenticazione, annullamento, operazioni, layout workspace, anteprima PAdES,
  cambio formato e overlay. Evidenza `.build/ui07-final-tests.log`.
- 21 test Python di packaging/runner: passati, inclusa compilazione vera del
  sorgente Icon Composer. `.build/ui07-packaging-tests-final.log`.
- Layout nativo di tutte le quattro sezioni con opzioni aperte, Light e Dark,
  a 980×650 dopo l'installazione della toolbar; sidebar presente, nessuna firma
  avviata. PIN raggiungibile a finestra ridotta con 32 documenti; PDFKit e stato
  errore coperti dai test esistenti.
- Debug e Release: bundle completi, firma ad hoc, librerie contenute, macOS
  minimo 13, rilocazione e avvio helper/worker/CLI verificati dal packager.
- 10 contratti sintetici sui bundle per ciascuna configurazione; avvio GUI e
  librerie caricate controllati con ambiente di sistema. Vedere i log di consegna.
- Non è una suite completa del motore né un collaudo su macOS 13/14 reali.

Inizialmente il test di dimensione misurava anche i 32pt installati dalla toolbar
SwiftUI: ora ridimensiona dopo la creazione della toolbar prima di misurare.
Nessun limite di prodotto è stato allentato. Non sono emersi errori SwiftUI di
compilazione. Xcode 27.1 richiede ancora i framework della sua XcodeSystemResources.pkg
estratti localmente: per actool si è usato il Python del runtime locale e
DYLD_FRAMEWORK_PATH solo per gli strumenti. Le build e gli avvii del prodotto
usano l'ambiente controllato del packager, senza questa ricerca di framework.

## Limiti del collaudo visivo

L'accesso interattivo alle app ha fallito due volte con `Sky Computer Use native
pipe closed before response`. Le catture NSHostingView fuori schermo hanno inoltre
omesso livelli compositi: non sono usate come prova di leggibilità o resa finale.
Il test Light/Dark certifica costruzione e dimensioni, non l'accettazione visiva.
Restano da eseguire i punti manuali sotto, inclusi toolbar, click e tastiera,
contrasto Burgundy in Dark, VoiceOver e token reale. La preview viene consegnata
con questi limiti espliciti; non si dichiara completato il gate manuale della PR.

## Installazione isolata

La consegna contiene `Signum 0.7 Development Preview — Build 1.app`, con bundle ID
`io.github.tiertoast.Signum.DevelopmentPreview.V07.B1`, versione 0.7.0, build 1.
Preferenze e cache Trusted Lists usano questa identità; la Beta 0.6 usa V06.B3.
Copiare dal DMG l'app con il suo nome completo in Applicazioni senza rinominarla
Signum.app. È una build arm64 firmata ad hoc, non notarizzata: non equivale a una
release Developer ID. Nessuna applicazione esistente è stata sostituita.

## Checklist manuale da completare

- [ ] Avviare 0.6 e 0.7 insieme; verificare nome, icona, preferenze e cache separate.
- [ ] Passare fra le quattro sezioni; nascondere/ripristinare la sidebar; toolbar
      Aggiungi documenti solo in Firma, Cerca dispositivi in Dispositivi.
- [ ] Light e Dark, dimensione minima e finestra grande: nessuna sovrapposizione,
      testo leggibile, Burgundy leggibile, focus tastiera e VoiceOver coerenti.
- [ ] Aprire/chiudere Certificati, Opzioni di firma, Dispositivi e connessioni;
      cambiare certificato e destinazione; controllare riepilogo aggiornato.
- [ ] Trascinare PDF e altri documenti, aprire anteprima PAdES, posizionare il
      segno, tornare a Documenti ed esiti; nessuna approvazione prematura.
- [ ] Con provider sintetico: conferma aggiuntiva, PIN sintetico, invio da tastiera,
      annullamento, 2+ file, esiti, collisione output senza sovrascrittura.
- [ ] Con DigitalDNA/CNS reale, a cura dell'utente: consenso, focus PIN, annulla,
      firma singola/multipla e verifica indipendente degli output.
- [ ] Verifica documenti ed esportazione PDF/TXT; dispositivo assente, errore di
      acquisizione e blocco navigazione durante le operazioni.

Nessuna GitHub Action, merge, release o tag. STOP alla consegna della Build 1.
