# Signum 0.7 Build 9 Verification — Hotfix 1

Base: `b00b6b6`. Versione 0.7.0, build interna 11, ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B11`. L'installazione non sostituisce la Build 9 originale. I minimi 980×650 pt del contenuto sono espressi anche come vincoli Auto Layout, richiesti da AppKit per mantenere il limite della finestra nativa.

## Diagnosi

Riprodotto il crash aprendo Impostazioni da Firma nella Build 9 installata. Il debugger si è fermato su `objc_exception_throw` sul main thread. Motivo originale (indirizzi rimossi):

> Cannot remove an observer <SwiftUI.BarAppearanceBridge> for the key path "displayMode" from <NSToolbar> because it is not registered as an observer.

Stack: Foundation `_removeObserver:forProperty:` → `removeObserver:forKeyPath:context:` → SwiftUI `AppKitWindowController.updateToolbarIfNeeded` → `NSHostingView.updateConstraints`. Senza debugger, il processo termina con EXC_BREAKPOINT/SIGTRAP.

Il problema è una proprietà concorrente della toolbar: il controller della scena Window di SwiftUI mantiene un bridge di aspetto/osservazione, mentre il contenitore nativo assegna e gestisce un altro NSToolbar. L'apertura del TabView Impostazioni forza l'aggiornamento del layout e la riconciliazione del bridge sulla toolbar corrente. L'osservatore non corrisponde alla toolbar dalla quale SwiftUI tenta di rimuoverlo.

Le prove controllate hanno escluso come correzioni sufficienti sia la sola rimozione di `.windowToolbarStyle`, sia il solo mantenimento di item fissi, sia la sola disabilitazione del bridge negli hosting controller figli. La finestra della scena SwiftUI rimaneva un secondo proprietario. Eliminando questo secondo proprietario, Impostazioni si apre mantenendo vivo lo stesso processo.

## Patch

- `SignumMainWindowController` è l'unico proprietario AppKit della NSWindow. I contenuti restano SwiftUI, senza una scena SwiftUI Window concorrente.
- Gli hosting controller esplicitano `sceneBridgingOptions = []` su macOS 14+, così i contenuti non gestiscono titolo/toolbar della finestra.
- Il set e l'ordine degli NSToolbarItem sono costanti dall'installazione. `update` non inserisce/rimuove item e non sostituisce il NSToolbar. Su macOS 15+ la visibilità cambia tramite `isHidden`; su 13–14 i comandi contestuali restano riservati e disabilitati quando non applicabili.
- I pulsanti controllano anche il contesto prima di invocare Aggiungi/Indietro. Rimangono i blocchi durante la firma.
- Menu nativi, ⌘,, riapertura della finestra, servizi e apertura file di Finder sono instradati dal delegate AppKit. Nessuna modifica al motore di verifica/firma o alle policy.
- Il controller finestra è mantenuto dal delegate per l'intera vita dell'app; gli osservatori di chiusura rimangono limitati alla finestra proprietaria e vengono rimossi in deinit.

Nessun ritardo arbitrario, cattura/soppressione dell'eccezione Objective-C, swizzling o API privata.

API Apple: https://developer.apple.com/documentation/swiftui/nshostingcontroller/scenebridgingoptions

## Checklist per il bundle Release

- Impostazioni da Firma, Verifica e Dispositivi; Indietro ritorna alla sezione corretta.
- ⌘, apre Impostazioni; provare anche quando la finestra viene riaperta.
- Almeno 30 cicli completi, con processo invariato e nessun nuovo crash report.
- Ripetere con sidebar aperta/chiusa e finestra minima/ingrandita/ridimensionata.
- Generali, Firma grafica, Trusted Lists e Dispositivi; tornare a Generali.
- App predefinite: aprire il pannello e annullare senza cambiare associazioni.
- Verificare il P7M reale e riaprire Impostazioni dopo il completamento.
- Toolbar unica, titolo nativo allineato e sidebar fluida; nessun item duplicato.
- Firma: approvazione, PIN e annullamento preservati. Le firme reali richiedono consenso e dispositivo dell'utente.

Motore crittografico, DSS, PKCS#11, OpenSC e HalleyMac invariati. Nessuna GitHub Action, merge, tag o release. STOP alla consegna per collaudo manuale.
