# Signum 0.7 — Settings Refinement & Document Management · Build 10

Base `2aaa052` (Build 9 Hotfix 1). Numero interno 12, bundle ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B12`, nome `Signum 0.7 Development Preview — Build 10`.

## Modifiche

- Pulsante × per ogni documento in Firma e Verifica: area 24 pt, etichetta accessibile, tooltip, evidenza al passaggio, animazione SwiftUI rispettosa di Reduce Motion. Azione distinta dalla selezione della riga.
- Firma riusa la rimozione del coordinatore esistente: ritira solo lo snapshot temporaneo e invalida il riepilogo. La UI cancella il preflight in corso, rilascia appearance/anteprima del documento e PIN eventualmente digitato, seleziona il vicino rimasto. Non è disponibile con firma, preparazione/acquisizione, PIN, approvazione congelata o esito incerto. Nessun output viene eliminato.
- Verifica rimuove per UUID solo la riga in memoria, mantiene identità e report delle altre righe e seleziona il vicino. Rimozione vietata durante acquisizione/verifica ed esportazione. Il contenuto originale di un report detached rimane associato al report: nessun ricalcolo o associazione per indice.
- Impostazioni con titolo esplicito e quattro schede native. Sezioni piatte e allineate, nessun GroupBox annidato. Autenticazione/PIN spiegati senza ulteriori disclosure.
- Firma grafica mantiene la preferenza nome e tutte le configurazioni nell’anteprima PDF effettiva, senza duplicare o modificare il posizionamento.
- Trusted Lists: stato, aggiornamento, scadenza e modalità nel riepilogo; paesi/cache e limitazioni in un solo livello Dettagli. Cache scadute, errori e messaggi rimangono visibili.
- Dispositivi: percorsi salvati, software e problemi di caricamento; configurazione manuale sempre disponibile indipendentemente dalla scansione. Gestione dei moduli esistenti e selezione sicura invariate.
- Architettura finestra/toolbar dell’hotfix invariata: nessuna modifica strutturale della toolbar.

Nessuna modifica ai motori di firma/verifica DSS/PKCS#11, policy, OpenSC o HalleyMac. Nessuna Action, merge, tag o release.

## Collaudo locale e manuale

- Rimozione primo/selezionato/ultimo, batch multiplo, selezione del vicino ed empty state.
- Snapshot ritirato, file originale/output/rapporti esportati conservati; approvazione precedente respinta.
- Rimozione bloccata durante attività asincrone e approvazione congelata; annullamento operativo invariato.
- Report detached conserva il contenuto associato, altri esiti invariati.
- Impostazioni/Indietro 30 volte sulla Release con PID invariato, da Firma/Verifica/Dispositivi e ⌘,.
- Quattro schede, pannello app predefinite aperto/annullato; nessuna associazione reale modificata.
- Trusted Lists e configurazione dispositivo, senza caricare middleware arbitrari o inviare PIN.
- Light/Dark, finestra minima e ingrandita, sidebar aperta/chiusa. Screenshot reali nella consegna locale.
- Debug/Release e controlli packaging; prova fisica su macOS 13 e firma reale con token/PIN restano al collaudo dell’utente.

STOP alla consegna per collaudo manuale.
