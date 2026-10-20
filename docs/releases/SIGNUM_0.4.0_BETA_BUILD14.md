# Signum 0.4.0 Beta — Build 14

*Digital signatures. Simply native.*

**Canale Beta · Apple Silicon arm64 · macOS 13.0 o successivo**

Questa Beta consolida l'hardening 14-A/B/C della versione 0.4.0. Include firma
digitale CAdES e PAdES, anche con rappresentazione visibile, interfaccia nativa
macOS, anteprima e posizionamento grafico sul PDF, firma di documenti multipli
e verifica crittografica delle firme prodotte.

La firma usa il middleware PKCS#11 installato dall'utente, tramite worker
isolato e helper PAdES. I collaudi locali riferiti dall'utente comprendono
DigitalDNA, CNS e documenti PDF multipli. La compatibilità è stata verificata
soltanto sui dispositivi e sulle configurazioni effettivamente provati: non è
una certificazione dell'intera famiglia DigitalDNA/CNS né di ogni versione
dei relativi driver. I middleware proprietari non sono inclusi nel bundle.
La sessione Secure Batch PIN è disponibile quando il dispositivo e il
middleware supportano il flusso previsto.

Il consolidamento migliora affidabilità dei flussi, isolamento del middleware,
gestione degli errori e degli esiti incerti, coerenza fra anteprima e firma,
gestione della memoria e riduzione di copie dei dati durante le operazioni
CAdES/PAdES. La Build 14 aggiorna il solo numero di build rispetto al codice
applicativo consolidato e collaudato della milestone 14-C.2.

## Limitazioni attuali

- È una Beta destinata a un collaudo controllato con copie di documenti di prova.
- La verifica crittografica non equivale automaticamente a una valutazione
  completa di attendibilità, catena di certificazione, revoca o qualificazione
  della firma. Tali valutazioni non sono dichiarate complete in questa Beta.
- Il budget di memoria per PDF particolarmente complessi rimane un limite
  documentato; le misure sulle fixture non garantiscono un limite generale
  dell'intera pipeline PDFKit e PAdES. Per i dettagli vedere il rapporto 14-C.2.
- Il target minimo è macOS 13.0; questa preparazione non aggiunge nuovi collaudi
  su sistemi macOS 13/14 reali, su tutti i middleware o su Mac Intel.
- La firma del bundle è ad hoc: la build non è notarizzata e non è firmata
  Developer ID. Le protezioni di macOS possono richiedere un'apertura manuale
  autorizzata dall'utente.

## Utilizzo e contenuto del DMG

Il DMG contiene `Signum.app`, `BuildManifest.json`, queste note e `SHA256SUMS`
per l'integrità dei file inclusi. Il checksum SHA-256 dell'intero DMG è fornito
separatamente nel file `.dmg.sha256`. Il bundle comprende CLI, worker PKCS#11,
helper PAdES e dipendenze native necessarie, con le relative notice.

Chiudere eventuali altre istanze di Signum e aprire la nuova applicazione.
Usare il middleware già installato per il dispositivo provato. Inserire il PIN
solo nella richiesta locale dell'app, senza riportarlo in chat, log o screenshot.
In caso di esito incerto, controllare l'output prima di avviare una nuova firma.

Questi artefatti sono preparati localmente: merge, tag e pubblicazione della
Pre-release richiedono un'approvazione esplicita separata.
