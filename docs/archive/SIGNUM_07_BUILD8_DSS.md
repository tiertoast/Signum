# Signum 0.7 Development Preview — Build 8 DSS

Consolidamento delle tre correzioni del commit `9c1f2b7`: ambiti TL combinati firma/sigillo, istante coerente dopo acquisizione online e selezione delle evidenze di revoca per certificato (con precedenza della revoca autenticata).

Interfaccia della Build 8, con la correzione già esistente della configurazione manuale PKCS#11 (`62b0175`). Nessun redesign della schermata Verifica. Il motore di firma, i controlli crittografici C, OpenSC e HalleyMac non vengono modificati.

## Identità del pacchetto

- Nome visibile: Signum 0.7 Development Preview — Build 8 DSS.
- Versione: 0.7.0; numero interno del bundle: 9.
- Bundle ID: `io.github.tiertoast.Signum.DevelopmentPreview.V07.B9`.
- Preferenze e installazione separate dalla Build 8 originale e dalla Beta 0.6.
- Build locale arm64, macOS minimo 13, firma ad hoc. Nessuna pubblicazione o notarizzazione.

## Diagnostica riproducibile

Il helper incluso `Contents/Helpers/SignumTrustProbe` aggiunge solo il selettore esplicito `--current-time` e gli istanti nel risultato. Il comportamento predefinito storico resta invariato. Il comando `evidence CACHE.json FILE --online --current-time` usa i validatori di produzione, il trasporto OCSP e le TL autenticate; non importa esiti DSS. Senza `--current-time`, in assenza di prova temporale la qualificazione storica rimane indeterminata.

Non includere P7M, certificati personali, risposte OCSP reali o cache utente nel repository. Il rapporto completo precedente è in `SIGNUM_DSS_6_5_DIAGNOSIS.md`.

## Collaudo manuale

1. Avviare questa app e verificare il nome Build 8 DSS, senza sostituire altre versioni.
2. In Verifica caricare il P7M di riferimento e consentire la verifica online. Attendere il completamento.
3. Controllare integrità, catena, revoca GOOD e QES alla data di verifica; nessuna marca temporale e nessuna attestazione retroattiva della data dichiarata.
4. Ripetere offline: evidenze mancanti o scadute devono restare indeterminate; nessuna qualificazione positiva forzata.
5. Controllare Firma: selezione documenti/certificato, approvazione, PIN e annullamento. Una firma reale richiede dispositivo e consenso dell'utente.
6. In Impostazioni → Dispositivi controllare il caricamento manuale del modulo anche senza dispositivi rilevati.
7. Verificare Light/Dark, sidebar e ridimensionamento: disposizione della Build 8.

STOP alla consegna per collaudo; nessun merge, tag, release o GitHub Action.
