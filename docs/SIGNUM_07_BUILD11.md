# Signum 0.7 — Devices Experience & Multi-Document Verification · Build 11

Base `b66d59a` (Build 10). Versione 0.7.0, numero interno 13, ID distinto `io.github.tiertoast.Signum.DevelopmentPreview.V07.B13`.

## Verifica cumulativa

La Build 10 chiamava `cancel()` e ricreava `rows` a ogni `start/verify/acquire`. Un nuovo documento sostituiva quindi la sessione. Ora le aperture aggiungono righe con UUID propri; i batch percorrono una coda seriale esplicita. Solo Annulla e reset invalidano la generazione dei task. Un callback di una generazione precedente non può aggiungere o aggiornare righe nuove.

- Selezione e report completati rimangono invariati quando si aggiungono documenti.
- Ogni richiesta conserva il proprio verificatore, compreso l’originale di un P7S. Gli aggiornamenti sono associati all’UUID, non al nome file o all’indice di un altro batch.
- Picker, drop e Finder confluiscono nella stessa coda. Aprire il picker e annullarlo non annulla la verifica già in corso.
- I documenti in attesa mostrano «In coda…». La × rimane bloccata finché ci sono elaborazioni/acquisizioni, come nella Build 10.
- Limite di 32 righe per sessione e di 32 acquisizioni pendenti; massimo 128 MiB di contenuto trattenuto condiviso tra tutti i batch. I limiti per singolo file del motore restano invariati. Un batch oltre capacità è respinto con messaggio, senza perdita di quelli esistenti.
- File con nomi uguali e percorsi diversi mantengono righe distinte; il percorso padre è visibile per disambiguare. La ripetizione del medesimo file in una nuova apertura è una nuova riga e una nuova verifica. Duplicati nella stessa richiesta sono filtrati per percorso completo, come in precedenza.
- Annulla arresta le attività pendenti e conserva i risultati conclusi. Export ed estrazione mantengono snapshot immutabili e scrittura senza sovrascrittura.

## Dispositivi

La nuova vista presenta dispositivi/accessi osservati, disponibilità pubblica, numero di certificati quando accertabile, titolare, funzione, scadenza, idoneità locale e selezione. I metadati del token forniscono il nome del dispositivo; nessuna deduzione dal certificato.

Le osservazioni identiche dello stesso modulo/slot sono deduplicate solo nella presentazione. Accessi con DER comune, seriale non vuoto, modello e produttore concordanti possono essere raccolti come «accessi correlati»: questa correlazione non prova identità fisica comune, dichiarata esplicitamente come non accertata. Tutte le route distinte restano nel modello di sicurezza. Una route ambigua richiede scelta esplicita; non viene effettuato fallback automatico.

La scelta usa la stessa funzione `selectRoute` e lo stesso `DeviceSelection` del Picker Firmatario. Non sono cambiati selezione automatica, conservazione al refresh, controlli locali, preflight del modulo/certificato, PIN o motori. Certificati non idonei sono consultabili ma non selezionabili come nuovi firmatari da questa schermata.

Un solo pannello Dettagli tecnici contiene provider/percorso, slot/token/CKA_ID, fingerprint, KU/EKU/OID, DER/Base64 e diagnostica copiabili. Security.framework legge le estensioni esclusivamente per presentazione: il risultato non partecipa a idoneità o fiducia. Configura dispositivo riusa il pannello esistente; Aggiorna rimane nella toolbar.

Firma e Impostazioni non sono ridisegnate. La sola integrazione nella finestra sostituisce il contenuto della sezione Dispositivi. Finestra/toolbar Hotfix, Liquid Glass e animazione sidebar restano invariati.

## Collaudo

Test deterministici su coda, aggiunte dopo/durante verifica, reset/cancellazione, omonimi, report corretti, rimozione, isolamento degli errori, capacità condivisa, certificati omonimi/non idonei/scaduti/indeterminati, CNS/DigitalDNA sintetici, middleware correlati, scelta route e refresh. Regressioni di Firma, qualificazione corrente, rapporti e toolbar.

La consegna locale include risultati, screenshot Release reali e immagini dei test Dispositivi con dati sintetici esplicitamente etichettate. Non confondere le immagini sintetiche con un collaudo hardware. Le prove fisiche CNS/DigitalDNA dipendono dai dispositivi collegati. Firma reale con PIN e macOS 13 fisico restano al collaudo dell’utente.

Motori CAdES/PAdES/DSS, PKCS#11, Trusted Lists/policy, OpenSC e HalleyMac invariati. Nessun documento personale pubblicato nel repository. Nessuna GitHub Action, merge, tag o release. STOP alla consegna della Build 11.
