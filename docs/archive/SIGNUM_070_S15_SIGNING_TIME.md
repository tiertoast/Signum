# S15 — portata della preferenza data e ora

D02: l’opzione persistente (stessa chiave e default) riguarda il solo attributo CMS signingTime della nuova firma CAdES: attached, detached, cofirma e controfirma. Non modifica le firme già presenti. Con false l’attributo della nuova firma è omesso; con true viene incluso.

XAdES/ASiC continuano a includere XML SigningTime, richiesto dal parser del profilo corrente. PAdES continua a impostare PDF /M. Non sono introdotti TSA o altri profili. La descrizione comune in SigningTimePolicy distingue i tre attributi e spiega che una data dichiarata non è una marca temporale né prova l’ora. È visibile nelle impostazioni, nel riepilogo principale prima del consenso, nell’eventuale conferma aggiuntiva e nella descrizione del job. Il flag resta congelato e il suo cambio invalida la review come prima. La sezione autenticazione e i testi del riuso PIN restano invariati.

Alternative: eliminare XML SigningTime uscirebbe dal profilo supportato; disattivare la preferenza globalmente toglierebbe una funzione CAdES valida. Omettere PDF /M potrebbe essere accettabile in altri assetti, ma la matrice dimostra soltanto il percorso attuale con /M e non qualifica un profilo senza /M o verificatori esterni. Si sceglie quindi la conservazione esplicitamente dichiarata, come richiesto da D02 in caso di dubbio. Nessuna affermazione che /M sia universalmente obbligatorio.

La matrice S15SigningTimeTests percorre preferenza isolata → SigningReviewContext → SigningReview → approvazione congelata → SigningJob → firma col worker sintetico o helper nativo → output finale verificato. Otto formati × due valori, con verifica dell’attributo CMS della sola nuova firma, XML SigningTime o voce PDF /M del dizionario firma; assenza di timestampTokens, invalidazione della review e immutabilità del job. Il rosso sul codice precedente produce 32 assert mancanti di disclosure; gli attributi reali già dimostrano la necessità di restringere l’opzione. Il primo tentativo non compilava perché l’enum formato non è CaseIterable: corretto solo il nuovo test e conservato il log.

Resta da collaudare manualmente leggibilità, flusso e VoiceOver dei testi nell’app.
