# S06 — Buffer PIN posseduti

`readPAdESPIN` riserva64 byte prima di leggere segreti, evitando copie ritirate per crescita del vettore. Un owner RAII azzera il parziale e il byte di lettura su ogni eccezione; solo il ritorno riuscito trasferisce il vettore al PINScope del chiamante, che lo azzera su ogni uscita controllata. Il dominio del frame resta invariato.

I test C++ intercettano l’allocatore esclusivamente nel probe: osservano i blocchi ancora vivi al confine delete, prima di free. CR, NUL, EOF, EIO, oversize, annullamento, timeout, EINTR e successo verificano assenza di sentinelle nei blocchi ritirati. Non viene letta memoria deallocata.

Il server batch ha due seam interni di test: input descriptor esplicito e osservatore della pagina già cancellata ma ancora mappata. I default produttivi restano stdin e nessun osservatore; non esiste un flag di prodotto né diagnostica aggiunta. `WorkerBatchPINContext.erase` azzera prima dell’osservatore e della distruzione, idempotentemente. I test eseguono `BatchWorkerServer.serve` reale con provider software, più firme, errore intermedio, EOF/cancel, contesto token/certificato cambiato, sessione perduta e timeout. La pagina è controllata prima di Finalize; un nuovo owner necessita un nuovo frame.

Nessuna modifica a scelta, testi, limiti, autenticazioni USER/CONTEXT o disponibilità del riuso PIN. La chiusura del processo con SIGKILL/crash non esegue necessariamente i distruttori: si prova lo stop/no retry e il rilascio della memoria da parte del sistema, non un wipe eseguito dopo la morte. Sono fuori garanzia copie Swift/String/Data/UI/framework, middleware e sistema, snapshot/ibernazione e lettori privilegiati. Questi limiti non vengono presentati come difetti del reader corretto.
