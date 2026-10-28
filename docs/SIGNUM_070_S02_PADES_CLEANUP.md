# S02 — conferma della chiusura PAdES

Il wrapper nativo usa `sg_close_checked`, consuma e disarma il contesto una sola volta e azzera il PIN prima di entrare nel teardown del provider. Il distruttore è una rete di sicurezza idempotente per i percorsi di eccezione. Non ritenta né Sign né Finalize. Un errore C_CloseSession già segnalato rende comunque la chiusura non confermata.

La chiusura esplicita avviene nel gancio prepubblicazione del writer transazionale esistente, dopo la verifica dei byte riletti e la chiusura del descrittore, prima del rename atomico. Un errore lascia il PDF verificato ma non pubblicato. I protocolli di esito v4 e v5 conservano separatamente `documentVerified`, `documentPublished`, `cleanupConfirmed` e la fase dell’errore primario. Il protocollo di firma e il numero delle operazioni private restano invariati.

Il bridge richiede conferma positiva di verifica, pubblicazione e cleanup per i job vincolati. In assenza di conferma produce un esito incerto; conserva un eventuale file già pubblicato. Il coordinatore espone l’avviso di chiusura e impedisce la continuazione automatica. Il vecchio ingresso del bridge senza expectedJobID resta compatibile, ma non è usato dall’app.

Prove sintetiche: PAdESStatusIntegrationTests, esteso con sei metodi S02 per v4 e v5, locator canonico in v5, Finalize fallito dopo firma valida o errore di verifica, CloseSession fallito, timeout, crash, preservazione di un file già pubblicato e blocco del coordinatore. Una sola Sign, un solo tentativo Finalize. Il guasto CloseSession viene iniettato dopo tre chiusure pubbliche del certificato per raggiungere il teardown della firma; la prima fixture a due chiusure si fermava troppo presto.

Limiti: timeout e crash non forniscono conferma del teardown né eseguono necessariamente i distruttori. La prova non qualifica middleware o hardware reali. Una firma crittograficamente valida e la conferma della chiusura sono informazioni distinte.
