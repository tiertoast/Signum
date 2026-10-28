# S03 — Fedeltà dell’input PIN terminale

Il CLI e l’ingresso terminale PAdES non usano più getpass/C string. L’acquisizione a lunghezza esplicita avviene in una pagina nativa bloccata e azzerata su ogni ritorno controllato, prima di aprire sessioni del provider. Una conversione UTF-8 stretta rifiuta l’intero input non rappresentabile; nessun trim o normalizzazione. Il dominio terminale è 1–64 byte UTF-8, esclusi NUL/CR/LF. Ctrl-C/D annullano. Il limite e la modalità di conferma sono dichiarati dal prompt. Timeout:120 secondi, senza autenticazione su rifiuto.

## Delimitatore dichiarato

LF (Ctrl-J) è esclusivamente la conferma terminale, non un byte del PIN. CR viene rifiutato: il reader disabilita la traduzione CR→LF, l’editing canonico e l’echo per impedire trasformazioni invisibili. Un incolla multilinea con altri byte già in coda dopo LF viene rifiutato interamente. Su un terminale il cui tasto Invio emette CR occorre Ctrl-J, come dichiarato nel prompt. Non si deduce dai tasti un PIN diverso dai byte ricevuti. Nessuna interfaccia può interpretare una conferma seguita da input futuro come parte retroattiva della stessa credenziale: il contratto di acquisizione è esplicito.

Alternative scartate: String(validatingCString:) da sola (perde comunque il suffisso NUL); getpass con strlen; riparazione UTF-8; CR rimosso o normalizzato a LF; taglio al limite o al primo delimitatore di un incolla multilinea. Acquisire il PIN prima dell’enumerazione certificati nel CLI è necessario per garantire zero sessioni sugli input rifiutati; il consenso alla firma resta successivo e distinto.

I canali one-shot e batch CAdES conservano il dominio a lunghezza esplicita precedente: CR/LF validi vengono trasportati identici. Non vengono modificati protocolli, opzione di riuso, testi GUI del batch o comportamento degli input validi del riuso. Il dominio PAdES di linea è già esplicitamente ristretto prima della trasmissione.

Il reader ripristina lo stato terminale su successo, rifiuto, errore, timeout o annullamento controllato. SIGKILL o morte improvvisa non eseguono cleanup: non si promettono ripristino terminale o wipe dei distruttori dopo questi eventi. Non è garantito il wipe di copie Swift/String/UI/framework/vendor o del sistema. I test PTY e il mock sintetico controllano lunghezza/hash al confine Login senza persistere il PIN; le credenziali reali non sono coinvolte.

## Test nativo preesistente

La prima esecuzione CTest di fase 2 falliva dopo 54 casi: il caso certificato malformato lasciava aperta la pipe senza PIN e pretendeva la lettura del certificato prima del reader. Questa sequenza contraddice S03 (input non valido rifiutato prima di qualsiasi sessione). Solo quel caso ora invia una cornice sintetica valida, mantenendo il rifiuto del certificato prima dell’autenticazione. I sei casi di errore su sorgente/protocollo continuano a non inviare il PIN e devono terminare entro tre secondi. Nessun assert sull’output o sul motivo di rifiuto è stato rimosso. La matrice S03 verifica separatamente zero sessioni/Login per tutti gli input rifiutati.

Anche la fixture nativa della lease occupata inviava EOF vuoto: ora ciò è correttamente rifiutato prima della lease con status v4 (exit 0 di trasporto, esito rifiutato). Per verificare davvero l’attesa della lease il test invia una cornice sintetica valida anche nel caso busy. Restano gli assert di zero accessi al provider/output e terminazione SIGKILL senza successo. Il fallimento intermedio è conservato in `final-pades-debug-ctest`.
