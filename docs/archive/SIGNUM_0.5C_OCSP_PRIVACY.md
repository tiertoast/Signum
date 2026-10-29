# Signum 0.5-C — Rete di revoca e privacy

L’integrazione delle evidenze usa offline come modalità predefinita. La modalità
online è esplicita nell’API e nel comando `SignumTrustProbe evidence … --online`;
non introduce un processo residente e non modifica la GUI.

**Che cosa viene comunicato.** Una richiesta OCSP contiene identificativi del
certificato da controllare: hash dell’emittente e numero seriale. Il responder
vede inoltre indirizzo IP, orario e frequenza delle interrogazioni e può correlare
l’interesse per un certificato. Non vengono inviati documento, contenuto firmato,
SignatureValue, attributi CMS o PIN. Il download CRL chiede la lista indicata dal
certificato; non aggiunge il suo seriale al corpo della richiesta. Anche DNS e
richieste CRL possono rivelare il dominio del prestatore interrogato.

**HTTP e HTTPS.** Si accettano soltanto URL AIA-OCSP e CDP del certificato già
ricondotto a un percorso TL verificato. HTTP consente di osservare e alterare il
traffico: è supportato per interoperabilità, ma la risposta non viene accettata
senza la verifica crittografica OCSP/CRL. HTTPS protegge il trasporto, non sostituisce
l’autenticazione della risposta. Il responder continua a conoscere la richiesta.
Non si usano credenziali, cookie, proxy o configurazioni personali di curl.

**Limiti e destinazioni.** Schemi diversi, credenziali nell’URL, frammenti, porte
non standard, IP letterali e nomi locali vengono rifiutati. La risoluzione DNS è
controllata: si rifiutano indirizzi locali, privati, di documentazione e transizione;
un indirizzo pubblico approvato viene fissato alla connessione per impedire una
seconda risoluzione e il DNS rebinding. Si preservano hostname TLS e verifica del
certificato del server. I redirect consentiti sono **zero**; risposte diverse da
HTTP 200 non vengono consumate. Si prova al massimo un endpoint OCSP e uno CRL
per certificato, entro otto richieste e trenta secondi di budget di sessione.
DNS ha timeout tre secondi, il trasferimento otto; corpo entro 8 MiB, processo
supervisionato e cancellabile. La modalità offline non esegue neppure risoluzioni DNS.

**Cache.** Si riutilizza la cache C autenticata e atomica, separata dalla cache TL.
Ogni lettura riautentica i DER e ricontrolla la scadenza; errori di rete o risposte
non autenticate non sostituiscono un’evidenza valida. La cache riduce le richieste
ripetute, ma contiene certificati e risposte in chiaro, con directory 0700 e file
0600. Non è cifrata e non dispone ancora di una quota globale o espulsione automatica.

Il trasporto usa esclusivamente gli strumenti macOS `/usr/bin/dscacheutil` e
`/usr/bin/curl`, senza shell, Homebrew o Java. I risultati della revoca non
costituiscono da soli un giudizio complessivo sulla firma o una qualificazione.
