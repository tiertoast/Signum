# Signum 0.4-A.2 — Device Discovery

## M1 — Base preservata

Branch `codex/signum-0.4-device-discovery` da `dd1e786`, versione 0.4-A.
Letti README, progressi 0.4, rapporti Foundation/PR2 e RELEASE_READINESS.
Review originale non tracciata preservata; nessuna modifica a main o altri repo.
Regressioni **prima del codice**: Swift 166/166 (helper nativo abilitato),
PKCS#11 40/40, PAdES 63/63. Log `discovery-baseline-*.log` sotto
`.build/reliability/evidence`. Solo fixture sintetiche, nessun hardware/PIN reale.

Registro tipizzato estensibile: Bit4id e OpenSC, con i due soli percorsi candidati
indicati. La presenza del percorso non implica caricabilità, dispositivo o firma.
Il collaudo 0.4-A DigitalDNA, tre firme valide/tre PIN, è riferito dall'utente:
non è una nuova prova eseguita in questa sessione né compatibilità generale.

## M2 — Discovery pubblica e caricamento

`MiddlewareDiscovery` separa presenza del software, sicurezza del percorso,
risposta del worker, presenza token e leggibilità dei certificati. Ricerca limitata
ai candidati noti; manuali solo per richiesta esplicita. Nessun Login/Sign.
Deadline globale (default 30 s, massimo 60), singola chiamata massimo 8 s,
32 token enumerati per modulo, 256 certificati/8 MiB aggregati. Lavoro off-main.
Crash/timeout/errori restano problemi di comunicazione, non assenza del token.
`CKR_USER_NOT_LOGGED_IN` pubblico ha uno stato distinto; una lista vuota non prova
l'assenza di certificati privati. Nessuna autenticazione proposta dalla discovery.

Automatici: proprietario root, niente scrittura gruppo/altri, niente ACL estese
con grant di scrittura (criterio conservativo anche per grant a root), file regolare,
componenti e antenati dei target symlink controllati in sola lettura. Nessuna
modifica ai permessi del software installato. Identità device/inode/size/mtime/ctime
controllata prima/dopo la ricerca e nel worker dopo la lease, prima del caricamento.
Il parent verifica il percorso canonico della risposta. Alias stesso inode non
vengono caricati due volte. I percorsi manuali hanno fiducia esplicita dell'utente
e conservano i controlli Foundation: non sono promossi a provider automatici.

**Test mirati M1+M2: 15/15.** Matrice installati/assenti, ACL reale sintetica,
permessi/ownership/antenati e symlink su filesystem simulato, symlink manuale reale,
identità modificata, alias, risposta estranea, deadline/cancel, worker sintetico
positivo/errore/hang/crash/autenticazione richiesta. Audit: nessun Login/Sign.
Il primo runner aveva un percorso worker errato nel test (xctest invece del
prodotto SwiftPM); corretto il fixture harness e ripetuta la suite con successo.
Non è stato caricato alcun middleware installato.

## M3 — Certificati e vie di accesso

Token: label/manufacturer/model/reader e seriale pubblico, più slot come localizzatore.
Versione opzionale via C_GetInfo nel worker supervisionato; mai usata per fiducia.
`DeviceCertificate` raggruppa soltanto DER uguali (SHA-256), conserva tutte le
`DeviceCertificateRoute` con provider/percorso/file identity/token/slot/object ID.
Non dichiara identità fisica condivisa fra moduli: questa non è dimostrabile con
la sola metadata PKCS#11 disponibile. Anche seriali uguali e nomi omonimi non
fondono certificati differenti. Lease fra provider diversi resta un limite noto.

Nome, organizzazione ed emittente vengono dal DER, scadenza/idoneità dalla policy
locale SG-04. Il nuovo flag clientAuth è solo descrittivo: nessuna modifica alle
regole di idoneità o alle primitive. `DeviceSelection` non preseleziona certificati,
invalida scelta/generazione al refresh e non effettua fallback, neppure al reinsert.
La route verifica l'identità corrente del modulo off-main prima del consenso;
job e motori continuano a vincolare provider/slot/ID/DER/snapshot immutabili.

**Test mirati M3 e regressioni collegate: 42/42.** Comprendono DER comune fra
provider/slot, omonimi con stesso seriale e diverso DER, firma/autenticazione/
scaduto/KU incompatibile/indeterminato, rimozione/reinsert/cambio slot e provider,
callback tardiva, sostituzione modulo dopo scelta e seriale letto nel figlio.
Non è stato effettuato alcun collaudo del middleware installato.

## M4 — Flusso GUI e consenso

All'apertura ricerca dei soli candidati noti in coda off-main, senza dlopen GUI.
Certificati in primo piano: titolare, organizzazione (se presente), emittente,
scadenza, uso/idoneità e dispositivo. Selezione sempre esplicita; certificati non
idonei ispezionabili ma non approvabili. «Configura dispositivo» mostra stato dei
software e possibilità di nuova ricerca; dettagli avanzati contengono percorsi,
versione, origine, file identity, seriale/slot/ID e vie alternative dello stesso DER.

Modulo manuale tramite inserimento o NSOpenPanel, caricamento **esplicito**.
UserDefaults conserva al massimo otto percorsi e il provider preferito, nessun PIN.
Un percorso ricordato non viene eseguito al lancio; una ricerca manuale sostituisce
le osservazioni precedenti, la ricerca ordinaria torna ai candidati noti. Rimuovere
una configurazione invalida la selezione; cambiare via cancella PIN e cache precedenti.
Refresh/cancel e callback tardive sono vincolati a generazioni. Il worker deve
confermare la nuova verifica di identità: una vecchia risposta priva della prova
non basta per la discovery automatica.

Il riepilogo conserva una sola conferma dell'insieme immutabile, distinta dal PIN
per documento. Destinazioni brevi; sorgenti omonime distinguibili con il minimo
suffisso di cartella necessario. Percorsi assoluti/hash nei dettagli tecnici.
Il modulo scelto viene ricontrollato off-main prima del consenso e prima di ogni
job; la route approvata resta congelata e non viene sostituita dopo errori.
Nessuna riscrittura del coordinatore, snapshot o motori di firma.

**Test mirati: 39/39, zero skip**, inclusi 12 batch e quattro nuovi test esperienza:
preferenze limitate/validate/rimovibili senza segreti o esecuzione implicita,
cambio route/PIN/DER, omonimi e ispezione di certificati non idonei. Un primo run
senza variabile helper saltava il caso misto PAdES opzionale; ripetuto con helper
esplicito, caso eseguito. Build SwiftUI riuscita. Click/layout interattivi non
ancora verificati; non è stata avviata una GUI che carichi middleware installati.
