# Signum 0.4-A.4 — Batch Authentication & Signing Workspace

## M1 — Baseline

18 ottobre 2026. HEAD effettivo build 4 `51e9d22`, codice candidato `daca4cf`.
Nuovo branch `codex/signum-0.4-batch-auth`. Tracciati puliti, review non tracciata
preservata (SHA-256 `2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`).
Worktree verificati senza aprire altri checkout; main resta `be84a1e`.
Nessun accesso a HalleyMac. Il collaudo di sette CAdES DigitalDNA/Bit4id/DS3
riusciti sulla build 4 è riferito dall'utente, non eseguito qui.

Baseline locale: Swift **240/240**, PKCS#11 **40/40**, PAdES Debug/Release
**63/63** ciascuno; build Swift Debug/Release passate. Helper esplicito, fixture
solo sintetiche; log `.build/reliability/evidence/04a4-baseline-*`.
Alpha e candidati precedenti preservati. Nessun PIN reale/hardware/CI remoto.

## M2 — Analisi e confine architetturale

Riferimento funzionale aggiunto dall'utente: InfoCamere consente più documenti
con un solo inserimento PIN, sia DigitalDNA sia CNS. Evidenza d'uso, non prova
di sessioni PKCS#11, cache PIN, servizi o protocolli interni. Nessuna attribuzione
di un meccanismo a InfoCamere o capability dedotta da marca/label.

Riferimento normativo: [OASIS PKCS#11 3.1, C_Login e CKA_ALWAYS_AUTHENTICATE](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).
USER e CONTEXT_SPECIFIC hanno ruoli distinti; ALWAYS_AUTHENTICATE true richiede
autenticazione per uso dopo SignInit. Il riuso di una sessione USER non autorizza
a saltarla. Un login già esistente non prova la verifica del PIN appena fornito.

Il percorso attuale avvia SignumPKCS11Worker per ogni job, acquisisce lease,
Initialize/OpenSession, verifica DER/policy, login USER, FindObjects/SignInit,
eventuale login CONTEXT_SPECIFIC, Sign, CloseSession e Finalize. Nessun Logout
indiscriminato. Registry in-process distingue ownership Initialize, ma non unisce
processi. Il lease provider/slot coordina solo processi Signum cooperanti.

Decisione: prototipo **CAdES** con worker dedicato al batch e protocollo interno
incorniciato/bounded. Manifesto immutabile di job e attributi CMS, nessun documento
o percorso input/output nel worker. Padre conserva snapshot, verifica RSA/CMS e
pubblicazione atomica. Un job successivo viene richiesto soltanto dopo il commit
verificato del precedente: nessuna pre-firma della coda e nessun retry di Sign.

Primo PIN autentica USER e il primo job. Attributo leggibile false, identità
token stabile, inizializzazione posseduta e sessione valida consentono il riuso.
True richiede CONTEXT_SPECIFIC per il primo job e chiusura, poi percorso one-shot
con un nuovo PIN per ogni documento; attributo sconosciuto conserva il percorso
conservativo. PIN non mantenuto per le richieste successive. Errori/disconnessione/
timeout/crash interrompono il canale; nessun fallback automatico di un job incerto.

PAdES usa un altro processo/lease e non può condividere un handle PKCS#11.
Deferita la modifica del protocollo PoDoFo; batch PAdES e misti restano one-shot,
con spiegazione esplicita. Nessuna promessa di ottimizzazione universale o di
compatibilità hardware prima del collaudo autorizzato.

## M3 — Prototipo worker persistente

Protocollo interno v2 a frame da 4 byte + JSON (richiesta <=128 KiB, risposta
<=64 KiB, massimo 32 job e attributi <=4096 byte). Manifesto fissato prima del
login: batch/job/snapshot/hash, provider/identità file, slot/seriale, DER e attributi.
Comandi successivi non contengono PIN o nuovi attributi. Sequenza e identificativi
impediscono richieste duplicate o fuori ordine. Nessun protocollo pubblico.

Worker conserva hardening parent-death/core dump/vendor stdout/stderr del percorso
one-shot, limite condiviso di otto processi e lease per tutto il batch, compresa
chiusura verificata. Timeout per scambio, idle worker 60s, durata batch 600s,
teardown bounded con terminazione/reaping; nessuna chiamata Finalize concorrente
a un'operazione bloccata. Il padre verifica RSA con la chiave DER approvata.

Shim C: sessione dedicata, USER fresco obbligatorio, controllo token/DER/policy e
stato USER a ogni firma. Attr false noto e Initialize posseduta abilitano riuso;
true/unknown chiudono dopo la prima firma. True effettua CONTEXT_SPECIFIC dopo
SignInit con il PIN del primo job. Nessun Logout; chiusura delle sole sessioni
possedute, poi Finalize secondo ownership. Seriali sono indizi di continuità,
non attestazioni crittografiche di identità fisica; DER/firma restano vincolanti.

Test prototipo e regressioni worker/lifecycle **18/18**: tre firme/un USER,
true/CONTEXT, attributo sconosciuto, login preesistente rifiutato, duplicati/ordine,
login fallita senza retry. Prima esecuzione: tre assert usavano il numero errato
per Finalize nel solo audit sintetico (2 anziché 1); corretti rispetto all'enum
mock, ripetuti positivi. Nessuna riduzione delle verifiche del prodotto.

## M4 — Integrazione CAdES

BatchCAdESSession contiene solo piano e canale, mai PIN. Il primo invio del campo
autentica il primo job; la continuazione Core non ha parametro PIN e usa solo
questa capability legata all'approval ID. Firma RSA verificata nel padre, poi
motore CMS, verifica staging e pubblicazione Foundation esistenti. Solo dopo il
commit viene chiesta la firma successiva. Skip espliciti per job approvati ma
annullati non effettuano Sign. Nessun inserimento di nuovi job nel manifesto.

Fine normale: sessione e provider chiusi con conferma prima di pubblicare l'ultimo
output. Per errori/cancellazione, revoca immediata e teardown off-main; nessuna
prosecuzione automatica dopo fallimento. Crash/timeout senza firma verificabile
diventano esito incerto, non un tentativo da ripetere. Chiusura non confermata
resta visibile e richiede controllo dell'utente. PAdES e misti invariati one-shot.

Le prove integrate hanno individuato un blocco di Foundation waitUntilExit quando
launch e chiusura avvengono su thread pool differenti. Stack campionato, runner
sintetico bloccato interrotto; eliminata l'attesa bloccante dal nuovo canale.
Ora osservazione bounded dello stato terminato e reaping automatico Foundation;
slot conservato se il sistema non termina il figlio. Regresso anche il teardown
su thread diverso, senza attese vendor/MainActor. Nessuna modifica al supervisore
one-shot oltre alla condivisione del contatore dei processi.

M4: **36/36** test mirati, zero skip/fallimenti nel run finale; primo run
intermedio aveva due skip per helper non esplicito e tre assert legacy dovuti
alla guard di authorizeNext durante l'estrazione dell'esecutore interno. Ripetuto
con helper esplicito e semantica pubblica preservata. Test integrati: tre CAdES
verificati/un PIN; true/tre USER e CONTEXT; annullamento in coda/in Sign; collisione
secondo output; snapshot corrotto; crash/timeout/errore secondo Sign; perdita
sessione e device removed; seriale/modulo cambiati prima del login; lease fra due
batch distinti; nessun PIN nei comandi successivi, nessun retry dopo errore.

## M5 — Impostazioni e flusso GUI

Preferenza persistente «Autenticazione nella firma multipla»: Automatica, quando
supportata / Richiedi PIN per ogni firma. Default automatico **condizionale**;
valori sconosciuti degradano alla seconda modalità. Nessun dato sensibile nelle
preferenze. Modalità scelta fissata al clic di approvazione, non riletta durante
il batch. Prima del PIN la GUI spiega che il supporto sarà verificato e può
richiedere altre autenticazioni; PAdES/misti/seriale indisponibile usano one-shot.

Dopo il primo job riutilizzabile, continuazione senza segreto e senza ulteriori
popup; PIN nascosto mentre il batch prosegue. In caso true/unknown, prima sessione
già chiusa e nuovo PIN esplicito per i documenti restanti. Non tentata nuovamente
la modalità persistente nello stesso batch dopo un rifiuto. Nuova sessione,
cancellazione e scomparsa della finestra revocano la capability; attese e chiusura
restano off-main. Nessuna attribuzione di capability al nome del dispositivo.

Test M5: preferenza isolata/persistenza/valore invalido e assenza credenziali,
policy CAdES/PAdES/misti/identità sconosciuta, regressioni auth/UI/PIN. Il caso
seriale/modulo cambiato, aggiunto dopo il run M4, è verificato qui prima del login.

M5: **27/27** test mirati, più **1/1** specifico per identità modulo/seriale.
Quest'ultimo era inizialmente annidato per errore in un altro metodo e quindi
non scoperto da XCTest: corretto lo scope, eseguito esplicitamente e contato
soltanto dopo l'esecuzione. Il run finale completo lo include.

## M6 — Workspace compatto

Intestazione unica Documenti, conteggio, barra e riepilogo degli esiti. Riga
principale: indicatore semantico, nome troncabile/tooltip, formato e stato breve.
Prima del consenso restano visibili le destinazioni effettive già pianificate;
poi i percorsi vengono mostrati solo espandendo. Dettagli per documento: origine,
destinazione, dimensione/hash, verifica, certificato/fingerprint, provider/slot,
ID job/snapshot ed errore integrale. Azioni Rimuovi/Annulla nei dettagli; Apri
cartella e Nuova sessione nell'intestazione. Nessun Finder avviato dai test.

Riepilogo separa successi, fallimenti, annullamenti e risultati da verificare.
PDFKit e approvazione degli snapshot restano invariati. Campo PIN fuori dallo
scroll laterale, nascosto durante continuazione automatica. Nessun redesign,
animazione o Liquid Glass. Candidato portato a **0.4.0/build 5**, target 13 invariato.

**31/31** test mirati finali auth/workspace/PIN, inclusi teardown bloccato visibile
e Initialize non posseduta (nessun Finalize/riuso). Aggiornato un solo assert sul
test interazione per il nuovo testo richiesto «3 documenti firmati correttamente»;
prima esecuzione lo segnalava come differenza, invarianti PIN/firme mantenuti.
Modello riepilogo coperto da due nuovi test; terzo test nativo aggiunto per errore
visibile, nessun PIN e nessun output. Rendering propri NSHostingView/NSWindow
ispezionati: lista 32 documenti/PIN raggiungibile a 650 punti, errore distinguibile
e pannello PDFKit conservato. PNG `.build/04a4-ui`. Versione dei PNG è quella
dell'host XCTest (16.0/build 25229), non del bundle. Rendering GPU del contenuto
PDF non interamente acquisito: verificati documento/pageCount e binding snapshot,
non dichiarata completa accettazione visiva/interattiva.

Ultimo controllo layout dopo le sole etichette singolare/formato nuovi documenti:
**5/5** (riepilogo e viste native). Nessun popup o interazione hardware nei test.
