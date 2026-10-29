# Signum 0.7 — Build 12B · PIN Change Qualification

26 ottobre 2026. Base Build 12A `9a2cc4ce390fe047f2c8984fcf21e3e5d90f0aaa`.
Branch `feature/signum-0.7-ui-redesign`, PR #8.

## Esito della qualificazione

**Nessun profilo hardware abilitato. DigitalDNA/OpenSC rimane non qualificato
per un cambio PIN reale.** Il percorso completo è collaudato esclusivamente con
un provider sintetico statico. La presenza di C_SetPIN non è un'autorizzazione.

Sono disponibili evidenze sufficienti per identificare la famiglia ChipDocIT/CNS
e documentare una candidatura futura; non per autorizzare l'operazione sulla
carta osservata. Il backend sintetico non qualifica l'implementazione OpenSC.
La Build 12B consegna sorgenti, rapporto e log. Non distribuisce un nuovo
installer né abilita i pulsanti amministrativi della Build 12A.

## Evidenze acquisite sul Mac, senza autenticazione

- Inventario pubblico Signum: DigitalDNA tramite OpenSC, slot 0; flag 0x40c,
  limiti dichiarati 4–8 byte. Nessun contatore residuo disponibile. Bit4id non
  rilevato nel percorso noto. Nessuna CNS fisica distinta provata.
- PC/SC: esclusivamente EstablishContext, ListReaders, GetStatusChange e
  ReleaseContext, senza Connect, Transmit, APDU o reset. Lettore
  `Bit4id Digital-DNA Key`; ATR osservato
  `3BFF1800008131FE45006B150C0302010101434E5310318061`.
  Corrisponde alla tabella ChipDocIT e contiene il discriminatore CNS.
- Il modello PKCS#15 e l'ATR costituiscono identificazione pubblica, non
  attestazione crittografica della carta, del firmware o dei domini interni.
  Nessuna SELECT/VERIFY diagnostica per esplorare AID o riferimenti PIN.
- Modulo `/Library/OpenSC/lib/opensc-pkcs11.so`, major/minor dichiarati 0.27.
  Le ricevute OpenSC riportano 0.27.1 e la stringa 0.27.1 compare nella libreria
  installata. `opensc-tool --version` non fornisce una revisione Git.
  Queste evidenze non dimostrano la corrispondenza a un pacchetto ufficiale.
- Firma ad hoc, senza TeamIdentifier; dipendenze comprendenti una libreria
  crypto in un percorso locale preesistente. Hash di modulo, libopensc, tool e
  configurazione confrontati prima/dopo: invariati. Il modulo PKCS#11 osservato
  mantiene SHA-256 `94e62a84eb8bc011fea439f74fa704ebb653766b50afba64b2bc906ee5d855b7`.
- Sorgenti locali OpenSC alla revisione
  `ccfa7600f7c7ae249118d5f301e679e476a004a5`; emulazione PKCS#15 con modifica
  locale preesistente. Il supporto ChipDocIT è presente nei sorgenti master
  esaminati; non è presente nel file omonimo del tag 0.27.1 consultato.
  Hash dei sorgenti conservati nell'evidenza locale. Non è stata certificata
  una build riproducibile sorgente→binario.

Inventari completi con seriali e identità stat restano locali, esclusi dalla PR.
Non sono state richieste, acquisite o registrate credenziali reali.

## Driver, applicazioni e dominio destinatario

ATR e metadati sono coerenti con `card-chipdocit`/`pkcs15-chipdocit`; la
selezione effettiva di ogni applicazione non è attestata dalla lettura pubblica.
Il sorgente espone PIN utente ASCII numerico, Auth ID `01`, riferimento `0x83`
(BSO 03), limiti 4–8 byte. Distingue Generic, SSCD, IAS e un dominio CNS.
IAS: AID `A0000002471001`; Generic: `E828BD080F014E585030`; SSCD termina in
`31`; CNS: `A000000530000B104001011B`, PIN BSO `0x10`.
Sono dati del sorgente, non AID o domini autenticati sulla carta collegata.
Il profilo CNS richiede qualificazione dei due domini e del firmware.
Fonte: [driver ChipDocIT, revisione fissata](https://github.com/OpenSC/OpenSC/blob/ccfa7600f7c7ae249118d5f301e679e476a004a5/src/libopensc/card-chipdocit.c).

## Semantica C_SetPIN e sessioni

PKCS#11 permette C_SetPIN in sessione R/W pubblica oppure R/W autenticata; il
destinatario cambia con l'utente autenticato. Una sessione pubblica individua il
PIN CKU_USER. Il profilo candidato richiederebbe una sessione seriale R/W
pubblica, nuovamente controllata, senza login SO/utente/context-specific e senza
un C_Login preliminare o successivo di prova.
Fonte: [OASIS PKCS#11 2.40, C_SetPIN](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

OpenSC controlla il flag R/W, ripristina lo stato di login, passa all'operazione
del framework e riporta lo stato. Nel framework PKCS#15:

- sessione non autenticata + configurazione normale: cambio del PIN dell'oggetto
  di autenticazione dello slot;
- `user_pin_unblock_style = set_pin_in_unlogged_session`: lo stesso C_SetPIN
  può essere interpretato come sblocco;
- altri stili e login context-specific/SO hanno ulteriori significati.

Il file globale osservato contiene soltanto il blocco default e commenti debug:
non contiene override dello stile. Non basta per attestare tutti i default
compilati, blocchi applicativi, plugin e input ambientali del binario installato.
Un futuro profilo deve fissare configurazione effettiva, dipendenze, ambiente e
stato della sessione. Nessuna modifica alla configurazione OpenSC è stata fatta.
Fonti: [framework PKCS#15](https://github.com/OpenSC/OpenSC/blob/ccfa7600f7c7ae249118d5f301e679e476a004a5/src/pkcs11/framework-pkcs15.c),
[sessioni](https://github.com/OpenSC/OpenSC/blob/ccfa7600f7c7ae249118d5f301e679e476a004a5/src/pkcs11/pkcs11-session.c),
[configurazione](https://github.com/OpenSC/OpenSC/blob/0.27.1/etc/opensc.conf.example.in).

Nel driver ChipDocIT esaminato il cambio può sincronizzare prima la CNS,
riaprire PACE per IAS, verificare il PIN corrente come passo interno del comando
e aggiornare IAS. In alcuni fallimenti è previsto un rollback CNS automatico.
La verifica interna non è un C_Login diagnostico aggiunto da Signum; occorre
comunque qualificarne effetti, tentativi e consenso. Un'unica chiamata C_SetPIN
non implica un'unica modifica hardware né atomicità fra domini. Senza questa
qualifica un errore non dimostra che nulla sia cambiato. È un limite della
qualificazione, non una segnalazione di bug al progetto OpenSC.

## Foundation completata e percorso sintetico

- Journal binario immutabile: intento, record di armamento e risultato separati,
  creazione esclusiva, nessuna sostituzione/troncamento/cancellazione; SHA-256
  dei record, permessi 0700/0600 e controllo ACL/owner/hardlink/symlink.
  File e directory sincronizzati; su macOS F_FULLFSYNC è obbligatorio per i
  file. Qualsiasi fallimento impedisce il dispatch.
- Posizione persistente prevista: Application Support dell'utente,
  `Signum-DeviceAdministration-v1`, condivisa fra bundle ID e aggiornamenti;
  nessun uso di Caches o cartelle temporanee in produzione. Non invocata dalla
  facciata reale disabilitata. I test provisionano soltanto directory sintetiche.
- Il consenso C opaco scade entro 90 secondi e viene consumato una sola volta,
  anche per un tentativo con binding/operazione errati. Non è un permesso
  serializzabile. UUID già presenti nel journal non vengono riutilizzati.
- Intento e armamento vengono persistiti prima del singolo dispatch sintetico.
  Morte prima/dopo il comando, assenza di risultato o dati malformati non
  autorizzano reinvii. Un nuovo UUID/scansione/profilo non aggira un esito
  incerto per il medesimo identificativo conservativo del dispositivo.
- Il binding completo include hash e identità dei file di modulo/configurazione/
  dipendenze dichiarate, profilo, driver, applicazioni, Auth ID, dominio,
  token e generazione. Evidenze lette da descrittori fissati, con verifica
  prima/dopo; ricostruzioni incomplete da JSON non producono un binding valido.
  Hash e seriali pubblici non sono attestazioni del produttore o della carta.
- Trasporto diretto C in pipe anonime, stesso utente, nonblocking e CLOEXEC,
  framing limitato e legato a UUID/binding, timeout ed EOF obbligatorio.
  FIFO nominate, code aggiunte e frame incompleti rifiutati. Segreti in buffer
  mlock con pagine guardia; conferma locale non trasmessa. Nessun PIN in JSON,
  argv, ambiente, preferenze, journal o log. Nessun segreto convertito in String/Data.
- Il worker sintetico possiede il lease amministrativo esclusivo prima della
  preparazione; lo mantiene durante sessione, dispatch e cleanup. Controlla
  sessione R/W pubblica; zero C_Login, reset o sblocco. Un solo C_SetPIN verso
  il provider statico sintetico, senza loader/fallback o retry. Il modello
  verifica il vecchio PIN, modifica lo stato sintetico e conserva lo stato
  precedente se il PIN è errato. Verifica dello stato solo tramite accessor mock,
  mai tramite autenticazione.
- Esiti distinti: successo, rifiuto definito del modello atomico sintetico,
  successo con cleanup fallito, non eseguito e incerto. La classificazione del
  modello **non viene trasferita** al driver composto reale non qualificato.

Il consenso del collaudo è simulato; la UI reale non rilascia autorizzazioni amministrative.
Il componente prodotto contiene journal, binding, consenso e trasporto. Il
coordinatore completo con chiamata C_SetPIN è limitato al programma di test,
collegato staticamente al mock; non viene copiato nell'app. Il protocollo reale
continua ad accettare solo readPublicStatus e a rifiutare opcode mutanti o campi
segreti prima del caricamento. `permitsRealMutation` e `realBackendEnabled`
restano falsi; `sg_pin_real_dispatch` rifiuta sempre. Nessun percorso PUK nuovo.

## Test locali

Mac Apple Silicon, macOS 27.2, Xcode 27.1 / Swift 6.4; minimo macOS 13.
Comandi riproducibili:

```sh
python3 Tools/PINManagementTests/run_qualification.py --configuration debug
python3 Tools/PINManagementTests/run_qualification.py --configuration release
python3 Tools/PINManagementTests/run.py --configuration debug
python3 Tools/PINManagementTests/run.py --configuration release
# Con dipendenze native e scratch della Build 12A:
swift test --filter 'PINChangeQualificationTests|PINManagementFoundationTests'
```

| Controllo | Esito |
| --- | --- |
| 41 contratti C 12B distinti | PASS Debug e Release; non 82 casi distinti |
| 38 casi C foundation + 8 barriera + 5 shim pubblico | PASS Debug e Release |
| Simboli degli oggetti C prodotto | PASS, assenti mock, loader e import di API mutanti |
| 11 nuovi test Swift 12B + 8 foundation | PASS Debug e Release |
| Regressioni Swift mirate | 204 PASS: 160 SignumCore + 44 CertificateValidation, inclusi gli 11 nuovi |
| Compilazione prodotti macOS Debug/Release | Eseguita nelle invocazioni Swift native |
| PC/SC pubblico + inventario Signum | PASS, nessun PIN/PUK o login diagnostico |

I contratti C includono successo con cambiamento effettivo dello stato mock,
vecchio PIN errato senza cambiamento, rimozione, errori di close/finalize,
interruzioni prima/dopo dispatch, nuovo processo di recupero dopo arresto e dopo
successo, consenso errato/scaduto, nuova generazione con incerto, scrittura/sync
fallita, record corrotti o con link/permessi errati, trasporto interrotto o
malformato, pipe chiusa, FIFO nominata, sessione già autenticata/non R/W e
saturazione a 256 record senza eviction. Nessun ciclo di test carica un
middleware installato. I crash test usano solo fixture e non provano perdita di
alimentazione del Mac o del token.

## Matrice e impedimenti

| Profilo | Prove | Stato |
| --- | --- | --- |
| Atomic PIN sintetico v1 | Vecchio/nuovo PIN fittizi noti, stato controllabile, sessione pubblica R/W, crash/IO/cleanup e concorrenza | Collaudato solo come fixture |
| DigitalDNA ChipDocIT/CNS via OpenSC locale | ATR osservato, metadati pubblici, sorgente del driver, stringhe/simboli binari e hash | Candidato documentato; non qualificato, disabilitato |
| DigitalDNA senza dominio CNS | Descritto nel sorgente, nessun esemplare distinto provato | Non qualificato |
| Bit4id e CNS separata | Modulo/dispositivo non disponibili | Non qualificati; nessun fallback |

Impedimenti: build/provenienza binaria non attestate; configurazione effettiva e
catena completa delle dipendenze non certificate; firmware e mapping dei domini
non confermati dal produttore; procedura composta e rollback da qualificare;
recupero di un aggiornamento parziale IAS/CNS non documentato per quel profilo.
Non risolti tramite autenticazioni esplorative o aggiornamenti OpenSC.

## Condizioni per una futura singola prova reale

Questo è un piano **condizionale**, non l'autorizzazione a eseguirlo. Nessuna
prova reale è stata preparata con credenziali o avviata.

1. Scegliere un dispositivo di test dedicato e sacrificabile, non quello usato
   per lavoro; titolare e autorizzazione espliciti, PIN corrente noto soltanto
   all'operatore. Non inviare il PIN all'assistente o inserirlo nei report.
2. Ottenere versione/provenienza binaria verificabili, configurazione e
   dipendenze fissate; completare la qualifica del driver, delle applicazioni,
   dei domini e delle eventuali azioni interne. Il criterio di una singola
   operazione e l'assenza di retry devono valere per il profilo dichiarato.
3. Documentare con produttore/emittente il recupero del modello esatto, inclusa
   un'eventuale divergenza fra IAS e CNS. Il manuale InfoCamere descrive il
   recupero ordinario con PUK e nuovo PIN, ma non dimostra che risolva un
   aggiornamento parziale prodotto da qualsiasi versione OpenSC.
4. Conservare il PUK fuori da Signum, verificarne disponibilità documentale
   senza provarlo; prevedere assistenza/sostituzione. Nessuna prova di PUK,
   reset o sblocco viene aggiunta al cambio PIN autorizzato.
5. Prima del dispatch: contesto ricostruito indipendentemente sotto lease,
   sessione R/W pubblica, journal sano in posizione persistente, nessun esito
   incerto precedente e nessun software concorrente non cooperante. Il solo
   lock Signum non attesta l'esclusione dei programmi terzi.
6. Con autorizzazione nuova per **una sola operazione sul profilo esatto**,
   l'operatore immette localmente vecchio e nuovo PIN nelle superfici protette.
   Consenso monouso con tutti i domini e rischi descritti; nessun cambio
   automatico di provider/configurazione o uso di credenziali in argomenti.
7. Un solo dispatch e cleanup contenuto. Dopo timeout, rimozione, crash o esito
   dubbio: conservare il journal, bloccare ulteriori tentativi e fermarsi.
   Nessuna autenticazione con vecchio/nuovo PIN per scoprire cosa sia accaduto.
   Una verifica autenticata o il recupero richiedono un'attività autorizzata
   separatamente, mai una continuazione automatica.

Fonte della procedura utente ordinaria: [Manuale InfoCamere Sign Desktop v3,
22 aprile 2026, pagine 23–24](https://id.infocamere.it/assets/documenti/Manuale_infocamere_sign_desktop.pdf).
Il flusso utente descritto dal produttore non qualifica di per sé il backend
OpenSC o il dominio amministrativo.

## Limiti residui e arresto

Il journal è persistente e conservativo nei test di arresto/riavvio di processo;
non è una prova di resistenza a spegnimenti fisici, rollback di backup o
cancellazione dolosa da parte dello stesso utente/root. I checksum rilevano
corruzione, non sono una firma di autenticità. Nessuna pulizia o risoluzione
automatica degli incerti; una politica di risoluzione manuale resta prerequisito
per un futuro backend abilitato. Nessuna garanzia sulle copie interne dei segreti
nei middleware reali: quei percorsi restano disabilitati.

Le 12 modifiche locali preesistenti del checkout Signum-0.7 sono preservate per
hash ed escluse dalla consegna. Lavoro sul checkout separato pulito della base.
Motori Firma/Verifica/DSS, configurazione e binari OpenSC, HalleyMac invariati.
PR #8 aggiornata senza merge/tag/release o GitHub Actions.

**STOP prima di qualsiasi operazione mutante reale.**
