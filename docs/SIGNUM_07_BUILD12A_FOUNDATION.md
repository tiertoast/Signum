# Signum 0.7 — PIN Management Foundation · Build 12A

Base: Build 11 `a0492d2acc4b3260dafac372e7db13d02bdab31d`.
Riferimento: rapporto `SIGNUM_PIN_PUK_PREFLIGHT_2026-10-26.md`, sezioni 3–10.

## Stato effettivo

Questa è una **patch sorgente preparata e collaudata nelle parti C portabili**,
non una Build macOS installabile certificata. L'ambiente di lavoro è Linux x86_64,
senza Swift/Xcode, accesso al Mac, OpenSC/Bit4id installati o token collegati.
Non sono stati prodotti app Debug/Release, DMG o screenshot reali. Nessuna lettura
hardware è stata effettuata. Non aggiornare la PR come «Build 12A pronta» sulla
base di questa consegna: servono compilazione e collaudo macOS.

## Implementazione

- Modelli `PINManagementProfile`, `PINStatusSnapshot`, `PINManagementContext`,
  `PINManagementApproval` e facade `PINManagementCoordinator`. Il contesto è
  amministrativo: non contiene DER, ID del certificato o route di firma.
- Protocollo amministrativo separato versione 1, attivato con `--pin-admin-v1`
  nel worker supervisionato esistente. Unica operazione ammessa: lettura pubblica.
  Schema limitato a 16 KiB e campi ignoti rifiutati anche annidati. Nessun campo
  JSON per PIN/PUK, nessuna risposta `readyForSecrets`, nessun opcode mutante.
- Lettura C dedicata `sg_pin_public_info`: soltanto `C_GetTokenInfo` e
  `C_GetSlotInfo`; nessuna apertura di sessione o autenticazione. Flag grezzi e
  limiti sconosciuti/incoerenti preservati. Nessun contatore numerico inventato.
- Modulo C `CPINManagement`: tre buffer CSecurePIN distinti e bloccati, azzerati
  su rifiuto/annullamento/errore; confronto locale della conferma; ricevitore binario
  limitato e vincolato a richiesta/contesto/operazione. Ricevitore usato soltanto
  dal collaudo sintetico: non collegato a un comando mutante del worker reale.
- Stati monotoni con consenso per richiesta/contesto/azione, flag pre-dispatch,
  successo/rifiuto/esito incerto e cleanup separato. Registro di richieste non
  riutilizzabili, limitato e non svuotato durante il processo. Esaurimento: rifiuto.
- `sg_pin_real_dispatch` non accetta moduli, API o callback e rifiuta sempre.
  Nessuna variabile d'ambiente o preferenza abilita un backend mutante.
- Barriera globale nello stesso coordinamento C usato dai lease Signum:
  condivisa per operazioni ordinarie, esclusiva per amministrazione. Ordine:
  barriera → provider → slot. Vale anche tra provider diversi. Il lease rimane
  posseduto fino al teardown; nessun upgrade di lease preesistente.
- In Dispositivi, accesso amministrativo scelto espressamente e indipendente dal
  firmatario. Lettura pubblica su richiesta, data/provenienza, avvisi di blocco o
  ultimo tentativo. Selezione/refresh/cambio vista invalidano snapshot e letture
  pendenti. Cambio PIN e sblocco disabilitati con spiegazione visibile.
- Finestre SwiftUI/AppKit native predisposte: NSSecureTextField disabilitati,
  nessun binding String ai segreti, conferma disabilitata. Le finestre non sono
  raggiungibili da azioni abilitate; nessun PIN/PUK reale richiesto.
- `SignumPINPreflight` e script inventario installazione predisposti per il Mac.
  Raccolgono informazioni pubbliche; nessun comando PKCS#15 esplorativo o
  identificazione arbitraria di driver, applet, dominio PIN o ruolo SO/PUK.
- Metadati packaging predisposti: versione 0.7.0, numero interno 14, nome
  «Signum 0.7 Development Preview — Build 12A», bundle ID
  `io.github.tiertoast.Signum.DevelopmentPreview.V07.B14`.

## Test effettivamente eseguiti

`python3 Tools/PINManagementTests/run.py --configuration debug` e `release`:

| Controllo | Esito e limiti |
| --- | --- |
| 38 casi amministrativi distinti con provider sintetico | PASS; stessi casi con -O0/-g e -O2, non 76 casi distinti |
| 8 asserzioni barriera multiprocesso e multiprovider | PASS; sorgente C reale con adattatori Linux soltanto per directory privata, ACL e API RSS non usata |
| 5 casi lettura pubblica sullo shim reale | PASS; provider sintetico e policy certificati di test che rifiuta sempre; nessuna validazione crittografica simulata come reale |
| Simboli componente C di produzione | PASS; assenti backend mock/accessor test, loader e riferimenti a funzioni mutanti vendor |
| 3 contratti metadati packaging | PASS; nome/ID nuovo, Build 11 invariata, numero non dichiarato rifiutato |
| 8 nuovi test Swift | Preparati, **non eseguiti**: Swift/macOS assenti |
| Build macOS, UI, packaging completo, screenshot | **Non eseguiti** |

I casi amministrativi includono cambio riuscito/rifiutato, PUK errato, blocco,
R/W indisponibile, sostituzione/rimozione, contesto/provider ambiguo, ricerca
incompleta, conferma diversa, NUL/eccesso di byte, frame malformati/troncati,
versione/ID errati, firma congelata, doppio tentativo, credenziali azzerate,
fallimento mlock iniziale/intermedio, cleanup fallito e rifiuto del backend reale.
Tre prove usano un vero sottoprocesso sintetico terminato prima/dopo dispatch o
senza restituire l'esito. Nessun reinvio e nessun login diagnostico.

Il provider esteso usa `SIGNUM_MOCK_PIN_ADMIN` solo nelle compilazioni dei test.
Il percorso PUK sintetico è esplicito (`mock_unblock_pin`), non una simulazione
dell'equivalenza PUK/SO o un uso generico di `C_InitPIN`.

## Capacità hardware rilevate in questo ambiente

| Dato | DigitalDNA/Bit4id | DigitalDNA/OpenSC | CNS/OpenSC | CNS/Bit4id |
| --- | --- | --- | --- | --- |
| Versione installata / identità modulo sul Mac | Non acquisita | Non acquisita | Non acquisita | Non acquisita |
| Flag pubblici PIN / limiti dichiarati | Non acquisiti | Non acquisiti | Non acquisiti | Non acquisiti |
| Driver, applet, AID e dominio PIN | Non identificati | Non identificati | Non identificati | Non identificati |
| Cambio PIN / sblocco PUK qualificati | No | No | No | No |
| Mutazioni consentite dalla Build 12A | Nessuna | Nessuna | Nessuna | Nessuna |

Il rapporto preliminare rimane la fonte di evidenze documentali; queste celle
non ne trasformano le ipotesi in capacità hardware verificate.

## Limiti e condizioni prima di qualsiasi backend reale

Il registro di tentativi C è **in memoria**, non un journal durevole. Prima di
abilitare mutazioni servono record persistente conservativo pre-dispatch,
gestione crash/riavvio, qualifica profilo/backend/versione/configurazione/dominio
e collaudo hardware separatamente autorizzato. La Build 12A rifiuta il dispatch
reale indipendentemente dal registro, quindi un riavvio non abilita un reinvio.

La barriera copre i processi che utilizzano il coordinamento Signum aggiornato.
Non rende cooperanti vecchie build, middleware di terzi o programmi esterni.
Il vincolo UI `locked` non costituisce una prova di esclusività di terzi; tutti
i pulsanti mutanti restano disabilitati. Il controllo dei lease nativi e delle
approvazioni congelate va ricollaudato sull'intero pacchetto macOS.

I test portabili non attestano la sicurezza ACL Darwin, il lifecycle AppKit,
l'integrazione completa IPC binaria in un futuro backend, la cancellazione di
copie interne nei middleware o le garanzie dopo SIGKILL. L'input reale dei
segreti non è implementato/abilitato: le finestre predisposte sono inattive.

## Completamento sul Mac

Applicare la patch soltanto a un checkout completo della base indicata,
preservando modifiche locali e controllando `git apply --check` prima
dell'applicazione. Lo snapshot usato qui è parziale e non compilabile come app.

Con dipendenze native e CMake già usati per Build 11:

```bash
python3 Tools/PINManagementTests/validate_macos.py \
  --native-prefix /percorso/prefix-nativo-build11 \
  --cmake /percorso/cmake \
  --output /percorso/nuovo-output-build12a \
  --collect-public-inventory
```

Lo script richiede percorsi reali, si ferma al primo errore e non installa
dipendenze, non sovrascrive output esistenti, non committa né accede a GitHub.
Compila e verifica app Debug/Release con la ricetta esistente e lancia i nuovi
contratti Swift. L'opzione inventario esegue solo discovery/letture pubbliche e
lettura metadati dell'installazione. I JSON possono contenere seriali pubblici e
percorsi locali: restano locali. Non pubblicarli automaticamente nella PR.

Dopo compilazione: verificare Dispositivi con DigitalDNA, CNS e provider multipli;
stato/avvisi/conservazione della selezione di firma; interruzione lettura con
cambio vista/refresh; nessuna richiesta di PIN/PUK; pulsanti sempre disabilitati;
Light/Dark, sidebar e larghezza minima; 30 cicli Impostazioni/Indietro; intera
regressione firma/verifica senza alterare i motori. Acquisire screenshot reali,
completare i controlli bundle/DMG esistenti e aggiornare la PR solo con risultati
effettivi. Nessuna Action, merge, tag o release.

**STOP prima di qualsiasi prova mutante su hardware reale.**
