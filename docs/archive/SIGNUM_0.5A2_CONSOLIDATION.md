# Signum 0.5-A.2 — Consolidamento locale e GitHub

20 ottobre 2026 — branch `feature/signum-0.5a-trusted-lists-foundation`.
Il commit A.1 `4311901f5ff15630ad638bea65e04c63ebf56e0b` è stato verificato,
pubblicato senza force-push e confrontato con il riferimento remoto prima di
iniziare A.2. Il rapporto finale di consegna contiene lo SHA A.2 e l'esito del
secondo confronto locale/remoto.

## Comportamento implementato

Sono estesi gli stessi `TLAuthenticator`, `LOTLPivotChain` e `TLSnapshot` della
PoC. Il verificatore XML nativo, il motore di firma 0.4 e la GUI restano invariati.

`TLRefreshService` aggiunge refresh su richiesta e un ciclo periodico cancellabile,
con intervallo predefinito di sei ore. Le richieste simultanee condividono il
medesimo aggiornamento. Il ciclo anticipa la scadenza di cinque minuti, con un
minimo di un minuto fra tentativi; gli errori provocano un nuovo tentativo entro
cinque minuti. Il chiamante possiede il ciclo: non viene installato alcun daemon,
LaunchAgent, scheduler Codex o collegamento automatico alla GUI.

`TLHTTPSClient` usa sessioni effimere senza cookie, credenziali o cache HTTP.
Accetta soltanto gli URL LOTL/AgID configurati e i pivot EC nel percorso ammesso.
Nessun redirect viene seguito. Limiti: 15 secondi per richiesta, 45 secondi di
risorsa, 64 MiB durante la ricezione, massimo 16 pivot e 64 MiB cumulativi per
LOTL più pivot. Il corpo AgID è recuperato solo dopo la verifica della catena EU.
URL scoperti in XML non verificato sono esclusivamente indizi limitati al server
EC autorizzato, mai certificati attendibili o destinazioni arbitrarie.

La cache contiene in un unico envelope i byte XML originali di EU, Italia e
catena dei pivot. Il formato A.1 senza campo pivot rimane leggibile. Le firme
vengono ricontrollate a ogni lettura; la scrittura conserva il meccanismo atomico
A.1 e aggiunge un lock laterale stabile fra processi. Il controllo di continuità
avviene sotto lock sulla versione effettivamente presente: sequenze, date e
cronologia pivot non possono arretrare. Un altro scrittore occupato produce un
errore esplicito, non una sostituzione concorrente.

Un errore di rete, firma, schema, download, rollback o aggiornamento italiano
conserva lo snapshot precedente. Il risultato indica `source=cache` e riporta
l'errore. Se una delle due liste è scaduta, il risultato indica `expired` e non
espone record autenticati come correnti. L’orologio viene ricampionato dopo i
download, prima della scrittura atomica e alla restituzione del risultato: una lista scaduta durante il refresh
non viene promossa a corrente. Due test separati coprono scadenza durante il
download e scadenza prima del commit. La cache corrotta viene rifiutata senza
azzerare silenziosamente lo storico locale. Senza cache verificabile l'errore
rimane un errore, non uno stato di fiducia.

## Pivot ufficiali

La correzione principale rispetto ad A.1 è l'autoriferimento: il pivot può e,
nel procedimento EC utilizzato, deve includere anche il proprio URL nella lista
firmata. La precedente fixture sintetica senza autoriferimento era incompleta.
Ora le fixture e il verificatore coprono due transizioni A→B→C, con pivot scaduti
ammessi solo come passaggi storici. Ogni passaggio verifica con la serie di
certificati precedente; solo dopo verifica viene adottata la serie successiva.

Il refresh scopre, recupera, ordina e salva automaticamente i pivot successivi
alla pubblicazione OJ fissata. La cronologia firmata deve concordare in ogni
passaggio e nella LOTL finale; la serie di chiavi del riferimento EU finale deve
coincidere con quella derivata dalla catena. Lo storico già accettato non può
essere troncato. Un pivot già nella cache può essere riutilizzato, ma viene
nuovamente verificato nella catena completa.

Riferimenti: [procedura EC](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html),
[OJ C/2026/1944](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:C_202601944).
La LOTL reale 397 continua a richiedere zero pivot dopo il reset 2026. Le prove
reali non sono quindi presentate come una rotazione EC effettivamente avvenuta:
le rotazioni sono testate con firme e certificati sintetici separati dalle ancore
OJ di produzione. Un chiamante pubblico non può selezionare le ancore sintetiche.

## Uso e riproduzione

```sh
export SIGNUM_TRUST_NATIVE_PREFIX="$PWD/.build/trust-native13-deps/prefix"
# Se necessario, costruire prima le dipendenze A.1:
Tools/TrustPoC/build-native13.sh
Tools/TrustPoC/native.sh run SignumTrustProbe refresh .build/trust-cache/verified.json
Tools/TrustPoC/native.sh run SignumTrustProbe offline .build/trust-cache/verified.json
# Ciclo di aggiornamento esplicito, da fermare con il processo chiamante:
Tools/TrustPoC/native.sh run SignumTrustProbe watch .build/trust-cache/verified.json
# Compatibilità con il comando di acquisizione A.1:
Tools/TrustPoC/acquire.sh .build/trust-cache
```

Il comando `refresh` forza un tentativo, mentre il ciclo automatico rispetta il
termine di aggiornamento e la prossima scadenza. `offline` non apre connessioni.
La libreria richiede una cartella cache esistente; il probe la crea per il CLI.

Prerequisiti del runner ufficiale predisposti: CMake 4.4.4, PoDoFo **1.1.2** da
sorgente contro OpenSSL **3.5.6**, FreeType 2.15.0 e Poppler 26.10.0. PoDoFo non
usa OpenSSL 4 del bottle Homebrew. Le dipendenze vengono installate in un prefix
locale e non incluse nel repository. Il checksum dell'archivio PoDoFo è fissato
nello script di preparazione.

```sh
brew install cmake freetype fontconfig jpeg-turbo libpng libtiff poppler pkgconf
Tools/TrustPoC/prepare-regressions.sh
export PKG_CONFIG_PATH="$SIGNUM_TRUST_NATIVE_PREFIX/lib/pkgconfig"
python3 scripts/test-local.py --group swift \
  --native-prefix "$SIGNUM_TRUST_NATIVE_PREFIX" \
  --cmake "$(command -v cmake)" --ctest "$(command -v ctest)" \
  --poppler "$(command -v pdftoppm)"
# Ulteriori gruppi eseguiti: pades (Debug e Release), pkcs11, packaging.
Tools/TrustPoC/native.sh test --filter 'SignumTrust(Core|Authentication)Tests'
```

Il runner e il suo manifest sono utilizzati senza modifiche. I test non usano
hardware, PIN reali, documenti utente o GitHub Actions. Risultati locali:

| Gruppo | Esito |
| --- | --- |
| TrustCore | 18 test superati |
| Autenticazione, refresh, HTTPS | 30 test superati |
| SignumCore, runner ufficiale Swift | 430 test superati |
| AddressSanitizer autenticazione | 28 test più 2 nuovi casi di scadenza superati |
| PAdES nativo | 81 casi Debug e 81 Release superati |
| PKCS#11 nativo | 58 casi provider; 2 CTest superati |
| Packaging | 17 test superati |
| Refresh reale e rilettura offline | EU LOTL 397 / AgID 224, entrambe correnti |

I 39 fallimenti di regressione A.1 causati dai prerequisiti mancanti sono risolti
predisponendo le dipendenze: nessuna correzione al motore 0.4 o al runner.
Nessun fallimento residuo nei gruppi eseguiti; non si dichiara eseguito ogni
possibile gruppo opzionale del runner. AddressSanitizer usa `detect_leaks=0`;
le librerie native esterne non sono state ricompilate con sanitizzazione.
Il rapporto finale e i log identificano esattamente le esecuzioni e gli SHA.
La rilettura offline ha mantenuto `source=cache freshness=current`, con scadenza
della coppia al 24 marzo 2027, 08:16:56 UTC.

## Problemi aperti e confini

- Esecuzione effettiva su macOS 13 e su Intel ancora non verificata; il codice e
  le dipendenze Trust A.1 hanno deployment target 13.0, i test girano su arm64/macOS
  27.2. Le dipendenze PAdES di regressione sono per questo host di sviluppo.
- Migrazione della posizione LOTL o nuova pubblicazione OJ richiedono un
  aggiornamento esplicito della policy. Nessun cambio automatico di ancore OJ.
- La cache non protegge dalla cancellazione o sostituzione dell'intero storico
  da parte di un aggressore locale con i permessi del proprietario. Un bootstrap
  nuovo non dispone di un contatore sicuro per riconoscere ogni replay ancora
  temporalmente valido. La sostituzione atomica non equivale a una garanzia di
  persistenza dopo perdita di alimentazione.
- Il ciclo periodico esiste finché il chiamante è in esecuzione. Non è stata
  attivata un'integrazione GUI o un servizio persistente su questo Mac.
- Restano il sottoinsieme XML/XAdES e i limiti di interoperabilità documentati in
  A.1. Nessuna catena X.509, revoca, marcatura temporale attendibile o qualificazione
  di firme: non è stata iniziata 0.5-B.

Nessun merge, tag, release, modifica a main, HalleyMac o motore Signum 0.4.
