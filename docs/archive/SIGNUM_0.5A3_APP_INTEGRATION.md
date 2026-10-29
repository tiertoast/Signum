# Signum 0.5-A.3 — integrazione macOS

Baseline: `3126e9c6ddefaee1abf845f72bb3375e9585b469`, branch
`feature/signum-0.5a-trusted-lists-foundation`. Solo Development Preview locale;
nessun merge, tag, release, GitHub Actions o avvio di 0.5-B.

## Applicazione

Il target SignumApp dipende dal nuovo adattatore `SignumTrustIntegration`, che
riutilizza `TLRefreshService` A.2. Non cambia il verificatore XML, il parser,
le ancore OJ, la policy dei pivot o il risultato CAdES/PAdES.

Il delegate dell’app possiede un solo modello e avvia il ciclo A.2 dopo il lancio.
La costruzione del modello non apre la rete o la cache. Creazione della cartella,
lettura autenticata e refresh partono in task a priorità utility; la verifica XML
rimane nell’actor del servizio, fuori dal MainActor. Nessuna operazione di firma
attende questi task. Non sono introdotti timer di processo, daemon o LaunchAgent.
La terminazione cancella il ciclo e il refresh; un identificatore di generazione
impedisce risultati tardivi dopo stop. Più finestre condividono lo stesso modello.

In Impostazioni, «Elenchi fiduciari» mostra stato, ultimo refresh verificato,
scadenza, conteggi della lista italiana e aggiornamento manuale. Un refresh fallito
con cache ancora corrente conserva dati e conteggi, accompagnati da un messaggio.
Una lista scaduta è indicata come obsoleta; il catalogo tipizzato non la restituisce
come corrente. La presentazione ricontrolla la scadenza anche fra refresh.

`TrustedListCatalogProviding.currentCatalog()` espone esclusivamente una lista
italiana autenticata e temporalmente corrente, o nessuna lista. Non produce
verdetti sulle firme personali e non viene chiamato dal motore CAdES/PAdES.
Non sono aggiunti catene X.509, OCSP/CRL, eIDAS o marche temporali.

## Isolamento

Bundle ID: `io.github.tiertoast.Signum.DevelopmentPreview`.
Nome: **Signum 0.5 Development Preview**, versione `0.5.0`, build `3`.
La versione 0.4 di `Resources/Info.plist` rimane invariata: i metadati preview sono
applicati soltanto dalla variante del packager.

Cache: `~/Library/Application Support/io.github.tiertoast.Signum.DevelopmentPreview/TrustedLists/verified.json`.
Preferenze nel dominio del bundle preview; nessuna modifica alla Beta 0.4,
alle sue installazioni, a main o HalleyMac. La preview non viene installata in
Applications. Le ricette storiche sono riutilizzate con opzioni preview esplicite;
i valori predefiniti della ricetta beta rimangono quelli precedenti.

## Packaging autonomo

Architettura arm64, deployment target dichiarato e misurato nei Mach-O **13.0**.
Le dipendenze private sono compilate da sorgenti con SHA-256 fissati:

| Dipendenza | Versione | Incorporazione |
| --- | --- | --- |
| xmlsec | 1.3.12 | libxmlsec1 e backend OpenSSL dinamici |
| libxml2 | 2.15.4 | una dylib condivisa da Trust e PoDoFo |
| OpenSSL | 3.5.6 | una libcrypto e una libssl per il bundle |
| PoDoFo | 1.1.2 | dylib privata, helper PAdES esistente |
| FreeType | 2.13.3 | statica in PoDoFo |

L’helper e Trust usano lo stesso prefix; non si mischiano OpenSSL 3 e 4 o librerie
Homebrew. Restano le normali librerie/framework di sistema macOS. Il supporto
PKCS#11 hardware richiede sempre il middleware del dispositivo, come nella 0.4;
questo non è una dipendenza per autenticare le Trusted Lists.

Sono inclusi gli schemi XSD A.1 e le licenze native. Il probe diagnostico incluso
nei Helpers usa gli stessi schemi tramite un collegamento relativo alle Resources.
Il packager copia la chiusura delle dipendenze, rifiuta dipendenze esterne al prefix,
controlla architetture/minimum OS, riscrive i load command a `@loader_path`, rimuove
rpath di sviluppo e firma dall’interno all’esterno. La copia rilocata preserva i
symlink e viene verificata nuovamente con codesign. Il manifest contiene commit,
configurazione, provenienza delle dipendenze e hash del codice annidato.

Firma **ad hoc**, senza Developer ID, hardened runtime o notarizzazione. È un
artefatto per collaudo locale. Non richiede Homebrew, Java o librerie installate
dall’utente per Trust e verifica crittografica software.

## Riproduzione

Servono Apple developer tools, Python 3, CMake e pkg-config sulla macchina di build.
La ricetta corrente trova pkg-config in `/opt/homebrew/bin`; Homebrew serve solo
alla preparazione dello sviluppo, mai al funzionamento dell’app.

```sh
Tools/TrustPoC/prepare-preview.sh /nuovo/percorso/native-preview
python3 scripts/build-preview-app.py \
  --output '/nuovo/percorso/Signum 0.5 Development Preview.app' \
  --native-prefix /nuovo/percorso/native-preview/prefix \
  --cmake /percorso/cmake
python3 scripts/test-preview-bundle.py \
  --bundle '/percorso/Signum 0.5 Development Preview.app' \
  --output-root /nuovo/percorso/evidenze-rilocazione
```

Gli output esistenti sono rifiutati. La cache degli archivi preview è separata
in `.build/preview-native-src`. Per test Swift non confezionati con il prefix
preview, aggiungere il suo rpath **solo di sviluppo**:

```sh
SIGNUM_TRUST_NATIVE_PREFIX=/percorso/prefix Tools/TrustPoC/native.sh test \
  -Xlinker -rpath -Xlinker /percorso/prefix/lib \
  --filter SignumTrustIntegrationTests
```

Gli rpath di sviluppo vengono rimossi dal bundle finale. Per il runner ufficiale
si può riutilizzare il prefix A.2 e i comandi documentati nel consolidamento.

## Validazione e limiti

I log e il rapporto di consegna identificano le esecuzioni e lo SHA finale.

| Prova | Esito |
| --- | --- |
| TrustCore e autenticazione A.1/A.2 | 18 + 30 test superati |
| Integrazione applicativa | 5 test superati; rendering finale ripetuto con controllo di pixel visibili |
| SignumCore, runner ufficiale | 430 test superati |
| PAdES, prefix condiviso preview | 81 casi Debug e 81 Release, CTest superati |
| PKCS#11 | 58 casi provider, 2 CTest superati |
| Contratti nel bundle | 10 test CAdES/PAdES/worker superati |
| Script di packaging | 17 test superati |
| Rete e cache nel bundle rilocato | EU LOTL 397, AgID 224, correnti |

Conteggi italiani: 56 prestatori, 562 servizi; prossima scadenza della coppia
24 marzo 2027 alle 08:16:56 UTC. La cache creata dall’avvio automatico reale
nel dominio della preview è stata riautenticata con il probe confezionato.
Nessun fallimento residuo nelle prove eseguite. Non si dichiara eseguito ogni
gruppo opzionale del runner, né una firma con token fisico o PIN utente.

Sono verificati refresh e rilettura offline dal probe nel bundle rilocato con
PATH di sistema e audit delle librerie realmente caricate, oltre all’avvio del
main executable. L’app non carica dylib esterne al bundle salvo quelle di sistema.
Le prove di aggiornamento del modello applicativo coprono rete assente, risposta
non autenticata, cache scaduta, conservazione dell’ultimo dato e cancellazione.

La prova di rendering AppKit riguarda la nuova sezione, non una code review
complessiva o una sessione manuale completa. Il tool di controllo grafico della
sessione non è riuscito a collegarsi (native pipe closed).

Host di collaudo arm64/macOS 27.2. **Esecuzione reale su macOS 13 non effettuata**;
non viene dedotta dal deployment target. Non è previsto Intel. Restano i confini
A.1/A.2: subset XML/XAdES della PoC, aggiornamento esplicito delle ancore OJ quando
necessario, assenza di un contatore sicuro contro sostituzione dell’intera cache
locale e assenza di una garanzia di persistenza dopo perdita di alimentazione.
