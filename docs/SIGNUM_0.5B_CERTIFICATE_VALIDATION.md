# Signum 0.5-B — Certificate Trust & Path Validation

Baseline `2ecff571e5e8e60ba3642079347604663578283f`.
Branch dedicato `feature/signum-0.5b-certificate-validation`.

## Perimetro e fonte delle identità

Il nuovo `SignumCertificateValidation` dipende da TrustCore/TrustAuthentication e
riutilizza OpenSSL 3.5.6 già incorporato. `CCertificatePath` è un piccolo bridge C,
non un secondo motore CMS/PDF. Nessun Java o nuova libreria esterna.

L’app usa soltanto `TrustedListCatalogProviding` del servizio A.2: la cache viene
riautenticata con catena LOTL/OJ e riferimenti nazionali prima di esporre il catalogo.
Nessuna CA è autorizzata perché nel documento o nel portachiavi. Security.framework
serve soltanto a leggere il nome di un certificato per la presentazione; non viene
creato alcun SecTrust e non viene interrogato lo store di fiducia macOS.

Il motore accetta una raccolta di liste nazionali autenticate; l’acquisizione A.3
fornisce oggi **la lista italiana AgID**, autenticata dalla LOTL europea. Non sono
stati aggiunti downloader o nuovi bootstrap nazionali in B. Un prestatore estero
non contenuto nei cataloghi disponibili produce «non verificabile»: non si dichiara
copertura automatica delle CA di tutti gli Stati europei.

Sono selezionate esclusivamente identità X.509 di servizi `CA/QC` con stato
`granted` nel periodo valutato. Nome e presenza del prestatore non autorizzano
nessun certificato. Un’identità senza DER X.509, un tipo/stato non supportato o una
cronologia ambigua non viene promossa ad ancora.

## Percorso X.509

Per ogni identità TL il bridge crea uno store OpenSSL nuovo, con **una sola**
ancora esplicita; non carica default paths, file di sistema, AIA, OCSP o CRL.
La ricerca esplora i percorsi candidati senza assumere che il primo intermedio
con nome corrispondente sia quello corretto. Duplicati DER sono eliminati;
intermedi cross-signed e chiavi alternative sono provati separatamente.
Ogni tentativo passa a `X509_verify_cert`; nessun callback ignora errori.

Flags: `PARTIAL_CHAIN`, `X509_STRICT`, `CHECK_SS_SIGNATURE`, `POLICY_CHECK`;
authentication security level 2. L’ancora finale deve essere esattamente un DER
autorizzato dal servizio TL, anche quando non self-signed. In questo caso il suo
issuer superiore non diventa implicitamente attendibile: la provenienza TL è il
confine di fiducia, e non si dichiara verificata una firma dell’ancora fuori da quel
confine. Una firma self-signed dell’ancora viene invece controllata.

OpenSSL verifica firme, validità, Basic Constraints, path length, Name Constraints,
policy constraints, estensioni critiche e coerenza delle strutture. Il profilo B
aggiunge controlli sui ruoli, Key Usage ed EKU:

- Leaf non CA, KU assente oppure digitalSignature/contentCommitment.
- CA con Basic Constraints CA e KU keyCertSign; anche le ancore rispettano questi
  requisiti e la validità temporale, scelta conservativa rispetto a un’ancora
  astratta RFC 5280.
- EKU assente, anyExtendedKeyUsage o documentSigning (`1.3.6.1.5.5.7.3.36`), su tutti
  i certificati del percorso. Un EKU esclusivo serverAuth/emailProtection non è
  accettato come firma di documenti in questo profilo.
- RSA/RSA-PSS almeno 2048 bit, EC fra 256 e 521 bit, Ed25519/Ed448; firme dei certificati
  SHA-256/384/512 o EdDSA. MD5/SHA-1 sono vietati. Altri profili non supportati non
  producono un esito verificato. Chiavi oltre 8192 bit ed esponenti RSA oltre 32 bit sono fuori dai limiti di B.

Riferimenti: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html),
[RFC 9336](https://www.rfc-editor.org/rfc/rfc9336.html),
[OpenSSL verification parameters](https://docs.openssl.org/3.4/man3/X509_VERIFY_PARAM_set_flags/),
[ETSI TS 119 612 v2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf).

## Tempo e storico

L’app valuta con l’orologio locale al momento della verifica. `declaredTime` del
CMS rimane una semplice data dichiarata e non viene mai passato al validatore.
Non si torna automaticamente alla data di firma per rendere valido un certificato
scaduto o un servizio ritirato. Non esiste ancora una prova attendibile del tempo.

Il parser A.1 conserva ora anche i DER di ogni `ServiceHistoryInstance`, con gli
stessi percorsi XML assoluti e le stesse difese dal wrapping. Il selettore sceglie
l’ultimo stato iniziato entro il tempo valutato, richiedendo date univoche e storico
precedente allo stato corrente, che non può iniziare dopo l’emissione della TL. Lo stato storico usa **le proprie** identità,
mai quelle correnti. Nessun certificato viene estratto da sottostrutture non firmate.
Le identità storiche sono cercate anche per individuare il prestatore di una vecchia
catena, ma un periodo già terminato non autorizza una catena oggi: il risultato
rimane non verificabile anche se lo stato passato era granted.
Il catalogo deve comunque essere temporalmente corrente per la valutazione.
Le date passate nei test sono clock di test espliciti; questa API non certifica
che una firma personale esistesse a quella data.

## Risultati e interfaccia

`CertificatePathResult` separa `verified`, `invalid`, `notVerifiable`, con tempo
valutato, percorso identificato da SHA-256/subject, prestatore, servizio, Paese,
identità dell’ancora, sequenza TL, stato e alternative verificate.

«Catena verificata» significa soltanto percorso crittografico valido verso
un’identità CA/QC autenticata nel perimetro valutato. «Catena non valida» indica
un’incompatibilità accertata in un percorso disponibile. Un percorso di errore è
un tentativo, non una catena accettata; il relativo prestatore è esplicitamente
presentato come **servizio candidato**. Mancanza di intermedi, servizio assente,
stato non ammesso, limiti o condizioni non supportate producono «non verificabile».
Un’alternativa valida prevale sui tentativi non validi; più servizi possono essere
registrati senza attribuire fiducia al nome del prestatore.

L’estrattore nativo CMS/PAdES preesistente passa il DER del firmatario selezionato
da SignerInfo e i certificati incorporati, senza cambiare i controlli d’integrità.
Swift verifica che il DER del firmatario corrisponda al fingerprint comunicato.
I nuovi campi del protocollo v1 sono opzionali per leggere un helper precedente;
senza DER la catena non è verificabile. Il limite dei metadati passa da 256 KiB a
8 MiB per contenere i certificati; restano 32 firme e 64 certificati per CMS,
64 KiB per DER. Input e contenuto firmato mantengono i limiti precedenti.

Il workspace acquisisce una sola istantanea TL autenticata per batch, valuta i
percorsi fuori dal MainActor e ricontrolla cancellazione/identificatore prima di
pubblicare i risultati. Il validatore ricontrolla la scadenza TL per ogni firma.
La sezione Verifica mostra integrità e catena separatamente, con revoca non ancora
verificata e qualificazione eIDAS non ancora determinata. I motori di firma,
PKCS#11 e appearance PDF non sono modificati. Le proprietà legacy `trust` restano
`notChecked`: il nuovo risultato di percorso non è un verdetto globale di fiducia.

## Limiti operativi

Massimo 64 intermedi in input, 2 MiB di DER complessivi, 2048 identità TL per
valutazione, 13 certificati per percorso, 4096 nodi e 128 tentativi per ancora.
La ricerca ha un budget di cinque secondi controllato fra ancore; il singolo
attempt OpenSSL è limitato da questi vincoli ma non interrotto al suo interno.
La cancellazione viene controllata fra ancore e prima della pubblicazione UI.
Nessuna ricerca di intermedi in rete o nel portachiavi; un intermedio assente può
quindi rendere una firma non verificabile anche se recuperabile da altre fonti.

Non sono implementati OCSP/CRL, validazione temporale avanzata, LTV, validazione
delle marche temporali, QCStatements/QES/QSCD o qualificazione eIDAS. Non viene
mai dichiarata una firma pienamente attendibile o qualificata.

## Preview e riproduzione

Build 4 arm64, target Mach-O macOS 13.0, bundle ID
`io.github.tiertoast.Signum.DevelopmentPreview.B4`. Cache e preferenze proprie:
`~/Library/Application Support/io.github.tiertoast.Signum.DevelopmentPreview.B4/TrustedLists/verified.json`.
Un primo bootstrap senza cache richiede rete; i successivi usano la cache A.2
riautenticata anche offline. Il nuovo percorso dell’app non sostituisce A.3 o Beta 0.4.

```sh
# Riutilizzare il prefix privato A.3, oppure prepararlo con prepare-preview.sh.
python3 scripts/build-preview-app.py --build-number 4 \
  --output '/nuovo/percorso/Signum 0.5 Development Preview — Build 4.app' \
  --native-prefix /percorso/prefix --cmake /percorso/cmake
python3 scripts/test-preview-bundle.py --build-number 4 \
  --bundle '/percorso/Signum 0.5 Development Preview — Build 4.app' \
  --output-root /nuovo/percorso/evidenze
# Diagnostica offline, stesso motore e catalogo di produzione:
'/percorso/Signum 0.5 Development Preview — Build 4.app/Contents/Helpers/SignumTrustProbe' \
  path /percorso/verified.json /percorso/documento.pdf
```

Firma ad hoc, nessuna notarizzazione o Developer ID. Le sei dylib private A.3
sono riutilizzate, senza una seconda OpenSSL e senza Java/Homebrew a runtime.
L’host di prova è arm64/macOS 27.2; **esecuzione su macOS 13 non effettuata**.
Non si deduce compatibilità runtime già collaudata dal deployment target.

Il corpus sintetico commesso contiene DER, CMS e TL XML firmate con chiavi di test
indipendenti dalle ancore OJ di produzione. `generate-path-fixtures.py` documenta la
rigenerazione e cancella le chiavi temporanee. I test coprono catene corrette,
alternative, duplicati, intermedi mancanti/alterati, scadenze, criticità, KU/EKU,
Basic Constraints, path length, Name Constraints, algoritmi, storico e dati TL
alterati/obsoleti, più il collegamento reale al workspace CAdES. Le regressioni
esistenti verificano anche DER e separazione della fiducia per CAdES e PAdES.
I risultati esatti, gli SHA e gli eventuali fallimenti sono nel rapporto finale.

Nessun merge, tag, release, GitHub Actions o code review generale. Nessuna modifica
a main, branch 0.5-A, Beta 0.4 o HalleyMac. STOP dopo la consegna; 0.5-C non avviata.

## Esiti locali della milestone

- 11 test di percorso e integrazione workspace superati, anche con AddressSanitizer
  (`detect_leaks=0`; bridge strumentato, librerie OpenSSL esterne non strumentate).
- Runner ufficiale Swift: 430 SignumCore, 18 TrustCore, 30 autenticazione/refresh,
  5 integrazione applicativa superati. Le ultime correzioni circoscritte al motore
  B e ai suoi fixture sono state poi ricontrollate nei suoi 11 test dedicati.
- PAdES: 81 casi Debug e 81 Release; PKCS#11: 58 casi provider e 2 CTest superati.
- 17 test degli script di packaging e 10 contratti del bundle superati.
- Refresh reale dal bundle rilocato: EU LOTL 397 / AgID 224, rilettura offline
  corrente, scadenza della coppia 24 marzo 2027 08:16:56 UTC.
- Nel bundle, il CMS sintetico mantiene `integrity=verified` e produce
  `chain=notVerifiable` contro le TL di produzione: nessuna CA sintetica autorizzata.

Nessun fallimento residuo nelle prove eseguite. Non si dichiara eseguito ogni
possibile gruppo opzionale del runner né una firma con token fisico. Il collaudo
interattivo della GUI non è stato effettuato; sono verificate compilazione,
workspace e avvio del main executable. Non è stata avviata una nuova code review.
