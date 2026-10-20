# Signum 0.5-C — Evidenze di revoca e tempo: gate non superato

Baseline: `da1fbd466e8ab7684f73967994d184dab957218b`.
Branch: `feature/signum-0.5cd-complete-validation`.

**Consegna parziale della C: primitive native e corpus verificati. La validazione
completa dei documenti non è implementata. Gate C non superato; D non iniziata.**
Questo documento non certifica il completamento delle milestone C/D.

## Codice riutilizzato e aggiunto

Si riutilizzano `SignumCertificateValidation`, il bridge `CCertificatePath` e
OpenSSL 3.5.6 della B. Il verificatore di percorsi B non viene riscritto. I nuovi
file C verificano esclusivamente evidenze fornite dal chiamante; non caricano
store di sistema, file di CA, AIA o risorse di rete. Nessuna nuova dipendenza
nativa o Java. Nessuna modifica ai motori CMS/PDF di firma, PKCS#11 o appearance.

`RevocationEvidenceVerifier` distingue `good`, `revoked`, `unknown`, `invalid`,
`stale`. **Sono esiti della singola evidenza per una coppia certificato/emittente,
non esiti di revoca dell'intera firma o del percorso.** Il chiamante deve prima
verificare la catena e poi coprire tutti i certificati pertinenti. Le date del
risultato non costituiscono una prova autonoma: non usare metadati di un risultato
non autenticato per dichiarare fiducia.

Profilo implementato:

- DER esatto, senza coda o decodifica parziale, certificati entro 64 KiB, evidenze
  entro 8 MiB; firme e corrispondenza della coppia certificato/emittente.
- OCSP: risposta successful, firma verificata con `OCSP_basic_verify`, store con
  il solo emittente esplicito, nessun flag che ignora firma o autorizzazione.
  Identificazione tramite CertID completo: issuerNameHash, issuerKeyHash e seriale;
  SHA-1 è ammesso solo per identificare il CertID, non per firmare l'evidenza.
  CertID SHA-256 supportato. Duplicati corrispondenti rifiutati.
- Responder delegato: autorizzazione OpenSSL, EKU, validità temporale e `no-check`
  non critico con valore ASN.1 NULL esatto. Se manca no-check, lo stato è unknown:
  la revoca del responder richiede una verifica aggiuntiva non ancora implementata.
- OCSP: controllo thisUpdate/nextUpdate/producedAt, rifiuto di date future,
  intervalli scaduti/incoerenti, limite di età sette giorni. nextUpdate assente
  resta unknown nel profilo scelto, anche se RFC 6960 lo rende opzionale.
- CRL: firma dell'emittente effettivo, DN, AKID se presente, KU cRLSign e validità
  dell'emittente, lista completa diretta, controllo thisUpdate/nextUpdate, età
  massima 31 giorni. La presenza del seriale produce revoked; l'assenza può
  produrre good soltanto per una CRL completa autenticata nel profilo.
- CRL delta, indirette, IDP/ambito ristretto, certificateIssuer, removeFromCRL e
  estensioni critiche non supportate producono unknown. Non si usa una lista
  parziale per provare l'assenza di revoca. Seriali corrispondenti duplicati e date
  di revoca impossibili sono rifiutati.
- Limiti sulle chiavi, sugli esponenti RSA, su certificati OCSP incorporati (16),
  SingleResponses (128), voci CRL (100000). Policy SHA-256/384/512 e chiavi almeno
  112 bit di sicurezza; RSA oltre 8192 bit ed esponenti oltre 32 bit non supportati.
  Per le firme delle evidenze RSA-PSS non è ancora supportato: manca
  l'interpretazione esplicita della relativa policy dei parametri.

`RevocationEvidenceCache` conserva evidenze DER e identità esatte, mai un booleano
persistito assunto attendibile. Le letture sono limitate, con O_NOFOLLOW e fstat;
lo store verifica prima di scrivere, serializza scrittori tramite lock laterale
non bloccante e usa sostituzione atomica. Una risposta alterata non sostituisce
quella precedente. Risposte correnti autenticate contraddittorie provocano un
errore e conservazione del file precedente, senza restituire good. Un thisUpdate
precedente non sostituisce un'evidenza corrente più recente dello stesso stato.
Certificati ed evidenze sono conservati in chiaro, con directory 0700 e file
0600; la cache non è cifrata. Non è una cache applicativa completa: mancano quota globale, espulsione e un
registro persistente di continuità oltre la scadenza delle evidenze. Nessuna
protezione da cancellazione completa della storia da parte del proprietario del
filesystem, né promessa di durabilità fsync in caso di perdita di alimentazione.

`TimestampEvidenceVerifier` verifica token ContentInfo RFC 3161 (non il contenitore
TimeStampResp), versione, firma, ESSCertID/v2, impronta SHA-256/384/512 dei **byte
esatti forniti**, EKU TSA e percorso rispetto a un'ancora esplicita. Controlla
`genTime` non futuro e il percorso a quella data. Supporta un firmatario,
precisione genTime a secondi interi, fino a 16 certificati incorporati e token
entro 1 MiB. Precisione frazionaria ed estensioni TSTInfo restano unsupported.
Il tempo del token non è un istante di firma accertato; l'accuratezza dichiarata
nel token non viene trasformata in una finestra di validazione storica.
L'esito positivo si chiama intenzionalmente **authenticatedToken**, non verified
signature time. L'API non verifica l'autorizzazione della TSA nella TL, la revoca
della TSA o la provenienza dei byte dal SignerInfo del documento. Il chiamante
può fornire una propria ancora soltanto a questa primitiva: nessuna ancora
arbitraria viene introdotta nella produzione LOTL/AgID.

## Blocchi sostanziali del gate C

Il passaggio dalle primitive alla validazione del documento richiede ancora i
seguenti lavori integrati e relativi test. Non si tratta di dipendenze native
mancanti o di un requisito di autorizzazione dell'utente.

1. **Legame documento/evidenze non disponibile nel protocollo corrente.** L'helper
   B esporta certificati e signingTime, ma non i byte della SignatureValue,
   i token unsigned del relativo SignerInfo, revocationValues, né gli oggetti DSS/VRI
   associati alla revisione PDF. Non è possibile usare le nuove API sull'app e
   dichiarare coperta la firma senza tale collegamento e senza test su firme
   multiple, revisioni e sostituzione delle evidenze. L'integrità CMS/PDF esistente
   rimane distinta e non viene modificata per aggirare questo limite.
2. **Percorso TSA e cronologia integrata non implementati.** Il profilo B seleziona
   CA/QC e documentSigning, mentre le TSA richiedono identità/servizi, scopi ed EKU
   specifici. Il controllo di freschezza TL e il tempo della catena condividono
   attualmente `now`. Occorre distinguere osservazione corrente, copertura storica
   autenticata ed evidenza di esistenza della firma. Il semplice genTime di un
   token crittograficamente valido non consente di ignorare revoca TSA, inaccuratezza
   temporale, revoche antecedenti o lacune dello storico TL. In questo stato non
   viene retrodatata alcuna catena e signingTime non diventa attendibile.
3. **Acquisizione di rete controllata non implementata.** Non esiste ancora un
   client OCSP/CRL con autorizzazione degli endpoint ottenuti da certificati già
   validati, difese verso indirizzi locali/redirect, limiti per sessione, cancellazione
   e controllo di freschezza all'arrivo. La primitiva non esegue richieste. Non
   si riutilizza il downloader LOTL: la sua allowlist è specifica e non viene ampliata
   a URL arbitrari. Mancano orchestrazione cache/rete, copertura dell'intero percorso
   e riconciliazione fra evidenze OCSP e CRL contrastanti.
4. **Gate applicativo e differenziale assente.** Non sono verificati aggiornamenti
   di revoca online, documenti CAdES/PAdES con timestamp e revoca combinati, profili
   storici o confronti di esiti con DSS. Gli eventuali test verdi delle primitive
   non chiudono queste voci. La UI mantiene gli esiti della B e non mostra i nuovi
   esiti come validazione completa.

Questi blocchi impediscono di considerare completata la C. Per il gate richiesto
**non si avvia la D**, non si classificano QES/QSCD, non si produce Build 5 e non si
rivendicano LTV/PAdES-LT/LTA. Le Preview precedenti restano isolate e conservate.
La prosecuzione richiede lavoro nella C, non una nuova code review generale.

## Privacy

Questa consegna non interroga responder OCSP o endpoint CRL. Quando verrà attivata
l'acquisizione, una richiesta OCSP comunicherà al responder identificativi del
certificato (emittente e seriale) e dati di rete come IP e orario della richiesta;
può quindi rendere osservabile l'interesse per un certificato. Il download di una
CRL normalmente richiede una lista dell'emittente, senza il seriale specifico.
Cache e richieste limitate ridurranno le interrogazioni ripetute. Prima di esporre
il servizio nell'app occorrono una politica esplicita di rete e un'informazione
comprensibile all'utente. Nessun documento personale è stato caricato su DSS.

## Test e riproduzione

Il corpus pubblico `Tests/SignumCertificateValidationTests/Fixtures/Revocation`
contiene certificati sintetici, OCSP, CRL e token RFC 3161; nessuna chiave privata.
`clock.json` fissa il tempo dei test. `manifest.json` contiene gli SHA-256.
La rigenerazione usa cryptography 50.0.2 e OpenSSL 3.5.6 solo come strumenti di
sviluppo; genera nuove chiavi casuali, poi le elimina. La riproducibilità dei test
usa i DER commessi e il clock registrato, non il byte-identical rebuild del corpus.

```sh
SIGNUM_TRUST_NATIVE_PREFIX=/percorso/prefix \
  Tools/TrustPoC/native.sh test --filter 'RevocationEvidenceTests|TimestampEvidenceTests'
# Rigenerazione facoltativa: Python con cryptography 50.0.2 e OpenSSL di sviluppo.
SIGNUM_FIXTURE_OPENSSL=/percorso/prefix/bin/openssl \
  python3 Tools/TrustPoC/generate-revocation-fixtures.py
```

Copertura dedicata: good/revoked/unknown, alterazione, emittente/responder errati,
responder autorizzato/no-check assente, scadenza e futuro, nextUpdate assente,
CRL delta/ristretta/critica, DER malformato/troncato/con coda, limiti, cache offline,
cache alterata/symlink, conservazione del file valido, contraddizioni; timestamp
valido con CA o identità TSA diretta, ancora errata, impronta errata, token
contraffatto, assente/futuro, CMS correttamente firmati privi di ESS o con EKU TSA
incompatibile. Le firme di questi ultimi token sono genuine: il rifiuto verifica
obblighi specifici oltre al controllo della sola firma.

I risultati del runner ufficiale, sanitizzatori e build target macOS 13 sono
riportati nel rapporto locale di consegna. Non si dichiara eseguita l'app su
macOS 13; l'host di test è arm64/macOS 27.2. Nessuna Build 5 è stata confezionata.

## Riferimenti consultati e differenze rispetto a DSS

- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html): autorizzazione responder,
  identificazione e validità delle risposte. Questo profilo restringe gli intervalli
  e richiede nextUpdate; non costituisce copertura integrale dello standard.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html): certificati e CRL.
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html): token temporale, impronta,
  identità e requisiti TSA.
- [OpenSSL 3.5: OCSP](https://docs.openssl.org/3.5/man3/OCSP_resp_find_status/),
  [TS_VERIFY_CTX](https://docs.openssl.org/3.5/man3/TS_VERIFY_CTX/).
- [DSS: documentazione ufficiale](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html):
  distingue signingTime, proof of existence, best-signature-time e validazione
  storica. Qui esiste soltanto la verifica di singole evidenze e non l'algoritmo
  integrato di validazione temporale descritto dal riferimento. **Confronto
  documentale effettuato; confronto eseguibile degli esiti DSS non effettuato.**

Nessun merge, tag, release, GitHub Action, modifica a main/Beta 0.4/HalleyMac o
ai branch precedenti. Il commit di questa consegna è un salvataggio della base C,
non il commit di superamento del gate e non un'autorizzazione a iniziare la D.

## Esiti locali di questa consegna

- 17 nuovi test: 12 revoca/cache e 5 token temporali. La suite dedicata finale,
  inclusi gli 11 test B, supera 28 casi sia normalmente sia con AddressSanitizer
  (`detect_leaks=0`; librerie native esterne non strumentate).
- Runner ufficiale `--group complete` superato: Swift completo, PAdES Debug e
  Release (81 casi ciascuno), PKCS#11 (58 casi provider e due contratti loader),
  17 test packaging, selezioni Swift ASan/TSan e gruppi nativi ASan/TSan previsti
  dal runner. Nessuno skip o fallimento nei gruppi eseguiti. La prima compilazione
  della suite completa includeva 26 test CertificateValidation; i due ulteriori
  test e gli affinamenti circoscritti alla C sono coperti dai 28 test finali dedicati.
- 430 SignumCore, 18 TrustCore, 30 autenticazione/refresh e 5 integrazione TL
  superati nella suite completa. Non vengono dichiarati coperti i percorsi C
  applicativi ancora mancanti dal solo passaggio delle regressioni della B.
- Sette controlli CLI OpenSSL confermano good/revoked OCSP, firma CRL e accettazione
  o rifiuto dei token. Usano la stessa libreria e non sostituiscono il confronto DSS.
- Build Release del modulo arm64/macOS 13.0 superata; oggetti nativi con minos 13.0,
  compilazione C con `-Wall -Wextra -Werror` senza diagnostiche e simboli necessari
  presenti nella libcrypto privata A.3. Non è una verifica di bundle Build 5.

Nessun fallimento residuo nei controlli completati; restano i blocchi funzionali
elencati sopra. Nessuna prova di esecuzione su macOS 13, nessun confronto eseguibile
DSS e nessuna Preview 5. Si consegna un commit della base C con gate ancora aperto.
