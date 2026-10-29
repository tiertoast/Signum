# Signum 0.5-C — Binding SignerInfo e revisione

Baseline `b05ff5d42bd6fa2c5fc99ac397fa732a55853b7f`; branch
`feature/signum-0.5cd-complete-validation`. Questa integrazione riutilizza le
primitive OCSP/CRL/RFC 3161 e la cache della base C. Nessuna modifica a GUI,
firma, appearance, PKCS#11 o qualificazione. Il documento del gate precedente
resta uno storico della baseline, non una descrizione del nuovo binding.

## Estrazione e provenienza

L’helper nativo restituisce per ciascun SignerInfo SignatureValue, indice nel CMS,
certificato selezionato, certificati incorporati, attributi firmati/non firmati
come OID e DER, signature-time-stamp e revocationValues. Le BasicOCSPResponse
incorporate vengono convertite in OCSPResponse senza cambiarne i dati firmati.
CRL globali SignedData vengono esposte separatamente come non associate.

La chiave strutturale SHA-256 di SignatureValue distingue i contenitori; il decoder
Swift ne ricontrolla il digest. Questa chiave non autentica un attributo unsigned.
L’impronta RFC 3161 viene confrontata con il digest dei **byte di SignatureValue**,
non con documento, certificato o signingTime. Per una risposta OCSP si confrontano
CertID completo e destinatario; per una CRL l’emittente e poi firma/ambito. La stessa
risposta non viene assegnata a un altro SignerInfo solo perché è nel CMS.

Per PAdES si conserva la revisione firmata ottenuta dai quattro numeri ByteRange,
si ricontrolla l’esatto intervallo Contents e si riapre il prefisso firmato: deve
contenere un’unica corrispondenza della stessa firma e ByteRange. Gli oggetti DSS
si leggono nel proprio snapshot PDF, non risolvendo lo storico attraverso l’ultimo
xref. I VRI vengono associati soltanto mediante la chiave SHA-1 maiuscola dei byte
Contents completi, padding incluso, con una sola firma destinataria verificata.
Si registrano separatamente `signatureRevisionEnd` e `sourceRevisionEnd`; una VRI
successiva può riferirsi a una revisione precedente. Chiavi sconosciute o ambigue,
DSS globale e CRL CMS globali restano `unassociated` e non vengono consumati per
default. SHA-1 qui è un identificatore VRI, non un algoritmo di firma ammesso.

Limiti: 32 firme, 64 attributi per categoria, quattro token per SignerInfo,
attributo/oggetto estratto entro 1 MiB, 64 oggetti di evidenza per raccolta,
metadati complessivi entro 8 MiB. Restano isolamento, timeout e limite RSS
preesistenti dell’helper. Errori di estrazione hanno una motivazione separata e
non trasformano una firma crittograficamente valida in un giudizio di fiducia.

## TSA e tempo

`TSAAuthorization` seleziona identità proprie dei servizi TSA/TST o TSA/QTST granted
nelle TL autenticate. Non seleziona CA/QC come sostituto di un servizio TSA e non
usa il portachiavi. La TL deve essere corrente all’osservazione; lo stato e
l’identità del servizio devono coprire la finestra temporale del token. Storici
ambigui o senza copertura non autorizzano un’ancora.

Il percorso usa lo stesso validatore C della B con scopo OpenSSL timestamp,
compresi ancoraggio diretto a un’identità TSA non CA e percorsi intermedi. Il
profilo documentSigning della B è conservato per le firme personali. La primitiva
RFC 3161 esistente verifica firma, ESS, impronta ed EKU TSA. Il percorso viene
controllato anche agli estremi della finestra di accuratezza dichiarata.

Il profilo integrato richiede genTime a secondi interi, accuratezza esplicita entro
60 secondi più frazioni millisecondi/microsecondi, nessuna estensione TSTInfo non
supportata. Senza una finestra utilizzabile il risultato resta indeterminato.
`provenTime` è il **limite superiore** della finestra, non un istante esatto di
creazione della firma. Per produrlo servono anche evidenze correnti di revoca per
il percorso TSA, compresa la TSA se è essa stessa l’ancora TL; devono coprire
l’intera finestra. Una revoca successiva non viene usata per inventare un esito
storico favorevole. La validità al tempo del token non implica che il certificato
personale sia valido oggi; i risultati restano indipendenti.

## Client, cache e output

`RevocationSession` riceve soltanto certificati/emittenti verificati. Estrae AIA/CDP
dal certificato, prepara una richiesta OCSP CertID SHA-256, usa timeout, pin DNS,
nessun redirect e limiti di rete. La cache esistente viene riautenticata a ogni
uso. Dati non associati non alimentano la cache. Offline, assenza di rete,
risposte alterate/obsolete o copertura incompleta producono indeterminato, non good.
La revoca autenticata di un certificato pertinente prevale su risposte good e
viene conservata per i successivi controlli offline. Una risposta good non
cancella una revoca corrente. Il clock esplicito avanza col tempo monotono della
sessione; la scadenza TL viene ricontrollata prima di restituire gli esiti.
Vedere [informativa OCSP](SIGNUM_0.5C_OCSP_PRIVACY.md).

`SignatureEvidenceValidationService.validate` produce un risultato per firma con
revoca (`good/revoked/indeterminate`), tempo (`proven/notProven/invalid/indeterminate`),
motivazioni e inventario `associated/unassociated`. signingTime dichiarato resta
un campo separato. Le proprietà legacy del rapporto di integrità non vengono
promosse a esiti globali. Il servizio è finito, cancellabile e senza scheduler.

Diagnostica, usando l’helper affiancato al probe:

```sh
SignumTrustProbe evidence /percorso/TrustedLists/verified.json documento.pdf
SignumTrustProbe evidence /percorso/TrustedLists/verified.json documento.p7m --online
```

Il probe usa esclusivamente il catalogo di produzione riautenticato LOTL/AgID.
Le ancore sintetiche dei test non entrano in questa modalità. La GUI rimane quella
della B e non viene collegata ai nuovi esiti in questa consegna.

## Test e limiti

Il corpus Binding riutilizza il generatore C; chiavi private soltanto in memoria o
in una directory temporanea rimossa. CMS a due SignerInfo e PDF a due revisioni,
con timestamp e revoche diverse per firma, sono commessi come fixture pubbliche.
Un’ulteriore revisione PDF contiene VRI distinti, DSS globale e VRI sconosciuta.
I test confrontano il destinatario, scambiano contenitori, ricollocano una risposta
OCSP sotto una chiave strutturale diversa e verificano impronte non corrispondenti,
revoche, alterazioni, scadenze, TSA non autorizzata, cache, rete assente e cancellazione.

Le prove di trasporto positivo e rete assente usano risposte controllate iniettate;
non si dichiara un collaudo OCSP su documenti personali o su tutti i responder
pubblici. La politica DNS/URL è testata separatamente. La sorgente AIA/CDP, le
primitive e il binding vengono eseguiti realmente dai test.

Non sono implementati document timestamp PDF, archive timestamp, DSS/VRI-LTV
completo, revoca storica con POE/archival cutoff, CRL indirette/delta, responder
senza no-check con verifica ricorsiva o criteri di qualificazione. Dati non
supportati restano indeterminati. Nessuna dichiarazione LTV/PAdES-LT/LTA, QES o QSCD.
Il target resta macOS 13; le prove sono su macOS 27.2 arm64, senza dedurre
un’esecuzione su macOS 13. Nessuna nuova Preview o modifica a quelle esistenti.

Riferimenti: [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html),
[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html),
[OpenSSL CMS attributes](https://docs.openssl.org/3.5/man3/CMS_signed_get_attr/),
[ETSI TS 119 142-1, §5.4.2](https://www.etsi.org/deliver/etsi_ts/119100_119199/11914201/01.00.01_60/ts_11914201v010001p.pdf).

## Esiti di consegna

Campagna completa normale eseguita una sola volta: runner ufficiale Swift
(430 SignumCore, 18 TrustCore, 30 Authentication, 5 integrazione TL, 34
CertificateValidation), PAdES 81 Debug e 81 Release, PKCS#11 58 casi provider e
2 contratti loader: tutti superati, nessuno skip. Gli affinamenti C sul clock e
sulla persistenza della revoca sono stati verificati nel solo target modificato;
la campagna completa non è stata ripetuta.

ASan e TSan eseguiti una volta ciascuno alla fine: 34 test CertificateValidation
più due test Core di estrazione/binding e tre documenti estratti dal rispettivo
helper nativo strumentato. Tutti superati. Le dipendenze OpenSSL/PoDoFo esterne
non sono strumentate; ASan usa detect_leaks=0. Nessun sanitizzatore sui target TL
o PKCS#11 non modificati. Nessuna prova con token fisico.

Due errori iniziali di compilazione distinti (stack tipizzato OpenSSL e un try nel
test Swift) sono stati risolti al primo intervento; nessuna causa si è ripetuta
per due tentativi. Nessun fallimento XCTest o residuo nella campagna finale.
