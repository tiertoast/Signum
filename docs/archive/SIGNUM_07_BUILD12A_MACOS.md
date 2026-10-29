# Signum 0.7 — Build 12A · Completamento macOS

26 ottobre 2026. Base Build 11 `a0492d2acc4b3260dafac372e7db13d02bdab31d`.
Riferimento obbligatorio: `SIGNUM_BUILD12A_FOUNDATION_REPORT_2026-10-26.md`
consegnato dall'utente insieme a `Signum-Build12A-Foundation.zip`.
SHA-256 ZIP: `73f9faa600d8d7ed3d0a0f70aefc8bd7b4b66c846145df053e980041b9fbef4a`.

## Provenienza e conservazione

Manifest della patch verificato: 31 file overlay, hash SHA-256 corrispondenti,
blob Git preesistenti coincidenti con la base Build 11, `git apply --check`
riuscito prima dell'applicazione. Applicazione su checkout separato già pulito,
Signum-DSS-Consolidation. Nessuna sovrascrittura del checkout Signum-0.7:
12 modifiche/file preesistenti conservati e inventariati separatamente. Due
percorsi si sovrappongono alla patch: Package.swift e PKCS11WorkerEntrypoint.swift;
non effettuare un aggiornamento automatico di quel checkout sporco.

## Intervento macOS

La foundation rimane documentata in SIGNUM_07_BUILD12A_FOUNDATION.md.
Nessun backend amministrativo reale: dispatcher C sempre rifiutante, protocollo
worker pubblico senza opcode mutanti, conferma Swift rifiutata prima dell'IPC,
Cambia PIN e Sblocca PIN disabilitati. Nessun codice reale richiesto.

Adeguato il driver locale alla toolchain Apple Silicon e alla configurazione
Xcode già presente: percorso scratch/triple coerente, dipendenze native private,
runtime actool ereditato solo dalla compilazione, mai dal preflight hardware.
Aggiornati i test dei metadati per il numero interno 14. Aggiunti contratti
macOS contro i worker effettivamente impacchettati, compreso l'helper PAdES,
con due moduli sintetici separati e contatori delle API.

Nessuna modifica agli algoritmi di firma/verifica, DSS, Trusted Lists, policy dei
certificati o HalleyMac. Lo shim PKCS#11 aggiunge solo una funzione pubblica di
lettura C_GetSlotInfo/C_GetTokenInfo; il worker esistente aggiunge il dispatch
verso il protocollo separato. Il coordinamento comune aggiunge una barriera
condivisa per operazioni ordinarie/esclusiva per amministrazione, trattenuta
fino al teardown. Non rende cooperanti vecchie build o programmi terzi.

## Test locali eseguiti prima del confezionamento finale

Mac Apple Silicon arm64, macOS 27.2, deployment target macOS 13.

| Prova | Esito |
| --- | --- |
| Compilazione app Debug e Release native | PASS |
| 8 nuovi test Swift PINManagementFoundationTests | PASS Debug e Release |
| Regressioni Swift selezionate | 149 SignumCore + 44 CertificateValidation = 193, zero fallimenti; includono gli 8 nuovi |
| 38 casi amministrativi C distinti | PASS Debug e Release; solo provider sintetici |
| 8 asserzioni barriera C multiprocesso/multiprovider | PASS entrambe; coordinamento e ACL Darwin reali |
| 5 casi lettura pubblica sullo shim reale | PASS entrambe; provider sintetico |
| Simboli produzione | PASS: nessun backend/accessor mock nel componente C produzione |
| Contratti worker amministrativo e helper impacchettati | 6 gruppi PASS Debug e Release |
| Test packaging Python | 18 PASS |
| Contratti metadati Build 12A | 3 PASS |
| UI Release preliminare | 30 cicli Impostazioni/Indietro; Firma, Verifica e Dispositivi, quattro schede, pannello app predefinite annullato; stesso processo, una toolbar |
| Verifica P7M di riferimento | Integrità verificata, certificatore in Trusted List, non revocato, QES alla data di verifica; nessuna firma creata |
| UI Sicurezza | Selezione esplicita, lettura pubblica, data/limiti/avvisi, entrambi i pulsanti mutanti disabilitati; snapshot invalidato al cambio schermata |

I 6 gruppi aggiunti provano: lettura senza sessione/login/firma/mutazione;
7 opcode mutanti respinti prima di caricare il provider; campi PIN/PUK
respinti; ordinario A blocca amministrativo B ma consente ordinario B;
amministrativo A blocca ordinario B, amministrativo B e helper PAdES B prima
di caricare il provider/autenticare; rilascio dopo teardown. Il test PAdES
verifica `rejectedBeforeAuthentication/busy` e assenza dell'output.

Una prima invocazione C Debug/Release concorrente ha fatto contendere la
barriera globale ai due harness, causando un fallimento di asserzione del test
Debug. Ripetuti in sequenza: entrambi PASS. Anche il driver completo li esegue
in sequenza. Non eseguire contemporaneamente questi harness sullo stesso utente.
La prima ricerca GUI ha segnalato una comunicazione incompleta; Aggiorna ha
rilevato DigitalDNA e due certificati. Non è stato nascosto l'errore né richiesto
un login diagnostico.

Il rapporto consegnato con l'app registra separatamente ricompilazioni pulite,
contratti sui bundle finali, Light/Dark, ridimensionamento, ulteriori cicli GUI,
verifica DMG e checksum effettivi. Questo documento non anticipa quei risultati.

## Matrice osservata, senza qualificazione delle mutazioni

| Accesso | Evidenza locale | Stato pubblico / limiti | Operazioni PIN/PUK |
| --- | --- | --- | --- |
| DigitalDNA / OpenSC | Un token, slot 0, due certificati; modulo dichiara 0.27; ricevute OpenSC 0.27.1 | Flag 0x40c: token e PIN utente inizializzati, login richiesto; nessun flag low/final/locked/must-change; 4–8 byte dichiarati | Non qualificate, sempre disabilitate |
| DigitalDNA / Bit4id | Modulo nel percorso noto non rilevato; ricevute Bit4id presenti non provano un modulo utilizzabile | Non acquisibili | Disabilitate |
| CNS / OpenSC | Nessuna CNS distinta osservata | Non acquisiti | Disabilitate |
| CNS / Bit4id | Nessuna CNS distinta e modulo non rilevato | Non acquisiti | Disabilitate |

Modulo OpenSC osservato `/Library/OpenSC/lib/opensc-pkcs11.so`, SHA-256
`94e62a84eb8bc011fea439f74fa704ebb653766b50afba64b2bc906ee5d855b7`, firma
ad hoc senza TeamIdentifier. Dipende anche da una libreria crypto in un percorso
locale preesistente: ricevute e versione dichiarata non attestano l'autenticità
né la corrispondenza del binario al pacchetto ufficiale. Non modificato.
Identità stat, seriale pubblico, route e fingerprint completi rimangono solo
nell'evidenza locale; non pubblicare DER, identificativi personali o seriali nella PR.
Driver/applicazione interna/AID/auth ID/dominio PIN e significato PUK non
qualificati; nessun contatore residuo dedotto. L'assenza di flag di blocco non
prova l'utilizzabilità del PIN e i limiti non autorizzano operazioni.

## Consegna e arresto

Nome: Signum 0.7 Development Preview — Build 12A, versione 0.7.0, build 14,
ID `io.github.tiertoast.Signum.DevelopmentPreview.V07.B14`.
Firma ad hoc per collaudo locale; nessuna notarizzazione/release pubblica.
Pubblicare soltanto il commit sul branch di sviluppo e aggiornare PR #8;
nessun merge/tag/Actions. STOP prima di qualsiasi mutazione reale.
