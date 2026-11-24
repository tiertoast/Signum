# Signum — PIN/PUK Backend Qualification

26 ottobre 2026 · base Build 12B `ed176ff841459c0f5611a9a9f205d8c2314c50d7`.
Repository `tiertoast/Signum`, PR #8 da mantenere Draft.

## Decisione

**Preferire il middleware ufficiale Bit4id/InfoCamere come candidato di
integrazione, subordinatamente al supporto documentato per il modello esatto.
Oggi non è qualificato alcun backend amministrativo da abilitare in Signum.**

Il cambio PIN dispone di una possibile interfaccia pubblica standard, C_SetPIN;
la sua esistenza non documenta il comportamento della specifica DigitalDNA.
Per lo sblocco con PUK manca nelle fonti consultate un contratto macOS specifico
sufficiente a scegliere una sequenza sicura. Il flusso utente delle applicazioni
ufficiali è documentato; la sua automazione programmatica non lo è nelle fonti
reperite. OpenSC locale resta un candidato distinto non qualificato, senza
fallback automatico fra provider.

Consegna esclusivamente di indagine e documentazione. Nessuno sviluppo operativo,
nuova build, installazione o abilitazione PIN/PUK.

## 1. Che cosa è presente sul Mac

Sono state confrontate ricevute Installer, relativi elenchi payload, percorsi
standard delle applicazioni/librerie, indice Spotlight e una copia d'archivio
precedentemente estratta. La versione 1.0 sotto indicata è quella della
**ricevuta del pacchetto**, non una versione accertata del middleware.

| Ricevuta | Data registrata, Europe/Rome | Versione pacchetto | Riscontro nei percorsi registrati |
| --- | --- | --- | --- |
| com.bit4id.pkg.infocamere | 28/04/2026 20:55 | 1.0 | App Firma4ng e librerie individuate nel BOM non presenti |
| com.bit4id.pkg.infocameresigndesktop | 14/10/2026 16:15 | 1.0 | App, librerie e componente CTK individuati nel BOM non presenti |
| com.bit4id.pkg.firmafacile | 14/10/2026 16:06 | 1.0 | App Firma4ng e librerie individuate nel BOM non presenti |
| com.bit4id.ukc | 28/04/2026 20:55 | 1.0 | Directory UniversalKeychain e componenti individuati nel BOM non presenti |

Non risultano attualmente `/Applications/InfoCamere Sign Desktop.app`,
`/Applications/Firma4ng.app`, `/Applications/UniversalKeychain`,
`/Applications/bit4id`, `/Applications/PKIManager-bit4id.app` o `/Library/bit4id`.
Nessuno dei moduli Bit4id individuati nei quattro elenchi payload è presente
alla posizione registrata. Restano ricevute di installazioni precedenti:
non dimostrano un'installazione operativa oggi e non spiegano la causa
dell'assenza: rimozione, spostamento o installazione incompleta. Non è stato eseguito alcun disinstallatore.

### Perché manca il vecchio libbit4xpki.dylib

`/Library/bit4id/pkcs11/libbit4xpki.dylib` è un percorso documentato per il
kit Universal Middleware; il produttore documenta anche una libreria dentro
PKIManager-bit4id.app. [Manuale Bit4id macOS, §1.3](https://cdn.bit4id.com/es/middleware/MacOs/MacOS.html).

I BOM locali consultati registrano invece, fra gli altri:

- InfoCamere: `/Applications/InfoCamere Sign Desktop.app/Contents/Resources/etc/sign_engine/libbit4xpki.dylib`;
- componente CTK: `/Applications/bit4id/.bit4ctkapp2.app/Contents/PlugIns/bit4ctktoken.appex/Contents/Resources/libbit4xpki.dylib`;
- Firma4ng: `/Applications/Firma4ng.app/Contents/Resources/libbit4xpki.dylib`;
- altre distribuzioni precedenti: librerie in bundle Firma4ng annidati e Diagnostics;
- UniversalKeychain: una famiglia di componenti idprovider_ddna, BLEScard e UKCTokenExt, non automaticamente equivalente al vecchio modulo globale.

Quindi l'assenza ha due aspetti distinti: **distribuzioni con percorsi diversi**
e **payload oggi assente nei percorsi registrati**. Non è un errore di lookup
risolvibile creando un link simbolico. L'assenza dal BOM del vecchio percorso
non esclude che un vecchio script post-installazione potesse crearvi file/link;
non si ricostruisce una disinstallazione dalla sola ricevuta.

### Copia d'archivio realmente trovata

Spotlight ha indicato una copia estratta di Firma4ng sotto un precedente spazio
di lavoro in Documents/Codex, con percorso finale
`firma4ng-full/Payload/Applications/Firma4ng.app/Contents/Resources/libbit4xpki.dylib`.
È un **payload d'archivio**, non un'app installata né una route configurata in Signum.

Controlli statici effettuati, senza caricamento del modulo:

| Dato | Riscontro |
| --- | --- |
| Architetture | Mach-O bundle universal x86_64 e arm64 |
| Firma | Developer ID Application: Bit4id srl; TeamIdentifier 7GWNHU58JZ |
| Timestamp firma riportato | 15 settembre 2025 |
| Verifica locale codesign --verify --strict | Riuscita |
| SHA-256 libreria | e94cdb8ca5fd5fb6528a19c9282e212d0124420d124ec66c5f24e3774c347263 |
| Entry point standard osservati | C_GetFunctionList, C_GetInfo, C_SetPIN, C_InitPIN |
| Estensioni non standard | Presenti; contratto non reperito, non utilizzate |
| Versione funzionale del middleware | Non accertata: plist app senza versione utile e nessuna interrogazione runtime |

La firma identifica il componente e la sua integrità locale; non prova
notarizzazione attuale, stato di revoca online, provenienza dell'intero archivio,
licenza d'uso esterno o compatibilità amministrativa del dispositivo. arm64 ed
export standard non dimostrano caricabilità nel bundle Signum con le policy
finali né correttezza del cambio/sblocco. Non è stata caricata neppure per C_GetInfo.

La ricerca non è una perizia esaustiva di ogni volume/cartella. Il volume
DigitalDNA era visibile; la scansione dei suoi file non ha completato ed è stata
interrotta fermando soltanto il processo di lettura avviato per questa indagine.
Nessun eseguibile dal volume è stato avviato e nessun volume è stato espulso.

## 2. Documentazione e interfacce effettivamente documentate

### Flusso utente InfoCamere — documentato

Il Manuale InfoCamere Sign Desktop v3, 22 aprile 2026, pagine 23–24, distingue
Cambio PIN (attuale, nuovo e conferma) e Sblocco PIN (PUK, nuovo e conferma).
Il manuale è stato riscaricato e ne sono state lette quelle pagine. SHA-256:
`c2c8f64abefcc84821bcbdef93943ea3f5985e98b73749285d667f4f6cdcd4d3`.
Il contratto descritto è quello della **GUI utilizzata dall'operatore**: nelle
sezioni consultate non definisce un SDK amministrativo per un'app esterna,
un endpoint IPC, una CLI per segreti o una garanzia di atomicità IAS/CNS.
[Manuale ufficiale](https://id.infocamere.it/assets/documenti/Manuale_infocamere_sign_desktop.pdf).

Il manuale Bit4id macOS documenta PKI Manager come applicazione di gestione e
PKCS#11/CryptoTokenKit come componenti del kit; i percorsi variano rispetto al
payload InfoCamere. Questo documenta prodotti e funzioni utente, non un profilo
PIN/PUK della DigitalDNA InfoCamere sotto un determinato firmware.
[Manuale ufficiale Bit4id](https://cdn.bit4id.com/es/middleware/MacOs/MacOS.html).

### PKCS#11 — API pubblica, profilo dispositivo ancora necessario

C_SetPIN è un'API standard e può essere il punto di integrazione per il cambio
PIN, se Bit4id ne documenta il profilo specifico. In PKCS#11 il ruolo/sessione
influenza il destinatario: non va scelta una sequenza di login per tentativi.
C_InitPIN inizializza il PIN utente nello stato R/W SO Functions; lo standard
non assegna universalmente al PUK della DigitalDNA il significato di SO PIN.
Non autorizza quindi ad assumere `PUK → CKU_SO → C_InitPIN` come sblocco.
[OASIS PKCS#11 2.40, C_SetPIN/C_InitPIN](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

**Risposta distinta:** interfaccia pubblica generica per il cambio presente;
procedura qualificata per questa DigitalDNA non dimostrata. Sblocco PUK
programmatico non determinato senza specifica del produttore. Le estensioni
esportate dal binario non diventano API supportate per il solo nome del simbolo.

### SDK e interfacce commerciali — cosa è stato trovato

- La scheda DigitalDNA descrive un SDK **mobile Android/iOS** e Universal
  Middleware per sistemi desktop. Non fornisce un contratto macOS per le
  operazioni amministrative qui richieste. La portabilità su Apple Silicon non
  si deduce dal supporto iOS. [Scheda DigitalDNA](https://www.bit4id.com/wp-content/uploads/2023/04/digitalDNA_DS_4.2_EN.pdf).
- 4identity pubblicizza API Web Intent per firma, autenticazione e timestamp,
  con manuali d'integrazione. Le pagine/datasheet consultati non documentano
  comandi amministrativi PIN/PUK per DigitalDNA macOS. [4identity Web SDK](https://www.bit4id.com/en/solutions/4identity/).
- Non è stato reperito, nelle fonti pubbliche e nei materiali locali esaminati,
  un SDK macOS PIN/PUK specifico con header, ABI, mapping dei domini, codici di
  esito e garanzie di recupero sufficienti. **Non equivale a provare che non
  esista:** potrebbe essere riservato agli integratori/licenziatari.

Ricerca mirata su bit4id.com, cdn.bit4id.com, support.bit4id.com,
servicedesk.bit4id.com e id.infocamere.it, includendo libbit4xpki, SDK,
C_SetPIN, C_InitPIN, DigitalDNA e PIN/PUK. Non sono state adottate istruzioni
ricavate da vecchi documenti di altri prodotti/OS o da esempi non ufficiali.
Nessun account integratore è stato creato e nessuna richiesta è stata inviata.

### Interfacce escluse dalla proposta

Nessun utilizzo di endpoint locali interni di Sign Desktop Engine, protocollo
privato di UniversalKeychain, comandi scoperti nei bundle, automazione dei
campi segreti della GUI o APDU costruite per tentativi. Un'estensione CTK,
un framework BLE o un engine presente in un payload non costituisce un
contratto pubblico di amministrazione utilizzabile da Signum.

## 3. Domini PIN, CNS/IAS e recupero parziale

Certificato di firma, certificato CNS, route PKCS#11 e dominio amministrativo
non sono sinonimi. La condivisione di un titolare o del testo del PIN non prova
che esista un solo oggetto PIN fisico. Anche una singola GUI di gestione può
nascondere operazioni su più applicazioni.

Il modello dei sorgenti ChipDocIT analizzati in Build 12B distingue IAS e CNS
con riferimenti e applicazioni diversi, prevedendo sincronizzazione e possibili
azioni compensative. È un'evidenza sul **sorgente esaminato**, non una specifica
ufficiale del modulo proprietario Bit4id né una prova del binario OpenSC installato.
[Driver sorgente alla revisione fissata](https://github.com/OpenSC/OpenSC/blob/ccfa7600f7c7ae249118d5f301e679e476a004a5/src/libopensc/card-chipdocit.c).

Nelle fonti ufficiali consultate non è stata reperita una garanzia specifica
che un cambio/sblocco interrotto lasci sempre entrambi i domini coerenti, né
una procedura verificabile per recuperare ogni possibile aggiornamento parziale
su questa combinazione middleware/firmware. Non si presume che il normale
Sblocca PIN della GUI sani automaticamente una divergenza IAS/CNS.

Prima dell'integrazione servono dal produttore: domini effettivamente coinvolti,
ordine dei passi, eventuali VERIFY/rollback interni, consumo dei tentativi,
semantica degli errori dopo un primo aggiornamento e recupero dei singoli stati.
Un errore non prova assenza di modifiche, un timeout non autorizza il reinvio,
e un cleanup fallito non annulla un cambio già avvenuto. Nessuna autenticazione
diagnostica con vecchio/nuovo PIN è proposta per scoprirne l'esito.

## 4. Percorso OpenSC locale, valutato separatamente

Il modulo attuale ha lo stesso hash registrato in Build 12B:
`94e62a84eb8bc011fea439f74fa704ebb653766b50afba64b2bc906ee5d855b7`.
Anche libopensc.13.dylib, configurazione e due tool confrontati sono invariati.
Questo dimostra continuità dei file, **non** la corrispondenza al sorgente pubblico.

Restano i limiti già documentati: modulo ad hoc senza attestazione del produttore,
versioni/receipt non equivalenti a una build riproducibile, dipendenze locali e
configurazione da qualificare. Il comportamento composto e l'opzione
user_pin_unblock_style sono motivi per analizzare un profilo preciso, non per
attribuire automaticamente quei rami al binario installato.

Non sono stati caricati nuovi moduli o interrogati token in questa indagine.
Le letture hardware/ATR della 12B sono evidenze storiche dichiarate nel relativo
rapporto, non nuove misurazioni di questo collaudo documentale.
OpenSC non è scelto come sostituto automatico quando Bit4id manca o fallisce.
[Rapporto base Build 12B](SIGNUM_07_BUILD12B_PIN_CHANGE_QUALIFICATION.md).

## 5. Matrice decisionale

«Non supportabile in sicurezza» significa con le prove e la procedura proposte
oggi; non è un'affermazione di impossibilità permanente del prodotto.

| Percorso | Cambio PIN | Sblocco PUK | Decisione e condizione |
| --- | --- | --- | --- |
| GUI ufficiale InfoCamere/Bit4id, gestita dall'operatore | Documentato nel manuale | Documentato nel manuale | **Implementabile come accompagnamento informativo/handoff manuale**, dopo verifica dell'installazione e del modello supportato. Non è un backend integrato e non fornisce a Signum una prova dell'esito. Oggi le app non risultano installate nei percorsi esaminati. |
| Modulo ufficiale Bit4id, API standard C_SetPIN | API pubblica disponibile come candidatura; profilo non qualificato | Nessuna sequenza specifica accertata | **Da qualificare ulteriormente**: versione supportata, contratto del modello e gestione dei domini. Candidato preferibile per il cambio PIN. |
| SDK amministrativo ufficiale macOS, eventualmente riservato | Contratto da ottenere | Contratto da ottenere | **Da qualificare ulteriormente**. Preferibile per entrambe le operazioni se il produttore documenta API, esiti e recupero. Non ancora reperito né collaudato. |
| Uso generico PUK come SO PIN e C_InitPIN | Non pertinente | Mapping assunto | **Non supportabile in sicurezza oggi** senza specifica del produttore. Nessuna prova per tentativi. |
| Engine IPC privato, export non standard senza SDK, automazione GUI con segreti | Non documentato per integratori | Non documentato per integratori | **Non supportabile nella proposta attuale**; escluso. |
| SDK mobile / 4identity trasferiti automaticamente a macOS PIN/PUK | Copertura non dimostrata | Copertura non dimostrata | **Non supportabile sulla sola documentazione reperita**; richiedere contratto pertinente. |
| OpenSC locale attuale | Candidato non qualificato | Candidato non qualificato, semantica dipendente dal profilo | **Da qualificare ulteriormente**, separatamente e senza fallback. La 12B non ne ha certificato il backend hardware. |

Per un handoff futuro non vanno passati segreti in URL, argv o ambiente;
nessuna automazione di PIN/PUK e nessun successo presunto al ritorno dalla GUI.
Il journal Signum non va risolto automaticamente perché un'app esterna è stata
aperta o chiusa. Anche l'esclusione reciproca con software terzo richiede un
contratto specifico, non è garantita dalla sola barriera Signum.

## 6. Informazioni da richiedere al produttore prima dello sviluppo

Elenco tecnico pronto per un eventuale contatto autorizzato, **non inviato**:

1. Pacchetto/versione ufficialmente supportati per DigitalDNA InfoCamere/NXP,
   variante e firmware esatti, macOS Apple Silicon; identificativi firmati,
   distribuzione e licenza di caricamento da un'app di terzi.
2. API pubblica/SDK amministrativo macOS e documentazione d'integrazione;
   uso esterno del modulo incluso in Sign Desktop o disponibilità di un modulo
   redistribuibile/installabile ufficiale, con percorso stabile.
3. Per C_SetPIN: slot/dominio, utente e stato di sessione, eventuale login
   funzionale richiesto, policy di lunghezza/codifica, pinpad e operazioni
   interne. Nessuna sequenza di ruoli sperimentata per trovare quella funzionante.
4. Per PUK: significato rispetto a SO PIN, API e sessione supportate, domini
   aggiornati, operazioni esplicitamente escluse e differenza da inizializzazione
   o reset del token. Nessun C_InitToken nella procedura proposta.
5. Atomicità fra IAS/CNS, risultati parziali, codici di esito, rimozione/timeout,
   rollback interni e recupero documentato per ciascuno stato. Nessun retry
   automatico, login di verifica o recupero dedotto da analogie con altre carte.
6. Identità amministrativa stabile indipendente dal certificato, comportamento
   con più route/provider e meccanismo di esclusione con altre app del produttore.
7. Canale protetto per segreti, assenza di logging/caching non controllabile,
   timeout/cleanup, politica degli esiti incerti e restrizioni sandbox/firma.
8. Se si preferisce un handoff: modalità pubblica documentata di apertura e
   selezione dispositivo, responsabilità dell'operatore e significato degli
   eventuali risultati; mai riutilizzare un protocollo interno non supportato.

Solo dopo risposte e qualifica del profilo si potrà pianificare una prova
separatamente autorizzata su un dispositivo di test. Questa indagine non ne
richiede il PIN/PUK e non autorizza alcuna operazione reale.

## Verifiche e limiti della consegna

Eseguiti: lettura di quattro ricevute e dei rispettivi BOM, verifica esistenza
dei percorsi pertinenti, ricerca indicizzata e nei percorsi standard, metadati
Mach-O/firma/export della sola copia archiviata, confronto hash dei cinque file
OpenSC, verifica delle 12 modifiche locali preservate, consultazione di fonti
primarie e lettura del manuale ufficiale scaricato.

Non eseguiti: dlopen/C_Initialize/C_GetInfo del modulo Bit4id, avvio di app o
engine del produttore, chiamate PKCS#11 al token, autenticazioni diagnostiche,
reset, cambio PIN o sblocco; nessuna installazione/reinstallazione o modifica
alla configurazione. Nessuna cattura di credenziali, disassemblaggio o probing
di API interne. Nessun nuovo test crittografico/build necessario per un rapporto
senza modifiche ai sorgenti runtime; i test 12B non qualificano il backend reale.

L'assenza di documentazione pubblica reperita non dimostra l'inesistenza di un
SDK commerciale. La firma della copia d'archivio non sostituisce installazione,
supporto e contratto del modello. I manuali utente non garantiscono recupero
transazionale. Questi limiti impediscono oggi l'abilitazione in Signum.

Motori di firma/verifica, foundation 12B, middleware e HalleyMac invariati.
PR #8 mantiene lo stato Draft; nessuna GitHub Action, merge, tag o release.

**STOP prima dello sviluppo operativo.**
