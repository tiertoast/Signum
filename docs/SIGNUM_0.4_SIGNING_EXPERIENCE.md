# Signum 0.4-A.3 — Signing Experience

## M1 — Baseline e perimetro

18 ottobre 2026. Branch `codex/signum-0.4-signing-experience` creato da
`a468c42`, candidata 0.4.0/build 2 della Device Discovery. Stato tracciato pulito;
review originale non tracciata preservata, SHA-256
`2f275328cdca3ebe2023ade1c87b3179bc89540af8d7a898b304241d61a168a6`.
Main rimane `be84a1e`; nessun accesso ad altri repository o a HalleyMac.
Letti i rapporti Device Discovery/progressi e i componenti coinvolti, senza una
nuova review generale. Il collaudo DigitalDNA/DS3 della 0.4-A.2 (discovery,
autenticazione distinta, firme e InfoCamere positivi) è riferito dall'utente.

**Baseline realmente eseguita prima del codice:** Swift **197/197**, zero skip,
con helper nativo esplicito; PKCS#11 **40/40**; PAdES Debug/Release **63/63**.
Evidenze locali `.build/reliability/evidence/04a3-baseline-*.log`.
Solo fixture sintetiche, nessun hardware o PIN personale.

Prima: certificati esclusi visibili, destinazione comune chiesta dentro il
percorso di conferma, colonna sinistra lunga e area CAdES destra poco utilizzata.
Intervento limitato a filtro/preferenze, pianificazione destinazioni, consenso e
workspace. Si conservano policy SG-04, snapshot, worker, lease, verifica e commit
Foundation. Nessun worker batch persistente o ottimizzazione PIN in questa fase.

Milestone: M2 filtro; M3 destinazioni; M4 conferma/PIN; M5 workspace;
M6 regressioni, packaging e istruzioni manuali. Ogni passaggio ha un commit locale.

## M2 — Filtro certificati

Default persistente OFF per «Mostra certificati non idonei». La presentazione usa
`CertificateVisibility`, senza cambiare SG-04: OFF mostra solo eligible; ON mostra
anche ineligible e indeterminate, mantenendo stati e motivi distinti. Gli
indeterminati hanno un accesso avanzato esplicito anche a filtro chiuso. Una
selezione esclusa nascosta viene cancellata insieme al PIN; nessuna preselezione
al refresh e nessuna possibilità di firmare con un certificato escluso.

Test mirati filtro/preferenza/selezione/provider: **17/17**. Cinque nuovi casi:
OFF/ON, stati e motivi, persistenza isolata senza credenziali, blocco SG-04 anche
quando il certificato è visibile, refresh senza preselezione. GUI compilata;
nessun collaudo interattivo o hardware implicato da questi test.

## M3 — Destinazioni prima del consenso

`BatchOutputDestination` pianifica in Core, off-main e senza creare output/probe:
- default `.originalFolders`: ogni copia accanto al proprio originale;
- `.commonDirectory`: cartella scelta in anticipo con Sfoglia, mai durante il consenso.

La preferenza originale è ON inizialmente; la cartella comune ricordata è un
percorso, non un'autorizzazione permanente. L'app attuale non ha App Sandbox:
nessun nuovo entitlement/bookmark, permessi OS ricontrollati a ogni pianificazione.
Se manca la cartella comune, il pulsante non è abilitabile. Cartelle mancanti,
non scrivibili o negate da ACL sono rifiutate prima dell'approvazione/PIN.

Percorsi canonici e identità device/inode del parent approvati e ricontrollati
prima dell'autenticazione; no fd/staging/output creati dal piano. Prenotazioni
per directory fisica e nome, incluso collisioni fra cartelle alias; lstat considera
anche symlink pendenti. CAdES `Relazione.pdf.p7m`, poi `Relazione (2).pdf.p7m`;
PAdES conserva la convenzione esistente `Relazione-firmato.pdf`. Un solo assert
legacy sui suffissi CAdES aggiornato alla nuova convenzione richiesta, mantenendo
il test e i suoi invarianti. Destinazioni e job immutabili dopo il consenso.

Collisione tardiva o parent sostituito: nessuna autenticazione, nessun rename
silenzioso; nuova sessione/approvazione prima di un nome diverso. Verifica e
pubblicazione atomica/no-overwrite Foundation restano obbligatorie e immutate.
Core CAdES e wrapper PAdES riusano il controllo di disponibilità del job prima
operazioni private; nessuna modifica a RSA/CMS/PDF o ai protocolli hardware.

**Test mirati M3 + batch/job: 36/36**, inclusi 11 nuovi casi: originale singolo,
cartelle diverse/nomi uguali, cartella comune con file e symlink già esistenti,
PAdES, directory assente/file/read-only/ACL, collisione dopo consenso, sostituzione
parent, preferenze incomplete/persistite, output congelati e tre CAdES verificati
accanto agli originali senza modificarli. Primo run: sette assert confrontavano
alias `/var` e `/private/var` invece della directory fisica; fixture normalizzata
con realpath e confronto coerente, poi suite ripetuta positiva. Nessuna deroga ai
controlli di percorso per far passare il test.

## M4 — Una conferma, autenticazione corrente

Pulsante «Firma documento» / «Firma N documenti», una sola conferma con firmatario,
certificato, lista/formati/destinazioni effettive. NSOpenPanel è esclusivamente
nell'azione Sfoglia precedente. SHA-256, percorsi, dimensioni, job/snapshot/provider/
slot e certificato nel dettaglio tecnico. Nessun popup documentale dopo il consenso.
Il pulsante/Invio nel campo PIN invia l'autenticazione, non richiede un altro consenso.

`SigningInteraction` separa consenso e invio da job e stato provider: niente PIN
memorizzato nel modello, campo svuotato sincronicamente prima della Task privata,
una sola richiesta in volo. Prompt «Firma i di N — Inserisci PIN» e focus quando
la firma successiva è pronta. Il documento corrente è vincolato anche nel guard
atomico Core: se viene annullato prima dell'avvio, il PIN non passa al successivo.
Nessun worker persistente, retry o riuso PIN fra documenti; ALWAYS_AUTHENTICATE,
worker/helper, timeout e gestione incerta restano invariati. Il riconoscimento di
un esito incerto rimane una misura Foundation, non un nuovo consenso ai documenti.

`SigningPresentation` distingue vuoto/destinazione incompleta/selezione incompleta,
pronto/preparazione/conferma/PIN/in corso/incerto/concluso. Non presenta fallimenti
o annullamenti come firme riuscite. Nuova sessione libera snapshot e piani.

**Test M4 + batch: 19/19**, sei nuovi casi: unica presentazione e tre CAdES reali
software, tre campi PIN consumati senza ulteriori conferme, seconda richiesta
concorrente rifiutata, consenso annullato, errore prima della conferma, annullamento
prima della Task senza retarget PIN, blocco dopo incertezza e stati/reset.
Nessun PIN personale e nessuna autenticazione hardware.
