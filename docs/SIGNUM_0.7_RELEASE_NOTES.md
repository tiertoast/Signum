# Signum 0.7.0 Beta — Build 14

29 ottobre 2026 · Apple Silicon arm64 · prerelease sperimentale.
**Gate RC NON SUPERATO. M3–M6 aperti e rinviati. Nessuna qualifica Stable.**

## Novità della 0.7

- Interfaccia nativa SwiftUI/AppKit con workspace documenti, inspector di firma,
  navigazione laterale e accenti Burgundy; gestione delle finestre e delle sessioni.
- Apertura documenti da Finder e servizi macOS, selezione dei formati, rimozione
  individuale dei documenti, verifica cumulativa e impostazioni applicazioni predefinite.
- Esperienza Dispositivi con certificati, finalità e selezione coerente; informazioni
  pubbliche PIN/PUK. Cambio PIN e sblocco PUK reali restano disabilitati/non qualificati:
  la foundation amministrativa è esclusivamente sintetica.
- Verifica PDF che distingue firme storiche valide dalla copertura della revisione
  corrente; gestione conservativa del cleanup PAdES e dell'esito privato incerto.
- Cancellazione delle operazioni legata alla vita delle sessioni; byte del PIN CLI,
  cancellazione dei buffer PIN e controllo dei conteggi PKCS#11 rafforzati.
- Informazioni distinte sul tempo dichiarato CAdES, XML e PDF prima del consenso;
  correzioni della presentazione della verifica e delle evidenze correnti.
- Packaging autonomo, audit di risorse/loader e kit sorgenti nativi corrispondenti.

Restano i sottoinsiemi CAdES/PAdES/XAdES/ASiC descritti nei rapporti della 0.6 e
nelle note delle build 0.7; non si estende implicitamente la copertura di formati,
Paesi, interoperabilità o qualificazione eIDAS. Nessuna nuova TSA o cifratura.

## Artefatto e provenienza

Si distribuisce **senza ricompilazione** il DMG locale verificato:

- File: `Signum-0.7.0-beta-arm64.dmg`, **22.766.204 byte**.
- SHA256: `cc5add5dab9163e44465a2b6161532ec6e5f1d5c5ed6aef98250935e9f80c2b9`.
- Sorgente del prodotto: `09316e046a4dd101ce74410a6eeccee6911d4783`.
- Bundle ID: `io.github.tiertoast.Signum`; versione `0.7.0`, build `14`.
- Minimo dichiarato: macOS `13.0`; architettura esclusivamente `arm64`.
- Firma **ad-hoc**; nessun Developer ID o notarizzazione.
- Il tag di release identifica il merge della PR #8, che aggiunge soltanto
  documentazione al sorgente del prodotto. Non attribuire quel merge al binario.

`ArtifactManifest.json`, `AppAudit.json`, `BuildManifest.json`, `summary.json`,
inventario dell'app e checksum accompagnano l'asset. I manifest storici conservano
`publicationQualified:false`: misurano la verifica locale, non una certificazione
alla pubblicazione. La decisione dell'autore di distribuire una Beta sperimentale
con questi limiti è separata e non modifica i risultati o il gate RC.

## Verifiche attestate e loro limiti

Il run Fase8 registra quattro passi riusciti (app, audit app, DMG, audit DMG),
zero blocchi e stato `verified-local-beta`. Il controllo di avvio attesta il PID e
il bundle corretti, `finishedLaunching` e processo vivo dopo due secondi: è un
controllo del loader/avvio, non un collaudo funzionale GUI o hardware completo.

Il 29 ottobre è stato ripetuto solo l'audit del DMG: hash/sidecar, montaggio readonly,
inventario completo, corrispondenza con l'app attestata e codesign. I materiali
sorgenti/licenze restano inclusi nel bundle verificato. Nessuna ricompilazione,
nuova suite Swift completa, campagna di stress o GitHub Action per la pubblicazione.
La dichiarazione dell'autore «installato e tutto funzionante» è accettazione locale,
non una matrice attestata di OS o dispositivi.

## Limitazioni e lavoro aperto

- **M3–M6 OPEN, categoria (e)**: causa delle ricorrenze non isolata, rinviati;
  [tracciamento #9](https://github.com/tiertoast/Signum/issues/9).
  Nessun fix, skip, allentamento degli assert o nuova campagna inclusi qui.
  I 795 test storici non sono un nuovo esito verde di questa revisione.
- Runtime reale macOS 13/14 e installazione su Mac pulito: **non attestati**.
  Il minimo Mach-O/plist non prova compatibilità runtime. Intel escluso.
- Matrice hardware/middleware, rimozione token, PIN bloccato, hang vendor e
  interoperabilità estesa: qualificazione limitata alle prove documentate.
  Nessun collaudo nuovo su dispositivi reali o operazione PIN/PUK autorizzata qui.
- Restano aperti accessibilità/collaudi manuali non eseguiti e gate di distribuzione
  produzione: Developer ID, hardened runtime, notarizzazione, Gatekeeper e aggiornamenti.
- Firma ad-hoc: macOS può impedire l'apertura del download. La release non contiene
  alcuna procedura automatica per disabilitare Gatekeeper o altre protezioni.
- La firma hardware richiede middleware PKCS#11 compatibile installato dall'operatore.
  Una firma integra, la fiducia, il tempo e la qualificazione eIDAS restano esiti separati.

Il DMG contiene l'app da trascinare in Applicazioni e le note locali congelate
prima della pubblicazione; queste note di release descrivono la decisione Beta
successiva senza alterare quel DMG. Il repository rimane privato: gli asset GitHub
sono accessibili ai soli utenti autorizzati.

## Licenze e sorgenti dei componenti

Signum resta Apache-2.0. PoDoFo 1.1.2 è distribuito secondo MPL-2.0, FreeType 2.13.3
secondo FTL; componenti autonome conservano i propri termini. Crediti, testi,
provenienza e kit corrispondente sono in
`Signum.app/Contents/Resources/ThirdPartySources/SOURCE_ACCESS.md` e materiali
adiacenti. Il destinatario del DMG può ottenere il kit incluso senza accesso al
repository privato. Il dossier documenta verifiche tecniche, non un parere legale.

Vedi [roadmap](https://github.com/tiertoast/Signum/blob/main/docs/ROADMAP.md),
[stato dei gate](https://github.com/tiertoast/Signum/blob/main/docs/RELEASE_READINESS.md)
e [PR #8](https://github.com/tiertoast/Signum/pull/8).
