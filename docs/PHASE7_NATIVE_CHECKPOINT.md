# Fase7 — checkpoint manuale indispensabile, senza app/DMG

Stato: **PRONTO PER IL COLLAUDO MANUALE DEL NUOVO PREFIX**. La procedura non è
stata eseguita da Codex. La carenza del vecchio registro viene risolta mediante
nuova build, senza fingere una ricostruzione storica o sostituire il vecchio prefix.

## Comando esatto (Terminale dell'autore)

```sh
/usr/bin/python3 /Users/andreaoregioni/Developer/Signum-Stabilization/worktree/scripts/rebuild-beta-native.py \
  --base-prefix /Users/andreaoregioni/Developer/Signum-0.7/.build/icon-native/prefix \
  --cmake /opt/homebrew/bin/cmake \
  --output /Users/andreaoregioni/Developer/Signum-Stabilization/diagnostics/fase7-native-001 \
  --budget-seconds 900
```

Output nuovo obbligatorio: un secondo tentativo richiede un altro nome; niente
sovrascritture. Default900s complessivi, `--jobs 6` configurabile. Nessuna
installazione/download, nessuna app/DMG, nessun accesso a hardware o credenziali.
OpenSC/middleware e prefix originale restano in sola lettura.

Leggere `summary.json` prima di fare altro. Successo atteso:
`status: verified-native-checkpoint`, test integrazione1, componenti3,
`packagingQualified:false`, `publicationQualified:false`. In caso di fallimento
sono conservati log del passo e diagnostica CMake/CTest necessaria; i successi
non lasciano stdout dettagliati. I gruppi figli sono terminati su timeout,
intermedi rimossi; sorgenti, nuovo prefix e prove sono conservati. Se manca
tempo per eliminare intermedi, cleanupIncomplete rende esplicito il fallimento.

## Cosa verifica e conserva

- SHA256 degli archivi attesi, estrazione sicura, inventario integrale sorgenti
  prima/dopo: zero patch solo con identità completa.
- Nuove FreeType2.13.3 statica e PoDoFo1.1.2 dinamica, macOS13.0/arm64/Release;
  CMake flag espliciti, nessuna ricerca di librerie Homebrew.
- OpenSSL3.5.6, libxml2 2.15.4, xmlsec1.3.12 copiati in staging dal prefix
  validato, con hash e stato di riuso esplicito. Vecchie FT/PoDoFo escluse.
- Toolchain, SDK, compiler hash/version, opzioni, comandi, CMakeCache e
  compile_commands; rpath/install-name riscritti solo nelle copie, ad-hoc locale.
- Helper Signum ricostruito e CTest offline esistente `signum-pades-reliability`
  con provider sintetico: niente campagne Swift/M3–M6. JUnit vuoto/skipped rifiutato.
- Versione/inizializzazione FreeType, normalizzazione Unicode compatibile e UTF8
  invalido: test dei moduli compilati da quei sorgenti; loader dell'helper deve
  caricare la NUOVA PoDoFo, senza librerie esterne al prefix o di sistema.
- Closure reale, minOS, rpath, architettura, notice; archivio fonti/notice e
  BUILD_NATIVE_SOURCES.md accessibili senza repository Signum privato.

`native-build-manifest.json` conserva il registro completo del run.
`prefix/share/signum-sources/NATIVE_BUILD_PROVENANCE.json` è la versione portabile,
con percorsi logici e attestazione limitata a QUEL prefix. L'inventario dei file
esclude il manifest stesso per evitare hash circolari. Il kit scoped cambia
podofo.json ad attested soltanto dopo tutti i controlli e cleanup riusciti;
il dossier globale/vecchio prefix non viene modificato. L'attestazione è la
tracciabilità del processo controllato, non una firma di un'autorità esterna.

## Ripresa dai risultati

Fornire il percorso di `summary.json` (e il manifest), senza rilanciare la build.
Si verifica il risultato e si seleziona soltanto allora il nuovo kit nel profilo
isolato del candidato, preservando il vecchio prefix e i gate esistenti.
La procedura di packaging già presente richiede ancora quella selezione
esplicita: al momento legge correttamente il dossier globale unattested.

I metadati reali riscontrati sono CFBundleIdentifier `io.github.tiertoast.Signum`,
CFBundleVersion `14`, target13.0; la risorsa legacy reca ShortVersion0.4.0.
Per il candidato richiesto la route Beta applica0.7.0 e nome Beta senza cambiare
la risorsa legacy. TrustProbe si conserva come nel preview0.7/build14, incluso;
staging ad-hoc come richiesto. Nessun identifier dimostrativo necessario.
La risorsa Info.plist principale non è modificata in questa fase.

Dopo la selezione e i controlli di provenienza, il prossimo checkpoint sarà
l'app/DMG locale, con icona/risorse/hash/avvio e integrità; nessuna qualificazione
pubblica o hardware si ricava dai soli test nativi. S17 resta soggetto all'audit
sul pacchetto. M3–M6 aperti/rinviati, gate RC NON SUPERATO invariato.
