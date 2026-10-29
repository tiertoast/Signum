# FreeType 2.13.3 — Fase6b

**Scelta definitiva dell'autore: FTL.** LICENSE principale Signum Apache2.0
invariata. Non si sceglie GPL per il motore FreeType. I componenti con termini
propri conservano quei termini; non si estende FTL per analogia.

Archivio ufficiale recuperato da
https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.xz
(con redirect al mirror ufficiale registrato nell'inventario), SHA256
`0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289`,
coincidente con metadata del prefix e recipe Signum.
`Resources/ThirdPartySources/freetype.tar.xz` conserva il sorgente originale
intero. LICENSE.TXT e docs/FTL.TXT sono identici byte per byte ai notice già
inclusi. Il credito FreeType Team è conservato; formula preferita e anno non
sono trasformati in nuovi requisiti o inventati.

Recuperati dal medesimo archivio i testi per BDF, PCF, zlib, fthash e codice
HarfBuzz (Old MIT). I primi due driver hanno simboli nel libfreetype.a esistente;
la raccolta dei notice è conservativa anche per moduli presenti nei sorgenti
ma non provati nel binario finale. La configurazione installata abilita
SYSTEM_ZLIB; la recipe disabilita HarfBuzz. Non è stato installato HarfBuzz.
55 header installati coincidono esattamente con l'archivio; ftconfig.h e
ftoption.h differiscono per configurazione. Diff integrali in
`Resources/ThirdPartySources/Evidence/`; non sono presentati come inventario
completo delle patch del codice compilato.

FTL: conservare testo e copyright; credito nella documentazione della
ridistribuzione binaria; per i sorgenti mantenere gli avvisi e documentare
modifiche; nessuna promozione tramite nomi degli autori senza permesso.
BDF/PCF/zlib/fthash/HarfBuzz mantengono i notice specifici. S17: scelta e credito
completati, verifica dell'artefatto finale ancora non eseguita.

Il sorgente è predisposto insieme all'app secondo SOURCE_ACCESS.md. Il match
archivio/header/notice non dimostra che ogni oggetto nel binario esistente sia
stato compilato da quei sorgenti senza modifiche: corrispondenza integrale NON
ATTESTATA; nessuna ricompilazione o sostituzione effettuata.
