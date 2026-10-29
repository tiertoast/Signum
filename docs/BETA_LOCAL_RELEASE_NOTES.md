# Signum 0.7.0 Beta — build14, candidato locale arm64

Digital signatures. Simply native.

Candidato tecnico locale con firma ad-hoc. Non è Developer ID, non è
notarizzato e non costituisce una release pubblica o una qualificazione Stable.
Minimo dichiarato macOS13.0; il solo valore Mach-O non prova l'esecuzione su
macOS13 reale. Intel non è incluso.

PoDoFo1.1.2 e FreeType2.13.3 provengono dalla nuova build controllata e verificata.
Il bundle include notice e il kit sorgenti corrispondenti con le istruzioni in
Contents/Resources/ThirdPartySources/SOURCE_ACCESS.md. PoDoFo sotto MPL2.0,
FreeType sotto FTL, componenti autonome secondo i propri termini; Signum resta
Apache2.0. Nessun accesso al repository privato è necessario per il kit coperto.

Il collaudo di packaging verifica risorse, loader, integrità, firma e avvio
base. Non certifica tutte le operazioni funzionali o l'hardware reale. Non
inserire PIN/PUK né avviare firme reali durante questo controllo automatico.
L'eventuale middleware PKCS#11 rimane un'installazione esterna dell'operatore.

M3–M6 restano aperti e rinviati; gate RC NON SUPERATO. I limiti già documentati,
inclusi accessibilità e altri collaudi manuali non eseguiti, non sono promossi
a successi. Nessuna nuova campagna di stabilità o stress è inclusa.

Prima di pubblicare occorrono separati audit del candidato, collaudi pertinenti
sul minimo OS/macchina pulita e decisione sul canale e sull'esperienza Gatekeeper.
Nessuna protezione macOS viene disabilitata automaticamente.
