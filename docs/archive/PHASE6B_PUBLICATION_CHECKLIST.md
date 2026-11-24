# Phase6b — minimo per DMG Beta di prova e pubblicazione

Scelte approvate: FreeType2.13.3 FTL, PoDoFo1.1.2 MPL2.0. Apache2.0 Signum invariata.

- [x] Archivi originali PoDoFo/FreeType recuperati da fonti ufficiali, SHA256
  identici alla recipe; MPL/FTL locali verificati byte per byte.
- [x] Credito FreeType Team conservato, licenze autonome aggiuntive raccolte.
- [x] xades.xsd ricondotto al file ETSI e alla LICENSE del medesimo tag,
  originale identico al DSS dichiarato; import locale documentato.
- [x] xml.xsd ricondotto allo snapshot W3C2009/01 con differenze esatte.
- [x] Modalità source-with-artifact e percorso accessibile al destinatario
  predisposti; nessun repository privato necessario per i due archivi.
- [ ] Riferimento W3C esplicito che copra la licenza di xml.xsd: ancora bloccante.
- [ ] Albero realmente compilato, patch/diff (o prova del diff vuoto) e registro
  di build collegato ai binari originali: corrispondenza ancora non attestata.
- [ ] Risolvere nel dossier effettivo anche il rinvio di utf8proc al copyright
  dei dati Unicode assente da quel file nell'archivio recuperato.
- [ ] Solo dopo questi prerequisiti e autorizzazione: preflight nuovo, metadati
  e TrustProbe approvati, build locale/DMG di prova. Nessun aggiramento dei gate.
- [ ] Prima della pubblicazione: audit sul pacchetto reale e sorgenti ottenibili,
  checksum, collaudi runtime/minimo13/macchina pulita, canale/Gatekeeper e note.

**DMG Beta di prova: NOT READY** con i gate attuali. Non è un giudizio Stable
né un'autorizzazione alla pubblicazione. Nessun packaging eseguito in Fase6b.
Nessuna nuova campagna funzionale richiesta. M3–M6 restano aperti/rinviati;
gate RC NON SUPERATO, non alterato da queste attività documentali.
