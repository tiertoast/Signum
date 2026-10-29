# Signum 0.6.0 — Development Preview Build 2

**Digital signatures. Simply native.**

Note preliminari per il collaudo locale; non è una pubblicazione Beta ufficiale.

## Funzionalità consolidate

- Valutazione eIDAS corrente distinta da quella storica: signingTime dichiarato,
  data di verifica e tempo comprovato restano separati. Un timestamp assente non
  impedisce da solo un esito positivo; tutte le altre evidenze restano necessarie.
- Firma e verifica XAdES-B enveloped nel sottoinsieme RSA/SHA-256 dichiarato.
- ASiC-S con un documento e ASiC-E con 2–4 documenti, XAdES detached,
  riferimenti e copertura dei contenuti controllati e ZIP con limiti di sicurezza.
- CAdES detached `.p7s` con originale esplicito; cofirma e controfirma di CMS
  attached supportati, con associazione individuale e conservazione delle firme.
- Rapporti PDF A4 e TXT con cinque esiti indipendenti e motivazioni del motore,
  date italiane UTC, evidenze disponibili e accenti Burgundy `#64313E`.
  L’interfaccia mantiene i colori precedenti.

## Ambiente e isolamento

Versione 0.6.0, build 2; Apple Silicon arm64; target macOS 13.0.
Identificativo: `io.github.tiertoast.Signum.DevelopmentPreview.V06.B2`.
Preferenze nel relativo dominio; Trusted Lists in
`~/Library/Application Support/io.github.tiertoast.Signum.DevelopmentPreview.V06.B2/TrustedLists`;
cache di revoca in `~/Library/Caches/io.github.tiertoast.Signum.DevelopmentPreview.V06.B2/Revocation`.
Nessuna migrazione automatica o sostituzione della Beta 0.5/Preview Build 1.
Firma ad hoc: nessun Developer ID o notarizzazione. Bundle nativo autonomo;
nessuna dipendenza Java/Homebrew a runtime. La firma hardware richiede middleware
PKCS#11 compatibile installato dall’utente.

## Limitazioni da conoscere

- XAdES/ASiC: profili ristretti descritti nei rapporti B/C, un firmatario XML,
  RSA PKCS#1/SHA-256; niente XAdES-T/LT/LTA o ASiC con CAdES.
- CAdES avanzato: DER id-data, controfirme RSA/SHA-256 con attributi firmati e
  SigningCertificateV2; modifiche a contenitori detached preesistenti o BER non
  supportate. Non sostituisce una controfirma con una cofirma.
- Qualificazione positiva limitata ai profili diretti CA/QC post-2016 verificati
  IT/AT/DE/BE/FR/ES e a evidenze complete. Altri Paesi, storie/criteri non supportati
  o dati insufficienti restano indeterminati. OCSP good corrente non prova validità
  storica; signingTime non è una marca temporale.
- Rapporti non firmati e non marcati: nessuna attestazione automatica di validità
  giuridica, PDF/A, LTV, LT/LTA. Data aggiornamento TL non esposta nei risultati:
  dichiarata non disponibile, senza dedurla dalla decorrenza del servizio.
- Nessun confronto DSS eseguibile nuovo; interoperabilità e collaudo hardware
  restano limitati ai profili/test documentati. Nessuna esecuzione su macOS 13
  dichiarata senza collaudo reale; il target minimo non equivale a tale collaudo.
- Il comando legacy verify-cades usa OpenSSL di sistema e rifiuta controfirme:
  usare la verifica unificata per i risultati individuali completi supportati.

## Checklist breve di collaudo manuale

Usare documenti di prova e destinazioni nuove; nessun test automatico usa token,
PIN o documenti personali. Annotare dispositivo, middleware, formato ed esito.

- [ ] Aprire Build 2; controllare versione/identità e Impostazioni → Elenchi
      fiduciari. Verificare isolamento dalla Beta 0.5 e dalla Preview Build 1.
- [ ] DigitalDNA e CNS: firmare/verificare CAdES attached e PAdES, controllando
      anteprima, approvazione, annullamento e rifiuto di destinazioni occupate.
- [ ] Firmare XML XAdES-B, ASiC-S e ASiC-E (2–4 file); verificare elenco/copertura
      documenti. Alterare una copia del contenuto e attendersi integrità negativa.
- [ ] Creare `.p7s`; verificare con originale corretto, errato e assente.
- [ ] Cofirmare e controfirmare un CMS di prova; confrontare identità/relazioni ed
      esiti individuali. Verificare con InfoCamere dove supportato, annotando limiti.
- [ ] Esportare PDF/TXT su documenti reali scelti dall’utente: confrontare tutti e
      cinque gli esiti, motivazioni, date e legami delle controfirme con il pannello.
      Verificare leggibilità, accenti Burgundy solo nei rapporti e dati mancanti.
- [ ] Verificare senza timestamp e offline: data dichiarata distinta dalla verifica,
      nessuna QES positiva quando mancano revoca o altre evidenze necessarie.

Risultati automatici, commit sorgente e checksum sono nel rapporto di consegna
Build 2 e nel manifest sigillato del bundle. La pubblicazione attende il collaudo.
