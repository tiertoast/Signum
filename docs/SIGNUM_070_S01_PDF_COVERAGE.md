# S01 — Copertura della revisione PDF corrente

`VerificationReport.integrity` conserva l’aggregazione degli esiti crittografici delle firme; non attesta da solo il documento PDF corrente. Lista, riepilogo, descrizioni accessibili, CLI ed export usano `documentOutcome` / `documentIntegrity`.

`documentByteCount` è la dimensione dell’input immutabile passato al motore. `currentRevisionCoverage` usa soltanto firme verificate, con limite di revisione positivo, entro l’input e coerente con `laterChanges`. Il motore nativo verifica già ByteRange/Contents, CMS e presenza univoca della firma nel prefisso storico. La copertura è dimostrata quando una firma verificata raggiunge esattamente la fine dell’input. Metadati mancanti o incoerenti non producono verde. `withoutPreview()` conserva i metadati di copertura senza trattenere i byte.

Le firme precedenti mantengono il proprio esito. Una firma non valida prevale sul verdetto globale anche quando un’altra firma copre l’ultima revisione. Più firme valide e ultima revisione interamente coperta consentono un esito positivo della copertura; ciò non asserisce conformità DocMDP/FieldMDP o accettabilità delle modifiche intermedie.

## Scelta conservativa

Il profilo non dispone di un classificatore che dimostri l’esclusività o benignità di un aggiornamento DSS, di un timestamp o di altre aggiunte. Ogni coda non coperta rimane `unclassified` / «modifiche successive non valutate», anche se contiene `/DSS` e il testo visibile non cambia. `signedRevisions` indica firme in revisioni verificate con ultima coprente, senza affermare che le revisioni contengano soltanto aggiunte di firme.

Alternative scartate: invalidare tutte le firme precedenti; fidarsi della sola assenza di `laterChanges`; dedurre benignità da `/DSS`, dal testo invariato o da una firma aggiunta; equiparare copertura byte e permessi PDF. Un classificatore strutturale e DocMDP/FieldMDP completo esulano da S01.

## Regressioni

`PDFRevisionCoverageTests` genera PDF sintetici con xref/Prev reali, CMS software e testo di pagina controllato indipendentemente con Poppler. Copre firma completa, content stream sostituito, seconda firma prodotta da Signum, DSS, commenti in coda, tamper firmato, tamper più contenuto successivo, mapping condiviso lista/riepilogo/accessibilità ed export TXT/PDF. I test dei metadati verificano il caso conservativo; nessun collaudo grafico o VoiceOver end-to-end è dedotto da questi assert.

Riproduzione e log della campagna sono nel rapporto esterno `FASE1_S01_RAPPORTO.md`, sotto la radice Signum-Stabilization. Nessuna modifica ai test preesistenti o ad altri finding.
