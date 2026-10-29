# Schemi XAdES / W3C / DSS — evidenze locali e blocchi

Stato: PARZIALE, ridistribuzione non qualificata. Inventario e SHA-256 dei sette
XSD in `scripts/schema-license-catalog.json`; nessun byte XSD modificato.
Le origini sono quelle dichiarate in Schemas/PROVENANCE.md, non nuove attestazioni
upstream. Package.swift copia la directory Schemas nel bundle SwiftPM.

| Materiale | Evidenza originale disponibile | Stato / materiale mancante |
|---|---|---|
| Tre 19612_*.xsd | ETSI TS119612 v2.4.1, commit dichiarato 812fe781d37ead5b0ad562f2874ef5f67fc3a4dd; ETSI-LICENSE locale Copyright2024 | testo source/binary a tre condizioni presente, conservato anche come Notices/ETSI-TL.txt; corrispondenza upstream da attestare |
| xades.xsd | origine DSS commit9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33, XAdES01903v132-202407.xsd, namespace1.3.2 | manca testo originale applicabile al file e prova della catena di provenienza; NON inferire LGPL/ETSI dalla licenza dell'intero repository |
| xmldsig.xsd | header Copyright2001 Internet Society/W3C, revisione2002-02-08, rinvio W3C Software License19980720 | manca il testo completo richiamato: http://www.w3.org/Consortium/Legal/copyright-software-19980720 |
| xml.xsd | origine dichiarata https://www.w3.org/2001/xml.xsd | mancano snapshot upstream datato e testo applicabile; non trasferire automaticamente la licenza XMLDSig |
| validation.xsd | wrapper originale Signum | LICENSE Apache2.0; non estendere la licenza alle risorse importate |

Le modifiche dichiarate nella provenienza originale sono import locali,
rimozione DTD/entità esterne da XMLDSig ed espansione del namespace; conservarne
la descrizione e verificarle contro gli originali quando disponibili.
Package.swift non dichiara DSS Java come dipendenza: qui DSS è la provenienza
indicata per XAdES; non si attesta un confronto con il validatore DSS6.5.

Apache2.0 resta la licenza del codice originale Signum. I testi ETSI e FreeType
presenti contengono condizioni proprie, da conservare; non è una licenza unica
del pacchetto. Compatibilità complessiva NON DETERMINATA finché mancano le
licenze specifiche e le decisioni dei dossier. Nessuna certificazione legale.

`schema_license_contract.py` distingue inventario valido da ridistribuzione
pronta; `--require-ready` rifiuta le tre licenze non determinate. Non recupera
file dalla rete. Il futuro audit del pacchetto dovrà controllare schema bundle,
provenienza, testi e crediti reali, oltre alla closure Mach-O.
