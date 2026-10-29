# Schemi XAdES / W3C / DSS — evidenze locali e blocchi

Stato corrente Fase7: testi e avvisi dei sette schemi documentati; xml.xsd usa la via W3C Document2023 per derivati nel software, non una licenza software per-file inferita. Audit dell'artefatto ancora da eseguire. Le lacune riportate nelle sezioni datate sono storiche. Inventario e SHA-256 dei sette
XSD in `scripts/schema-license-catalog.json`; nessun byte XSD modificato.
Le origini sono quelle dichiarate in Schemas/PROVENANCE.md, non nuove attestazioni
upstream. Package.swift copia la directory Schemas nel bundle SwiftPM.

| Materiale | Evidenza originale disponibile | Stato / materiale mancante |
|---|---|---|
| Tre 19612_*.xsd | ETSI TS119612 v2.4.1, commit dichiarato 812fe781d37ead5b0ad562f2874ef5f67fc3a4dd; ETSI-LICENSE locale Copyright2024 | testo source/binary a tre condizioni presente, conservato anche come Notices/ETSI-TL.txt; corrispondenza upstream da attestare |
| xades.xsd | ETSI v1.3.1 e DSS: stessi byte upstream, import localizzato | Fase6b: LICENSE ETSI del medesimo tag recuperata; evidenza/diff archiviati |
| xmldsig.xsd | header Copyright2001 Internet Society/W3C, revisione2002-02-08, rinvio W3C19980720 | testo completo recuperato in Fase6, avvisi conservati |
| xml.xsd | snapshot W3C2009/01 e URL2001 confrontati, diff esatto archiviato | Fase7: Document2023 / grant per derivati nel software, policy e notice conservati |
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

## Fase6 — fonti pubbliche documentali

XMLDSig: il testo completo della licenza19980720 richiamata esplicitamente
dall'header è ora conservato in Resources/Notices/W3C-Software-1998.html,
con hash nel catalogo. W3C-Schema-Changes.txt mantiene gli avvisi di modifica
e la data del commit locale registrato. Nessun XSD è stato cambiato.

Restano non qualificate due risorse, xades.xsd e xml.xsd: il file DSS al commit
dichiarato è accessibile ma non espone una licenza specifica; xml.xsd servito
oggi dall'URL W3C non coincide byte per byte col file locale. Queste sole
consultazioni non chiudono applicabilità e provenienza. Non si trasferisce
la licenza XMLDSig a xml.xsd o la licenza generale DSS a XAdES. Le precedenti
indicazioni di tre lacune descrivono lo stato della Fase5b; lo stato corrente
è il catalogo aggiornato, con due licenze ancora da documentare.

## Fase6b — corrispondenza esatta e licenza ETSI recuperata

`xades.xsd`: chiusa la lacuna documentale. Il file ufficiale
https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd
è identico byte per byte al file DSS precedentemente identificato, SHA256
`457745286eaa292ae1aaa6e976e0f30eeceb0a37cc2301151576175e0ae1986c`.
Il tag ETSI v1.3.1 risolve a commit
`01ab58e88086f1b4ec1549cf9905cc63a4b791f7`, registrato dalla API ufficiale.
La LICENSE del medesimo tag è il testo Copyright2024 ETSI a tre condizioni,
SHA256 `d74b5c11a994434905178d2bb2accf881ef9955795dcd676432fbceefb8e36a6`,
identico al notice ETSI già presente. Si applica questa evidenza al file
specifico, non la licenza generale DSS. L'unica modifica è l'URL XMLDSig
sostituito con `xmldsig.xsd`: applicando quella sola sostituzione si ottiene
esattamente lo SHA locale `e1d0b9b7d152aca05dafbbb108c76ca7f90f276cc0418f31ddbd86676b458a72`.

`xml.xsd`: provenienza ricostruita, **licenza ancora aperta**. Snapshot datato
https://www.w3.org/2009/01/xml.xsd, SHA256
`cc701736c42cc64126fad063bb95f94484b5de3b5f808a86ea098b0957aff829`.
Rispetto ad esso il file locale modifica il percorso relativo dello stylesheet,
due schemaLocation nei soli esempi documentali e una riga vuota finale.
L'URL2001 corrente SHA256
`61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c`
produce i byte locali con le sole due sostituzioni schemaLocation degli esempi.
Sono confronti esatti di byte, non equivalenza generica di XML. Il file non
espone un testo/licenza espliciti; la policy W3C attuale consultata non lo
qualifica specificamente. La licenza2002 trovata nello stylesheet si riferisce
allo stylesheet: NON è trasferita allo schema. Nessun campo licenza promosso.
Azione concreta residua: ottenere da W3C un riferimento scritto alla licenza
che copre lo snapshot2009/01 e la sua ridistribuzione modificata, indicando
URL e SHA; oppure un originale ufficiale identico con avviso applicabile.
Non è stato inviato alcun messaggio a W3C.

Originali, risposta tag ETSI e diff integrali:
`Resources/ThirdPartySources/Evidence/`. Tutti i sette XSD runtime restano
immutati. Il gate conserva **una** risorsa irrisolta, xml.xsd. Gli stati delle
fasi precedenti rimangono storici, non riscritti come successi retroattivi.

## Fase7 — via documentale esplicita per xml.xsd, senza cambiarne i byte

La policy ufficiale https://www.w3.org/copyright/intellectual-rights/ nella
sezione sui documenti indica la Document License come regola predefinita per
i documenti pubblici W3C senza termini diversi. La versione vigente2023
https://www.w3.org/copyright/document-license-2023/ autorizza espressamente
opere derivate incluse nel software per facilitare l'implementazione delle
specifiche, con notice dedicato; vieta invece la ripubblicazione di una
specifica tecnica modificata. È questa la via scelta per il documento XML
pubblico attuale, non un'inferenza dalla licenza dello stylesheet o da XMLDSig.

La pagina ufficiale https://www.w3.org/XML/1998/namespace.html identifica
specificamente il file https://www.w3.org/2001/xml.xsd come frammento schema
per xml:lang/space/base/id. Il file attuale è stato nuovamente recuperato e
ha SHA25661960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c.
Con le sole due riscritture negli esempi documentali si ottengono i byte
locali già censiti. Non si sostituisce lo schema, né si elimina la validazione
xml:lang richiesta dagli schemi TL. Nessun test funzionale nuovo è necessario
perché nessun byte XSD o resolver è cambiato.

Base documentale: grant generale esplicito, non un header per-file che non
esiste. Campo licenseEvidence ne conserva esattamente l'ambito. Testo2023
integrale, policy e pagina namespace con hash sono conservati nei notice e
nell'inventario; W3C-XML-Namespace-Notice.txt reca l'avviso2023 prescritto,
origine e modifiche datate. La distribuzione riguarda il software di
validazione, senza qualificare come ufficiale una specifica modificata.
Il catalogo ora registra tutti i sette testi disponibili; questo controllo
tecnico non è una certificazione legale, né sostituisce l'audit dell'artefatto.
Le conclusioni Fase6b rimangono storiche e sono superate da questa evidenza.
