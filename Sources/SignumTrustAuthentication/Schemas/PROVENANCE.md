# Bundled validation resources

TL schemas: ETSI TS 119 612 v2.4.1, official repository tag v2.4.1, commit
812fe781d37ead5b0ad562f2874ef5f67fc3a4dd:
https://forge.etsi.org/rep/esi/x19_612_trusted_lists

The three 19612_*.xsd files retain the accompanying ETSI license.
XAdES namespace 1.3.2 schema (revision 202407): European Commission DSS,
commit 9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33:
https://github.com/esig/dss/blob/9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33/specs-xades/src/main/resources/xsd/XAdES01903v132-202407.xsd

W3C resources:
https://www.w3.org/2001/xml.xsd
https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/xmldsig-core-schema.xsd

Local modifications: schemaLocation imports point exclusively to sibling files;
the XMLDSig schema's external DTD/internal entity declarations were removed and
the dsig namespace entity expanded to its literal URI. Schema definitions are
otherwise retained. validation.xsd is Signum's explicit import wrapper. No
instance-supplied schema location or network schema resolver is used.

The ETSI archive and historical 201601 XAdES endpoint returned HTTP 403 from
this host. The official tagged ETSI repository and DSS-hosted XAdES revision
were used instead. This is an interoperability proof, not certification of
every XAdES-BASELINE-B serialization.

Phase6b documentary verification (no XSD byte changes):
The original XAdES bytes above are identical to ETSI
https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd
at tag v1.3.1, commit01ab58e88086f1b4ec1549cf9905cc63a4b791f7.
LICENSE from that same tag is retained in the distribution notices; only the
XMLDSig import URL differs in Signum. W3C xml.xsd matches the dated2009/01
snapshot after the stylesheet relative path, two documented example imports
and terminal blank line changes recorded in the source evidence. Applicable
license for xml.xsd remains unresolved; no license inferred from its XSL file.
Full byte diffs and URLs/hashes are in Resources/ThirdPartySources/Evidence
and SOURCE_INVENTORY.json in the enclosing app distribution. These changes
were already present in local commit4311901f5ff15630ad638bea65e04c63ebf56e0b,
2026-10-20; Phase6b only documents them.
