# Signum 0.5-A — Trusted Lists Foundation (initial increment)

**Status:** initial, isolated ingestion module; NOT an authenticated EU LOTL/TL implementation.

## Isolation

Development branch: feature/signum-0.5a-trusted-lists-foundation, based on the published 0.4.0 Beta Build 14 main branch.

New library/target: SignumTrustCore. The established SignumCore, SignumApp, signing workers, and PAdES helper do not depend on it. The signing behavior, UI, release metadata and packaging are unchanged.

## Implemented

- Swift/FoundationXML parsing of raw ETSI TS 119 612 XML namespace (http://uri.etsi.org/02231/v2#), including TSL versions 5 and 6.
- Explicit UntrustedTLDocument result: territory, sequence, issue and next-update times, providers, services, historical status, X.509 identity bytes and pointers to other TLs.
- Bounded UTF-8 input (64 MiB), maximum XML depth/nodes, disabled external entity resolution and rejection of DTD/entity declarations.
- Seven synthetic tests for v5/v6, history/pointers/identity bytes, malformed XML, namespace impersonation, DTD/entity injection, invalid UTF-8 and input size.
- Proof compilation: isolated Swift package with Swift 6.2.1 on Linux, 7/7 passed. This is NOT a macOS build or the full Signum test suite.

**Security invariant:** raw parsed fields and the mere presence of a ds:Signature are NEVER evidence of trust. This target exposes no trusted/valid/qualified conclusion. Embedded certificate bytes and raw TL pointers are not trust anchors or authorized network destinations.

## Remaining gates to complete 0.5-A

1. **LOTL trust bootstrap:** obtain and independently authenticate current EU LOTL signing certificates from the Official Journal; account for rotation and the official pivot-LOTL procedure. Never trust a certificate merely because it occurs in downloaded XML.
2. **XML signature and ETSI schemas:** validate the XAdES-BASELINE-B signatures required in TLv6, compatible historical TL signatures, XML canonicalization, all signed references, and the approved signer identity. Evaluate xmlsec in an isolated macOS native proof, including restrictions on URI dereferencing and test vectors; compare with the official EU DSS. XML parsing alone is not schema or signature validation.
3. **Authenticated LOTL-to-national-TL chain:** only authenticated LOTL pointers can authorize the location and signing certificate of a national TL. Reject unauthorized destinations, signing-certificate substitution, unsupported critical extensions and downgrade.
4. **Refresh and cache:** bounded downloads, deadlines and redirects, atomic last-known-good snapshots, sequence/issue-time rollback controls, expiry and NextUpdate, explicit offline/stale status. Never label stale data as currently trusted.
5. **Real and negative fixtures:** use current EU LOTL and AgID TL, key rotation and historical service status, cross-check official eIDAS browser/DSS. Expand to other EU/EEA countries.
6. **macOS gates:** compile with Apple Silicon/macOS 13+ and run the dedicated tests and established complete Signum suites before any application integration.

Only after authentication is complete should 0.5-B certificate-chain validation, 0.5-C revocation/time, and 0.5-D qualification determinations consume these records.

## Official references (checked October 2026)

- EU LOTL/pivot: https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html
- EU LOTL: https://ec.europa.eu/tools/lotl/eu-lotl.xml
- ETSI TS 119 612 v2.4.1: https://www.etsi.org/deliver/etsi_TS/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf
- European Commission TLv6 transition: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/967116974/Critical+Updates+Migration+to+TLv6+and+new+OJEU+Notice+for+the+EU+LOTL
- AgID TL: https://eidas.agid.gov.it/TL/TSL-IT.xml
- AgID signer certificate rotation: https://www.agid.gov.it/it/piattaforme/firma-elettronica-qualificata/certificati
- EU TL browser: https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls

No user document, smart-card PIN, token or PKCS#11 provider is involved in the ingestion component.
