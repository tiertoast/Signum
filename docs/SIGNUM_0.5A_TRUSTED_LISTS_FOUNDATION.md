# Signum 0.5-A — Trusted Lists Foundation (initial increment)

**Status:** initial ingestion history below. An isolated native authentication proof is now locally verified; see [authentication PoC report](SIGNUM_0.5A_LOTL_AUTHENTICATION_POC.md) for results and remaining gates. No GUI integration or qualification verdict.

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

## Additional preparation increment — continuity and negative cases (20 October 2026)

A second isolated component, TLContinuityPolicy.swift, now compares two **untrusted revision observations**. It provides initial / unchanged / newer *candidates* or rejection for expired data, implausible future issue time, changed territory, version downgrade, sequence rollback, changed document under a reused sequence number, and issue-time rollback. It consumes a caller-supplied 32-byte XML SHA-256 value. It does NOT calculate that hash, authenticate the input, fetch a URL or authorize publishing to an authenticated cache. The eventual signature-verification pipeline MUST authenticate both the candidate and the previously accepted revision before acting on the comparison.

Tests added: 7 TLContinuityPolicy XCTest methods and 4 parser negative cases (missing signature is still parsed strictly as untrusted data; foreign-namespace status spoofing; malformed Base64 identity; non-positive TSL sequence). Total target source contains 18 XCTest methods, subject to independent macOS execution. Local Swift 6.2.1 Linux compiler smoke-tested the standalone continuity model with strict-concurrency diagnostics; this is **not** a run of the whole package test target.

### Next Codex-only task: authenticated LOTL/TL ingestion

This is the highest-risk portion and should be handled on macOS using native builds and tests, without changing the established signing engine.

1. Establish the actual current Official Journal anchor (OJ C/2026/1944), signing certificate digests, LOTL URL, and official pivot history; verify their bytes and effective periods against the notice rather than treating downloaded XML as an anchor.
2. Prototype a native XMLDSig/XAdES verification component (evaluate xmlsec + libxml2 + the existing OpenSSL). Verify *all* signed references, canonicalization and enveloped-signature transforms, SignedProperties, expected signature profile, signed document root, unique IDs, authorized signer identity, and schema/critical extensions. In TLv6 the published profile is XAdES-BASELINE-B (ETSI EN 319 132-1), whereas historical TLv5 uses XAdES BES. Reject algorithm/digest downgrade, wrapping attacks, external references, ambiguous roots and unauthenticated nested pointers.
3. Authenticate EU LOTL independently; only then use authenticated LOTL pointers and signer identities to retrieve and authenticate the AgID national TL. Do not turn arbitrary TLLocation fields into outbound network access. Define URL, redirects, size and timeout bounds.
4. Enforce publication policy: validate signature and source first, then apply version/sequence/issue/next-update continuity and preserve an atomic last-known-good authenticated snapshot. An offline or stale snapshot must be labeled as such, never silently become a current qualification verdict. Review TLContinuityPolicy against real-world rotation cases; enhance/restrict if necessary.
5. Verify independent results against the European Commission DSS and eIDAS Trusted List Browser, including historical, malformed, expired, replayed and intentionally altered fixtures.
6. Build/test arm64 macOS 13+ and package only the new isolated trust component. No claim of certificate trust, OCSP/CRL or qualified signatures yet; these belong to 0.5-B/C/D.

**Hard scope:** no editing 0.4 release/tag, no GitHub Actions, no HalleyMac, no PIN/hardware, no PR merge/release, no automatic GUI switch-on. Provide reproducible local test commands and independent evidence before integration.

Relevant 2026 normative notice: https://eur-lex.europa.eu/eli/C/2026/1944/oj/eng
European Commission TLv6 migration: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/967116974/Critical+Updates+Migration+to+TLv6+and+new+OJEU+Notice+for+the+EU+LOTL
