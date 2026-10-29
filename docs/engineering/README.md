# Engineering, provenance and assurance records

Current product instructions are in the [documentation index](../README.md).
The records below preserve revision-specific evidence, source correspondence
and unresolved engineering work. Historical results are not fresh passes on
later commits. Some original records are in Italian and may contain development
paths; they are archival evidence rather than current user instructions.

## Capability reference map

The current product guides were checked against these implementation entry points
and their engineering profiles. This is a documentation reference map, not a new
code review or test campaign.

| Capability | Implementation | Engineering profile |
| --- | --- | --- |
| Attached/detached CAdES | [CAdES](../../Sources/SignumCore/CAdES.swift), [advanced operations](../../Sources/SignumCore/CAdESAdvanced.swift) | [CMS operations](../archive/SIGNUM_0.6D_CADES_ADVANCED.md) |
| PDF signing/coverage | [native signer](../../Tools/PAdESPrototype/signum_pades_local.cpp), [verifier](../../Tools/PAdESPrototype/PAdESVerification.cpp), [coverage](../../Sources/SignumCore/PDFRevisionCoverage.swift) | [appearance](../archive/SIGNUM_0.4_PADES_APPEARANCE.md), [revision coverage](../SIGNUM_070_S01_PDF_COVERAGE.md) |
| XML | [XAdES](../../Sources/SignumCore/XAdES.swift), [native XML implementation](../../Sources/CXMLSecurity/xades.c) | [XAdES profile](../archive/SIGNUM_0.6B_XADES_BASELINE.md) |
| ASiC | [ASiC](../../Sources/SignumCore/ASiC.swift), [ZIP bounds](../../Sources/SignumCore/ASiCZIP.swift) | [ASiC profile](../archive/SIGNUM_0.6C_ASIC.md) |
| Trust and evidence | [certificate validation](../../Sources/SignumCertificateValidation), [trust authentication](../../Sources/SignumTrustAuthentication) | [current/historical policy](../archive/SIGNUM_0.6A_CURRENT_TIME_VALIDATION.md) |
| Reports | [report modules](../../Sources/SignumVerificationReports) | [report contract](../archive/SIGNUM_0.6E_VERIFICATION_REPORTS.md) |
| Batch authentication | [batch session](../../Sources/SignumCore/BatchCAdESSession.swift), [settings](../../Sources/SignumApp/SigningSettings.swift) | [batch foundation](../archive/SIGNUM_0.4_BATCH_AUTH.md), [temporary PIN](../archive/SIGNUM_0.4_SECURE_BATCH_PIN.md) |
| Desktop/CLI entry points | [Services](../../Sources/SignumApp/SystemDocuments.swift), [CLI commands](../../Sources/SignumCLI/main.swift), [Swift products](../../Package.swift) | [Finder integration](../archive/SIGNUM_0.7_BUILD7_ACCEPTANCE.md) |

## Release artifact and source correspondence

- [Build 14 ArtifactManifest](../releases/0.7.0-beta/ArtifactManifest.json)
- [Original publication evidence](../releases/0.7.0-beta/PublicationEvidence.json)
- Release assets: `BuildManifest.json`, `AppAudit.json`, `summary.json`, application
  inventory and DMG checksum. These retain their recorded values and scope.
- [Native checkpoint](../PHASE7_NATIVE_CHECKPOINT.md),
  [packaging checkpoint](../PHASE8_PACKAGING_CHECKPOINT.md),
  [packaging procedure](../PUBLIC_BETA_PACKAGING.md)
- [Source access](../../Resources/ThirdPartySources/SOURCE_ACCESS.md),
  [source inventory](../../Resources/ThirdPartySources/SOURCE_INVENTORY.json),
  [PoDoFo dossier](../PODOFO_SOURCE_DOSSIER.md),
  [FreeType dossier](../FREETYPE_DOSSIER.md),
  [schema-license dossier](../SCHEMA_LICENSE_DOSSIER.md)

Legal originals, licenses and source/provenance materials remain at stable paths
and are not translated or reclassified by the product documentation.
The DMG's original Italian packaging notes remain embedded unchanged.

## Open assurance work

[M3–M6 tracking issue #9](https://github.com/tiertoast/Signum/issues/9) remains open,
category (e), with recurrence causes not isolated and follow-up deferred. No new
fix, skip, timeout relaxation or campaign is implied. The RC stability gate is
**not passed**. See [stability evidence](../SUITE_STABILITY.md),
[local checks](../LOCAL_TESTING.md),
[historical Phase5b status](../PHASE5B_RELEASE_STATUS.md) and
[current readiness](../RELEASE_READINESS.md).

## Historical archive

[Historical engineering reports](../archive/README.md) retain the original
implementation chronology and results separately from product guides. Reports
referenced directly by code or packaging contracts keep their stable original
paths. Versioned source remains available through the preserved Git tags even
where obsolete GitHub Release entries are removed.
