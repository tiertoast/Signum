# Signum 0.5-E4 — European integration and Development Preview Build 6

Baseline E3 `465999d81267bfe266ff77245cd307c57af6ff96`; existing European branch.
Scope: application integration, minimal Settings/verification changes and the
existing native packaging recipe. No CAdES, PAdES, PKCS#11, PDF appearance,
XMLDSig/RSA-PSS or B/C/D/E2 engine changes, new standards or dependencies.

## Application integration

`TrustedListsModel.developmentPreview` owns one `EuropeanTrustCatalogService`.
A typed `EuropeanCatalogProvider` shares it with the existing verification workspace;
`EuropeanValidation` selects actual matching cached services or bounded issuer
country hints and retains all existing trust/evidence gates. Startup reads the
cache asynchronously and schedules only the caller-owned automatic refresh task.
No national list is downloaded on first startup without selection; existing
national caches remain the automatic refresh selection. Shutdown and verification
cancellation propagate to their tasks; signing does not await trust work.

Settings retains its GroupBox and update control. It shows available LOTL
territories, present national cache files, usable service counts, expiry and
coverage limits. A country picker restricts manual acquisition to one selected
list. The offline switch prevents new trust/revocation requests for subsequently
started operations and uses authenticated cache/evidence only; it does not claim
to retract a request already sent by an earlier verification. Cache presence is
not displayed as authentication: unavailable/expired files remain visible but are
not passed to the validator. Selective refresh results are followed by a local
reauthentication of installed caches so other countries' states stay visible.
Failures preserve prior files and are shown separately from usable current data.

The existing verification panel keeps integrity, X.509 path, revocation, time and
qualification separate, with reasons and country/service when established.
Off-main-thread validation reuses the existing E2 API and per-SignerInfo/PDF binding.
The Italian legacy adapter remains for existing clients/tests, but the production
Preview uses the coordinated European provider. Positive qualification stays
restricted to tested IT/AT/DE/BE/FR/ES direct CA/QC post-2016 profiles with sufficient
bound time and revocation evidence. An authenticated/interpretable service alone
never proves QES. No broad historical/LTV/PAdES-LT/LTA claim is made.

## Build and isolation

The existing preview packager accepts build number 6 and reuses its native prefix,
dependency closure, path rewriting, minimum-OS checks and ad hoc signing. Like
Build 5, it omits duplicate native CTest/helper-integration campaigns already covered
by the final official runner. Existing builds and the 0.4 resource metadata remain
untouched. No dependency is installed globally or added to the application.

Bundle identifier: `io.github.tiertoast.Signum.DevelopmentPreview.B6`.
Trusted cache: `~/Library/Application Support/io.github.tiertoast.Signum.DevelopmentPreview.B6/TrustedLists`.
Revocation cache: `~/Library/Caches/io.github.tiertoast.Signum.DevelopmentPreview.B6/Revocation`.
Standard application preferences use the B6 bundle domain; the offline switch is a
session control. Old preview caches are not imported or changed.
Target: arm64/macOS 13.0. This target is checked in Mach-O metadata, not a claim
that the app was executed on macOS 13. Developer tools/Homebrew are used only for
building; runtime closure must contain all non-system native libraries.

`test-preview6-bundle.py` reuses the packager diagnostics and production OJ/pivot
service. It relocates the finished app, authenticates a selective EU/IT update,
reads that coordinated cache offline without writes, audits loaded libraries with
a system-only PATH, and starts the relocated GUI for the native panel check.
It accesses no personal document, token, PIN or private key. The probe's two new
European diagnostic commands call the existing E2 service unchanged.

## Validation policy

One targeted integration phase uses existing synthetic fixtures (no corpus
regeneration): selective acquisition, malformed refresh preservation, offline
restart, expired/missing cache, existing native pane rendering and both CAdES/PAdES
multi-signer documents through the actual workspace with five independent results.
Legacy Italian integration and verification cancellation tests are included.
One compilation diagnostic (duplicate local binding in the legacy adapter) was
corrected before test execution. Final results are recorded below and in the
companion machine-readable results file.

One official complete campaign follows the targeted phase. Sanitizers are not
repeated: changes contain no new native/unsafe-memory boundary. Release packaging,
relocation/startup and panel acceptance are performed separately once for Build 6.
DSS execution remains **not performed**: no ready runtime was found in E3; no
Java/DSS/Maven install or remote demo submission is made for E4. The E3 comparison
plan remains deferred and does not block this Preview or prove DSS equivalence.

## Final campaign and post-campaign coverage

The single complete official campaign passed: **559 Swift tests** (Core 430,
TrustCore 19, Authentication 34, Integration 5, CertificateValidation 71), PAdES
81 cases each Debug/Release, PKCS#11 58 provider cases plus 2 loader contracts,
and 18 packaging/runner contracts. The targeted phase passed 14 tests (5 legacy
Italian integration, 5 verification lifecycle, 4 new European app integration).
No production code changed after this campaign or the Release packaging.

Inspection of the new rendering artifact revealed that an unattached hosting view
could produce an empty bitmap despite its dimensions passing. After the complete
campaign, **only this test** was strengthened: attach a native window, display the
view and require visible pixel variation. Only that rendering case is rerun; the
complete suite is not repeated after this test-only correction. Its first focused
invocation selected the dynamic packaging prefix instead of the original static
development prefix and could not load libcrypto before executing any test. The
original complete-run development environment was restored for the focused run.
This diagnostic failure was not a failure of the independently tested app bundle.

The relocated production probe authenticated EU LOTL **397**, discovered **30**
UE/EEA territories and selectively acquired **IT only** (434 interpretable services).
It then reauthenticated the coordinated cache offline, with identical cache bytes.
The GUI stayed alive with a system-only PATH and all loaded non-system libraries
inside the relocated bundle. The local ZIP was generated from the sealed original
bundle; original and relocated apps are distinct copies of the same packaged code.

Automated control of the real app failed twice with `native pipe closed` and was
not bypassed through other UI automation. The human user explicitly confirmed:
**“Pannello aperto e dati visibili”** for Settings → Elenchi fiduciari in Build 6.
This is user-observed panel acceptance, separate from the native rendering test.
Online end-to-end acquisition in the packaged app/probe covers EU/IT; six-country
qualification coverage remains the existing synthetic/frozen-fixture coverage,
not a claim of real QES validation in every country. DSS remains unexecuted.

The corrected single rendering test passed and its image was inspected: native
controls, available/acquired countries, dates and profile limits are visible.
No production correction followed the full campaign. Build 6 .app/.zip, logs and
images are in `outputs/signum-0.5e4` in the task workspace; exact absolute artifact
paths, ZIP/executable hashes, runner results and the human panel confirmation are
recorded in `SIGNUM_0.5E4_RESULTS.json`. All mandatory gates are closed with that
explicit distinction between automated checks and user-observed acceptance.
The previously tested E2 historical/interpretation exclusions remain unchanged.
