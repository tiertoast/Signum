# Signum 0.6 — Final polish / Development Preview Build 3

Baseline `2aa4110b3eede2d743659dd26d33f1930bd51eac`; existing 0.6-E branch.

## Identity boundary

The existing CertificateIdentityReader is reused, not duplicated. Presentation
reads only SignatureVerificationResult.signerDER, with its certificate fingerprint
matching; no arbitrary embedded certificate, DN display string, signer order or
country is used as proof of identity/trust. All supported formats share this result.
Personal name uses unambiguous Subject givenName + surname. CN-only/incomplete
personal names are unavailable; the original Subject remains in details.
Structured personal Italian CF: serialNumber TINIT-, exact Italian bare CF, or the
existing personal CNS CF/DEVICE-ID CN profile when serialNumber is absent. Supports
omocodia; no arbitrary substring scan. VAT/NTR/company IDs excluded. Duplicate
conflicting Subject attributes become unavailable. CF extraction is not a registry
or checksum attestation; all existing crypto/path/revocation/time/eIDAS gates remain.

The summary and details of the existing GUI show name, CF and individual integrity;
PDF/TXT share the same bound identity and independent five outcomes. A4, Burgundy
reports, native UI styling and bounded exclusive output retained. Large signer
sets continue across summary pages; identities/outcomes are never merged together.

## Focused validation

26 focused tests pass (8 certificate identity, 18 reports), including Italian,
foreign, corporate, missing/ambiguous fields, omocodia, malformed DER, mismatched
certificate fingerprints, distinct signer/counter identities and outcomes across
CAdES/PAdES/XML/ASiC reports, first-page PDF and TXT summary, safe writes and layout.
An initial local-variable naming compilation collision was corrected before tests.
The five-page updated synthetic PDF was rendered and every page visually inspected.

Build 3 identity: `io.github.tiertoast.Signum.DevelopmentPreview.V06.B3`, version
0.6.0, build 3; existing Build 1/2 and release 0.5 identity recipes preserved.
Only packaging metadata and identity presentation/extraction change in this task;
no new signature profile, dependency, eIDAS policy or signing/worker operation.

Full regression, exact source commit and packaging evidence are recorded in the
subsequent delivery section. Notes/checklist: SIGNUM_0.6_RELEASE_NOTES.md.
No merge/tag/release/branch deletion is authorized before manual acceptance.

## Final regression and bundle evidence

One official complete campaign passed on clean source commit **`fc59d0a17ab33571129e6cfb1fe993b5e2589d27`**.
Runner: `scripts/test-local.py --group complete --skip-sanitizers --native-prefix
../a3-native-v3/prefix --output-root ../06-build3-campaign`, with the existing private
pkg-config/xmlsec prefix and Python environment. Run evidence:
`work/06-build3-campaign/20261022T074937Z-49d7197ca5`.

**635 Swift tests** (Core 475, CertificateValidation 102, TrustAuthentication 34,
TrustCore 19, TrustIntegration 5); **81 PAdES cases each Debug/Release**;
**58 PKCS#11 provider + 2 loader contracts**; **19 runner/packaging contracts**.
**0 failures/skips**. No full rerun, source correction or sanitizer repetition.
The earlier 26 focused tests and all-page PDF visual inspection are separate.

BuildManifest seals that exact source commit with **sourceTrackedDirty=false**.
This appended delivery evidence is a subsequent documentation-only commit;
application/native/test/packaging source provenance remains the commit above.
No rebuild is necessary for a documentation-only delivery entry.

Passed private dependency closure, all Mach-O arm64/minimum-OS checks,
loader-relative dependencies and rpath audit, development-path rejection, nested
hashes, strict/deep ad hoc codesign, synthetic helper/worker IPC, relocation and
GUI alive after four seconds with system-only PATH and loaded-library audit.
The GUI smoke terminates its own process so logs are final.
The isolated B3 EU/IT cache was deliberately populated with a copy of existing
public authenticated data for the smoke, reauthenticated offline with current
freshness and byte preservation; no preference migration was added.
ZIP extraction preserves all bytes, executable permissions and symlink targets;
extracted codesign and manifest verify. Host: macOS 27.2;
macOS 13 is a validated deployment target, **not an executed OS test**.
Nonfatal existing toolchain warnings (filtered xmlsec pkg-config defines and
mapped PCM paths missing during dsymutil) are preserved in logs; all gates pass.

## Candidate artifacts and acceptance

`outputs/signum-0.6-build3/` contains:

- `Signum 0.6 Development Preview — Build 3.app` and `.zip`;
- `BuildManifest.json`, `SHA256SUMS.txt`, `bundle-inventory.json`, `results.json`;
- `RELEASE_NOTES.md`, `MANUAL_ACCEPTANCE.md`, `BRANCH_CLEANUP_AFTER_MERGE.md`;
- `report-example/` (synthetic PDF/TXT) and validation/log evidence.

ZIP SHA-256: **`924212c704913431dcde416722e799fc588edc74ef87e1ed9edd2e02e1edb124`**.

Source/main comparison: the 0.6 A/B/C/D branch heads are ancestors of this candidate;
main contains two additional documentation commits, whose README/roadmap content
is preserved and extended here. Branch cleanup is only a proposed list: fetch
actual heads and check ancestry to main again **after** the approved merge, and
do not delete non-ancestors or infer safety from a squash/rebase merge.
Historical releases `v0.4.0-beta.14` and `v0.5.0-beta` remain preserved.

The PR is prepared as a draft toward main. `v0.6.0-beta` release notes are ready,
with no release/tag created. No GitHub Actions workflow or dispatch, merge,
branch deletion, GUI redesign or change to HalleyMac. Manual acceptance of Build 3
must precede publication. Hardware/PIN/personal-document tests remain manual.

### PR preparation status

Draft PR: https://github.com/tiertoast/Signum/pull/6 . GitHub reports
`CONFLICTING`: README.md and docs/ROADMAP.md overlap main’s two documentation
commits. A read-only `git merge-tree <base> origin/main HEAD` diagnostic confirms
only those documentation conflicts; it does not merge refs or change the index.
No engine/source conflict or artifact-integrity problem is observed. The Build 3
candidate is ready for manual acceptance; the draft PR is **not yet mergeable**.
Resolve these documentation overlaps as part of the explicitly approved merge
preparation after acceptance. No merge, rebase/force-push or main modification is
performed to bypass the current no-merge gate. The artifact/source hash is unchanged.
