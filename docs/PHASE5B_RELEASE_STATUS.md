# Phase 5b — release dossier and packaging prerequisites

This is a new status record. It does not revise historical Phase 5a outcomes.
By explicit author decision M3–M6 remain OPEN, category(e), deferred; no fixes
or reruns are part of Phase5b. The stability gate is NOT PASSED. No RC/Stable
promotion, packaging, signing, notarization or publication is authorized here.

## Findings and distribution decisions

- S16: scalar `C_FindObjects` returned counts greater than one are rejected in
  `find_one` and certificate enumeration; Final/CloseSession remain balanced.
  This is defensive count validation, not protection against arbitrary writes
  by an in-process vendor library. D03-bis batch PIN reuse policy is unchanged.
- S17: explicit FreeType product acknowledgment is packaged and hash-pinned;
  FTL/GPL selection remains an author decision. The original texts are intact.
  Credit correction is done; finding remains partial until that decision and
  the final package audit. No preferred credit formula is falsely mandatory.
- Schema licenses: inventory and gate in SCHEMA_LICENSE_DOSSIER.md; XAdES,
  XMLDSig and XML namespace schema licenses remain unresolved.
- PoDoFo: PODOFO_SOURCE_DOSSIER.md and ThirdPartySources/podofo.json remain
  incomplete. Original archive, patches, actual source/build correspondence,
  embedded components and a working recipient source-access route are needed.
  Signum original-code Apache2.0 does not relicense those components.

## Author-run verification, not run by Codex

`scripts/verify-phase5b.py` uses the existing CMake/CTest/cc and native metadata,
external new builds, macOS13 deployment and an overall default900-second
budget. It runs only targeted native tests and license contracts; never Swift
or M3–M6. Process groups are stopped on timeout/signal/error and leaders reaped.
It writes summary.json with status/counts/failed tests/duration. Detailed
command logs are retained only for failures. Known distribution blockers give
status `blocked`/exit1 even when the technical tests pass. This is not RC
qualification. ASAN disables leak detection; TSAN on the scalar harness is not
a general concurrency qualification. Script syntax was checked, pipeline not run.

Example for the current Mac, using only the validated prefix in read-only mode:

```sh
/usr/bin/timeout -k 2s 905s /usr/bin/python3 \
  /Users/andreaoregioni/Developer/Signum-Stabilization/worktree/scripts/verify-phase5b.py \
  --native-prefix /Users/andreaoregioni/Developer/Signum-0.7/.build/icon-native/prefix \
  --budget-seconds 900
```

The automatically created output is a new subdirectory of
Signum-Stabilization/diagnostics; --output may specify another NEW subdirectory
there. No existing build or log is overwritten. Source archives must be
supplied and approved separately; the script downloads nothing.

## Packaging remains a separate authorized operation

The actool version check and isolated compilation of the original icon now
pass (AppIcon.icns, Assets.car, macOS13 target). This supersedes the current
prerequisite assessment, not the preserved historical crash. No app/DMG was
built. It is not macOS13 runtime/clean-machine validation.

The existing app recipe fixes build scratch under REPO/.build and always
performs ad-hoc signing. It has no unsigned external-scratch Stable entrypoint.
Do not run it inside the preserved worktree or present its preview identity as
a release identity. No end-to-end app/DMG wrapper is supplied until the author
decides metadata, channel/signing policy, native source provenance and license
delivery, and approves the bounded recipe adjustment for external scratch.
The existing DMG builder is a subsequent step requiring a complete approved
app and release notes; it cannot fill those prerequisites.

Still required: source/notice dossier closure; native reconstruction and
dependency audit on the exact candidate; app/DMG resource/relocation checks;
macOS13/14 runtime, clean-machine and operator-approved device tests; explicit
decisions for previously unaccepted residuals. M3–M6 are deferred, not passed.
No gate or author decision is inferred from the targeted Phase5b green tests.
