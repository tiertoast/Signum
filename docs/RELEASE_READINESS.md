# Release readiness

Signum **0.7.0 Beta — Build 17** is an experimental prerelease for Apple Silicon.
The [release notes](RELEASE_NOTES.md) describe the product and installation scope.
This record concerns release assurance, not the features of an earlier version.

| Area | Current boundary |
| --- | --- |
| Distribution | Ad-hoc signature; no Developer ID, hardened-runtime qualification or notarization |
| OS compatibility | Minimum 13.0 declared; real macOS 13/14 and clean-machine acceptance remain open |
| Hardware/middleware | Device-specific evidence only; no universal vendor/token certification |
| Stability | M3–M6 campaign green on 2026-11-24 (80/80 runs, 4 cells; [issue #9](https://github.com/tiertoast/Signum/issues/9) closed). RC stability gate not yet declared passed: five-class and pertinent-selection campaigns pending |
| Accessibility/manual experience | Remaining checks are not promoted to completed acceptance |
| Standards and trust | Explicit supported profiles; no blanket eIDAS/QES, LT/LTA or interoperability certification |
| Artifact | Released DMG and linked manifest evidence retained unchanged |

Historical manifests retain `publicationQualified:false`; the Beta release channel
does not convert that technical evidence into a production qualification.
No Stable or RC designation is claimed.

Developer ID, installation/updates, a defined support matrix and reproducible
distribution are forward work in the [roadmap](ROADMAP.md).
[Engineering records](engineering/README.md) retain the detailed evidence and open findings.
