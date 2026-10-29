# Signum 0.7.0 Beta — local packaging notes

This document is input for future local packaging. For the published product,
use the [current release notes](RELEASE_NOTES.md).

Build 14 targets Apple Silicon arm64 and declares macOS 13.0. Distribution is
ad-hoc signed, without Developer ID or notarization. PKCS#11 middleware is
installed separately. Included libraries, notices and source-access materials
retain their own terms; Signum original code remains Apache-2.0.

A local build or startup/loader audit is not complete OS, device or functional
qualification. M3–M6 remain open and the RC stability gate is not passed.
Production distribution, clean-Mac, accessibility and broader compatibility
acceptance remain separate. The app does not disable system protections.

The already published DMG contains the earlier Italian packaging notes frozen
inside that artifact. Updating this repository document does not change its bytes.
