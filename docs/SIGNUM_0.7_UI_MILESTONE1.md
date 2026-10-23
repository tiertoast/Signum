# Signum 0.7 — UI milestone 1: native signing shell

## Intent

Keep the validated 0.6 signing, approval, secure PIN, device discovery, and
verification engines unchanged. Give ordinary users a document-first macOS
workspace with technical information available on demand.

## Implemented

- Native `NavigationSplitView` sidebar with Firma, Verifica, Dispositivi and
  interim Impostazioni destination; no segmented page selector.
- Contextual native toolbar actions for adding documents and rediscovering devices.
- Burgundy `#64313E` used as a restrained window accent, rather than a background.
- Compact signing summary (format, signer, output), expandable certificate,
  format/destination, and device/connection sections.
- Clear drag-and-drop empty state; existing multi-document queue, individual
  format selection, PAdES placement preview, PIN, consent, cancellation, and
  outcome-review states remain connected to the original coordinators.
- Shared appearance and summary/empty-state components in
  `Sources/SignumApp/SignumUIComponents.swift`.
- No new cryptographic formats, engine changes, preferences migrations, or
  dependencies. macOS 13 remains the minimum.

## Deliberate next milestones

1. Refine the document list/preview and signing-operation state presentation.
2. Redesign verification to show person + fiscal code + separate top-level
   outcomes; retain detailed explanations and PDF/TXT export.
3. Refine device discovery/status and move settings into standard native
   macOS settings presentation.
4. Validate native materials on current macOS, Light/Dark Mode, VoiceOver,
   keyboard navigation, minimum window size, and older supported macOS.

## Local acceptance gate

Automated Build 1 validation has been run; manual acceptance is still pending.
See [results and manual checklist](SIGNUM_0.7_BUILD1_ACCEPTANCE.md).

- Build and launch the macOS app with the local preview packager; do not use
  GitHub Actions. Verify native sidebar, toolbar, resizing, and both appearances.
- Load one PDF, preview/position the PAdES signature, return to document list,
  and verify that approval is blocked before the required preview is ready.
- Select DigitalDNA/CNS certificate; test user consent, PIN focus, cancel,
  successful signing, existing-file collision, and completion.
- Test multi-file and CAdES/XAdES/ASiC format choices, detached/co/countersign
  selection, without changing their 0.6 constraints.
- Open verification and devices pages; inspect report/export functionality,
  offline/no token states, and switching sections while signing is locked.

Do not merge into `main` or publish a release until local build and
manual GUI acceptance are complete.

## Build 2

The signing workspace and completed-session presentation are superseded by
[Native Experience Build 2](SIGNUM_0.7_BUILD2_ACCEPTANCE.md).
