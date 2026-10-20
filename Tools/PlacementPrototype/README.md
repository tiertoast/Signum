# Placement reference

`Reference/ReferenceRenderer.swift` is TEST REFERENCE: frozen PDFKit stamp and
freeText paths, retained for thumbnail geometry/pixel and ownership assertions.
The target `SignumPlacementReference` is a dependency of the XCTest target only.
It is not linked into SignumApp, CLI or worker. Its tests do not prove live UI behavior.

The active viewer is `PlacementPDFView.updatePlacementOverlay` with
`SignaturePlacementOverlay`. The official suite exercises its viewport, rotations,
zoom/drag/resize, default stamp and signed-output equivalence separately.

The optional synthetic A/B probe compiles that exact current viewport type and
this isolated reference. It no longer reads an old Git pane, builds an alternative
overlay, or uses products from a hard-coded historical package. Pass `--products`
and `--maps` from the same fresh Release build, then `--variant rotated --auto-close`
for a bounded smoke. Run it through the official runner's `Run.command` watchdog.
No personal PDF is accepted. Manual viewing remains a separate diagnostic.
