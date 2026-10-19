#!/usr/bin/env python3
"""Local-only A/B viewport probe. Optional PDF path is read-only, never signed."""
from pathlib import Path
import os
import subprocess
import sys
import re
root = Path(__file__).resolve().parents[2]
out = root / ".build/04stabilization-b11/prototype"
out.mkdir(parents=True, exist_ok=True)
baseline = subprocess.check_output(["git", "show", "718406a:Sources/SignumApp/PAdESPlacementPane.swift"], cwd=root, text=True)
# Log the *native callback* clip before/after the old annotation transform.
integrated = "--integrated" in sys.argv
if integrated:
    sys.argv.remove("--integrated")
    for name in ["PAdESPlacementPane", "PAdESPlacement", "AppearancePDFAnnotation", "AppearancePDFView", "PlacementPDFView"]:
        baseline = re.sub(r"\b" + name + r"\b", "Baseline" + name, baseline)
baseline = baseline.replace("context.saveGState()", 'context.saveGState(); print("ANNOTATION_INPUT_CLIP", context.boundingBoxOfClipPath)', 1)
baseline = baseline.replace("context.drawPDFPage(page);", 'print("ANNOTATION_ARTWORK_CLIP", context.boundingBoxOfClipPath); context.drawPDFPage(page);', 1)
(out / "BaselinePane.swift").write_text(baseline)
probe = (root / "Tools/PlacementPrototype/Probe.swift").read_text().replace("draws=\\(ProbeTrace.draws)", "draws=see-clip-trace")
if integrated:
    probe = probe.replace("let old=PlacementPDFView", "let old=BaselinePlacementPDFView")
    probe = probe.replace("let overlay=PrototypeOverlay(frame:fresh.bounds);overlay.autoresizingMask=[.width,.height];overlay.viewer=fresh", "let overlay=fresh.signatureOverlay")
    probe = probe.replace("fresh.addSubview(overlay,positioned:.above,relativeTo:nil)", "")
    probe = probe.replace("for v in [old,fresh] {v.install(document:PDFDocument(data:bytes)!,pageIndex:0)}", "old.install(document:PDFDocument(data:bytes)!,pageIndex:0); fresh.install(document:PDFDocument(data:bytes)!,pageIndex:0)")
    probe = probe.replace("overlay.update(art)", "fresh.updatePlacementOverlay(art)").replace("overlay.update(moved)", "fresh.updatePlacementOverlay(moved)")
    probe = probe.replace("[old,fresh]", "[old as PDFView,fresh as PDFView]")
(out / "Probe.swift").write_text(probe)
products = root / ".build/beta-package-release/out/Products/Release"
maps = root / ".build/beta-package-release/out/Intermediates.noindex/GeneratedModuleMaps"
if not (products / "SignumCore.o").is_file():
    sys.exit("Build a local Release bundle first (scripts/build-beta-app.py); no downloads are performed.")
app = out / "SignumPlacementProbe.app/Contents"
(app / "MacOS").mkdir(parents=True, exist_ok=True)
(app / "Info.plist").write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.tiertoast.Signum.PlacementProbe</string><key>CFBundleExecutable</key><string>SignumPlacementProbe</string><key>CFBundlePackageType</key><string>APPL</string><key>NSHighResolutionCapable</key><true/></dict></plist>""")
args = ["xcrun", "swiftc", "-O", "-target", "arm64-apple-macos13.0", "-parse-as-library",
        "-module-cache-path", str(out / "module-cache"), "-I", str(products)]
for name in ["CPKCS11", "CCertificatePolicy", "COutputPermissions", "CProcessCoordination", "CSecurePIN"]:
    args += ["-Xcc", "-fmodule-map-file=" + str(maps / (name + ".modulemap"))]
args += [str(out / "BaselinePane.swift"), str(root / "Sources/SignumApp/PAdESRenderCoordinator.swift"), str(out / "Probe.swift")]
if integrated:
    args += [str(root / "Sources/SignumApp/PAdESPlacementPane.swift"), str(root / "Sources/SignumApp/SignaturePlacementOverlay.swift")]
args += [str(products / (name + ".o")) for name in ["SignumCore", "CPKCS11", "CCertificatePolicy", "COutputPermissions", "CProcessCoordination", "CSecurePIN"]]
args += ["-framework", "Security", "-framework", "CoreFoundation", "-o", str(app / "MacOS/SignumPlacementProbe")]
subprocess.run(args, cwd=root, check=True)
# zero / translated / rotated are synthetic; local <absolute-path> reads that PDF.
os.execv(str(app / "MacOS/SignumPlacementProbe"), ["SignumPlacementProbe"] + sys.argv[1:])
