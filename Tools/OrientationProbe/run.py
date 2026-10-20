#!/usr/bin/env python3
"""Preview-only native probe. Optional local PDF is snapshotted, never signed."""
from pathlib import Path
import subprocess
import os
import sys
root=Path(__file__).resolve().parents[2]
out=root/".build/04stabilization-b12/probe"
products=root/".build/reliability/out/Products/Debug"
maps=root/".build/reliability/out/Intermediates.noindex/GeneratedModuleMaps"
app=out/"SignumOrientationProbe.app/Contents"
(app/"MacOS").mkdir(parents=True,exist_ok=True)
(app/"Info.plist").write_text("""<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.github.tiertoast.Signum.OrientationProbe</string>
<key>CFBundleExecutable</key><string>SignumOrientationProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>NSHighResolutionCapable</key><true/></dict></plist>""")
args=["xcrun","swiftc","-O","-target","arm64-apple-macos13.0","-parse-as-library","-I",str(products),"-module-cache-path",str(out/"module-cache")]
for name in ["CPKCS11","CCertificatePolicy","COutputPermissions","CProcessCoordination","CSecurePIN"]:
    args+=["-Xcc","-fmodule-map-file="+str(maps/(name+".modulemap"))]
args += [str(root/"Sources/SignumApp"/name) for name in ["PAdESPlacementPane.swift","PAdESRenderCoordinator.swift","SignaturePlacementOverlay.swift"]]
args += [str(root/"Tools/OrientationProbe/Probe.swift")]
args += [str(products/(name+".o")) for name in ["SignumCore","CPKCS11","CCertificatePolicy","COutputPermissions","CProcessCoordination","CSecurePIN"]]
args += ["-framework","Security","-framework","CoreFoundation","-o",str(app/"MacOS/SignumOrientationProbe")]
subprocess.run(args,cwd=root,check=True)
os.execv(str(app/"MacOS/SignumOrientationProbe"),["SignumOrientationProbe"]+sys.argv[1:])
