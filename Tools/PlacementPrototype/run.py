#!/usr/bin/env python3
"""Synthetic A/B: isolated annotation reference versus current production overlay.
Pass --products and --maps from the SAME fresh Release Swift build.
This visual probe is supplementary; acceptance uses the official UI/output tests.
"""
from pathlib import Path
import argparse, subprocess, tempfile, os
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--products',type=Path,required=True);p.add_argument('--maps',type=Path,required=True)
p.add_argument('--variant',choices=['zero','translated','rotated'],default='rotated')
p.add_argument('--auto-close',action='store_true')
a=p.parse_args();root=Path(__file__).resolve().parents[2]
out=Path(tempfile.mkdtemp(prefix='signum-placement-',dir=root/'.build'))
pane=(root/'Sources/SignumApp/PAdESPlacementPane.swift').read_text()
# Compile the exact current viewport type; no second implementation of live geometry.
(out/'Viewport.swift').write_text('import AppKit\nimport PDFKit\nimport SignumCore\n'+pane[pane.index('final class PlacementPDFView:'):pane.rindex('#endif')])
cmd=['xcrun','swiftc','-O','-target','arm64-apple-macos13.0','-parse-as-library','-I',a.products]
for name in ['CPKCS11','CCertificatePolicy','COutputPermissions','CProcessCoordination','CSecurePIN']:
    cmd+=['-Xcc','-fmodule-map-file='+str(a.maps/(name+'.modulemap'))]
cmd += [root/'Tools/PlacementPrototype/Reference/ReferenceRenderer.swift',out/'Viewport.swift',root/'Sources/SignumApp/SignaturePlacementOverlay.swift',root/'Tools/PlacementPrototype/Probe.swift']
cmd += [a.products/(name+'.o') for name in ['SignumCore','CPKCS11','CCertificatePolicy','COutputPermissions','CProcessCoordination','CSecurePIN']]
cmd += ['-framework','Security','-framework','CoreFoundation','-o',out/'probe']
subprocess.run([str(x) for x in cmd],check=True,timeout=120)
subprocess.run([str(out/'probe'),a.variant]+(['--auto-close'] if a.auto_close else []),check=True,timeout=30 if a.auto_close else None)
