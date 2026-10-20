#!/usr/bin/env python3
"""Prepare only the fixed local memory experiment with the official watchdog."""
from pathlib import Path
import argparse, importlib.util, json, hashlib, uuid
p=argparse.ArgumentParser(description=__doc__)
for name in ['source','prefix','cmake','output-root']:p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--revision',required=True);a=p.parse_args();source=a.source.resolve()
spec=importlib.util.spec_from_file_location('official',source/'scripts/test-local.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
r=m.Run(argparse.Namespace(output_root=str(a.output_root.resolve())),dict(group='14C2-profile-preparation',revision=a.revision,cmake=str(a.cmake),ctest=str(a.cmake.with_name('ctest')),prefix=str(a.prefix)))
try:
    r.command('swift-release',['xcrun','swift','build','-c','release','--scratch-path',r.root/'swift','--jobs','4','-Xswiftc','-enable-testing'],600)
    helper=r.native('pades-release','Tools/PAdESPrototype','Release')/'signum-pades-local'
    fixture=source/'.build'/('memory-profile-'+uuid.uuid4().hex)
    r.command('synthetic-provider',['python3',source/'scripts/prepare-batch-demo.py','--output',fixture])
    config=dict(source=str(source),root=str(r.root),helper=str(helper),fixture=str(fixture),revision=a.revision)
    (r.root/'profile-build.json').write_text(json.dumps(config,indent=2)+'\n')
    files=[p for directory in ['Sources','Tests','Tools','scripts'] for p in (source/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files+=[source/'Package.swift']
    (r.root/'source-sha256.json').write_text(json.dumps({str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)},indent=2)+'\n')
    r.write_summary('passed')
except Exception:r.write_summary('failed');raise
