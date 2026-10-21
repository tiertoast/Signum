#!/usr/bin/env python3
"""Build 6 relocation and production EU/IT cache smoke; no personal input or token.
The existing packager audits Mach-O deployment/closure/rpaths and seals the bundle.
This script tests the relocated bytes and leaves the GUI open for one panel check.
"""
import argparse, importlib.util, json, os, plistlib, shutil, subprocess, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('recipe', Path(__file__).with_name('build-beta-app.py'))
recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--bundle', type=Path, required=True); p.add_argument('--output-root', type=Path, required=True)
a = p.parse_args(); root = a.output_root.resolve(); root.mkdir(parents=True, exist_ok=False)
app = root/'Relocated'/a.bundle.name; app.parent.mkdir(); shutil.copytree(a.bundle.resolve(), app, symlinks=True)
info = plistlib.loads((app/'Contents/Info.plist').read_bytes()); identity = 'io.github.tiertoast.Signum.DevelopmentPreview.B6'
assert info['CFBundleIdentifier'] == identity and info['CFBundleVersion'] == '6'
assert info['LSMinimumSystemVersion'] == '13.0'
subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':os.environ['HOME'],'LC_ALL':'C','DYLD_PRINT_LIBRARIES':'1'}
cache = Path.home()/'Library/Application Support'/identity/'TrustedLists'
probe = app/'Contents/Helpers/SignumTrustProbe'
def run(name, args):
    result = subprocess.run(list(map(str,args)),env=env,capture_output=True,timeout=180)
    (root/(name+'.stdout.log')).write_bytes(result.stdout); (root/(name+'.dyld.log')).write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr.decode(errors='replace')[-1500:]
    recipe.audit_loaded(result.stderr.decode(errors='replace'),app)
    return result.stdout.decode()
online = run('selective-production-update',[probe,'europe-refresh',cache,'IT'])
assert 'country=IT freshness=current' in online, online
before = {f.name:f.read_bytes() for f in cache.glob('*.json')}
offline = run('authenticated-offline-cache',[probe,'europe-offline',cache])
assert 'source=cache' in offline and 'country=IT freshness=current' in offline
assert before == {f.name:f.read_bytes() for f in cache.glob('*.json')}
with (root/'gui.stdout.log').open('wb') as out, (root/'gui.dyld.log').open('wb') as err:
    process = subprocess.Popen([str(app/'Contents/MacOS/Signum')],env=env,stdout=out,stderr=err,start_new_session=True)
time.sleep(4)
assert process.poll() is None, 'GUI exited during startup'
recipe.audit_loaded((root/'gui.dyld.log').read_text(errors='replace'),app)
result = {'status':'passed','bundleID':identity,'relocatedBundle':str(app),'minimumOS':'13.0',
          'macOS13RuntimeTested':False,'cache':str(cache),'selectiveUpdate':online,'offlineCache':offline,
          'startupPID':process.pid,'startup':'alive after four seconds; panel check pending',
          'environment':'system PATH, no DYLD search overrides; loaded libraries audited',
          'DSS':'not executed; no ready runtime; not a Build 6 gate'}
(root/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('Relocation, production selective EU/IT update, authenticated offline cache and GUI startup passed.')
