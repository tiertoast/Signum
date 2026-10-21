#!/usr/bin/env python3
"""Local preview relocation, Mach-O closure, signatures and online/offline TL check."""
import argparse, importlib.util, json, os, plistlib, shutil, subprocess, tempfile
from pathlib import Path
spec = importlib.util.spec_from_file_location('packager', Path(__file__).with_name('build-beta-app.py'))
packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle', type=Path, required=True)
parser.add_argument('--output-root', type=Path, required=True)
parser.add_argument('--build-number', type=int, choices=(3,4), default=4)
args = parser.parse_args(); root = args.output_root.resolve(); root.mkdir(parents=True, exist_ok=True)
app = root / 'Relocated' / args.bundle.name
app.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(args.bundle.resolve(), app, symlinks=True)
info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
assert info['CFBundleIdentifier'] == 'io.github.tiertoast.Signum.DevelopmentPreview' + ('.B4' if args.build_number == 4 else '')
assert info['CFBundleVersion'] == str(args.build_number)
assert info['CFBundleShortVersionString'] == '0.5.0' and info['LSMinimumSystemVersion'] == '13.0'
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)], check=True)
files = [app/'Contents/MacOS/Signum'] + list((app/'Contents/Helpers').glob('*')) + list((app/'Contents/Frameworks').glob('*'))
macho = []
for file in files:
    if not file.is_file(): continue
    description = subprocess.check_output(['/usr/bin/file',str(file)],text=True)
    if 'Mach-O' not in description: continue
    assert subprocess.check_output(['/usr/bin/lipo','-archs',str(file)],text=True).strip() == 'arm64'
    load = subprocess.check_output(['/usr/bin/otool','-l',str(file)],text=True)
    assert packager.minimum(load) <= (13,0,0)
    for path in packager.rpaths(load): assert packager.system(path), path
    deps = packager.dependencies(subprocess.check_output(['/usr/bin/otool','-L',str(file)],text=True))
    for dep in deps:
        if packager.system(dep) or dep == '@rpath/'+file.name: continue
        assert dep.startswith('@loader_path/'), dep
        target = (file.parent/dep.removeprefix('@loader_path/')).resolve(strict=True)
        assert app in target.parents, target
    macho.append(str(file.relative_to(app)))
env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':os.environ['HOME'],'LC_ALL':'C','DYLD_PRINT_LIBRARIES':'1'}
probe = app/'Contents/Helpers/SignumTrustProbe'; cache = root/'cache/verified.json'; outputs={}
for mode in ['refresh','offline']:
    r = subprocess.run([str(probe),mode,str(cache)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    (root/(mode+'.stdout.log')).write_bytes(r.stdout); (root/(mode+'.dyld.log')).write_bytes(r.stderr)
    assert r.returncode == 0, r.stderr.decode(errors='replace')[-1000:]
    assert b'freshness=current' in r.stdout and (b'source=network' if mode=='refresh' else b'source=cache') in r.stdout
    packager.audit_loaded(r.stderr.decode(errors='replace'),app)
    outputs[mode] = r.stdout.decode().strip()
if args.build_number == 4:
    fixture = Path(__file__).resolve().parents[1]/'Tests/SignumCertificateValidationTests/Fixtures/valid-untrusted.cms'
    r = subprocess.run([str(probe),'path',str(cache),str(fixture)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    (root/'untrusted-path.stdout.log').write_bytes(r.stdout); (root/'untrusted-path.dyld.log').write_bytes(r.stderr)
    assert r.returncode == 0, r.stderr.decode(errors='replace')[-1000:]
    assert b'integrity=verified chain=notVerifiable revocation=notChecked qualification=notChecked' in r.stdout
    packager.audit_loaded(r.stderr.decode(errors='replace'),app)
    outputs['untrustedPath'] = r.stdout.decode().strip()
# Main executable startup is independent of the developer environment. No UI actions or signing.
process = subprocess.Popen([str(app/'Contents/MacOS/Signum')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    stdout,stderr=process.communicate(timeout=4)
    raise RuntimeError('GUI exited during startup: '+str(process.returncode))
except subprocess.TimeoutExpired:
    process.terminate(); stdout,stderr=process.communicate(timeout=10)
(root/'main-startup.dyld.log').write_bytes(stderr)
packager.audit_loaded(stderr.decode(errors='replace'),app)
assert b'libxmlsec1' in stderr and b'libcrypto.3' in stderr
result={'status':'passed','relocatedBundle':str(app),'architecture':'arm64','minimumOS':'13.0','macOS13RuntimeTested':False,
        'macho':macho,'trustedLists':outputs,'mainStartup':'alive after 4 seconds, then test terminated','environment':'system PATH; no DYLD search overrides; loaded closure audited'}
(root/'results.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result,indent=2))
