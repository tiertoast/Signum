#!/usr/bin/env python3
"""Build 5 only: closure, ad-hoc seal, relocation, startup, one private InfoCamere input.
No document is copied into the repo or logged. Reuses production TL authentication.
"""
import argparse,hashlib,importlib.util,json,os,plistlib,shutil,subprocess
from pathlib import Path
spec=importlib.util.spec_from_file_location('recipe',Path(__file__).with_name('build-beta-app.py'));recipe=importlib.util.module_from_spec(spec);spec.loader.exec_module(recipe)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output-root',type=Path,required=True)
p.add_argument('--trusted-cache',type=Path,required=True);p.add_argument('--infocamere-document',type=Path,required=True)
a=p.parse_args();root=a.output_root.resolve();root.mkdir(parents=True,exist_ok=False)
app=root/'Relocated'/a.bundle.name;app.parent.mkdir();shutil.copytree(a.bundle.resolve(),app,symlinks=True)
info=plistlib.loads((app/'Contents/Info.plist').read_bytes());identity='io.github.tiertoast.Signum.DevelopmentPreview.B5'
assert info['CFBundleIdentifier']==identity and info['CFBundleVersion']=='5'
assert info['CFBundleShortVersionString']=='0.5.0' and info['LSMinimumSystemVersion']=='13.0'
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
macho=[]
for file in app.rglob('*'):
 if not file.is_file() or file.is_symlink():continue
 if 'Mach-O' not in subprocess.check_output(['/usr/bin/file',str(file)],text=True):continue
 assert subprocess.check_output(['/usr/bin/lipo','-archs',str(file)],text=True).strip()=='arm64'
 load=subprocess.check_output(['/usr/bin/otool','-l',str(file)],text=True)
 assert recipe.minimum(load)<=(13,0,0)
 for rpath in recipe.rpaths(load):assert recipe.system(rpath),rpath
 for dep in recipe.dependencies(subprocess.check_output(['/usr/bin/otool','-L',str(file)],text=True)):
  if recipe.system(dep) or dep=='@rpath/'+file.name:continue
  assert dep.startswith('@loader_path/'),dep
  assert app in (file.parent/dep.removeprefix('@loader_path/')).resolve(strict=True).parents
 macho.append(str(file.relative_to(app)))
env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':os.environ['HOME'],'LC_ALL':'C','DYLD_PRINT_LIBRARIES':'1'}
cache=root/'cache/verified.json';cache.parent.mkdir();shutil.copyfile(a.trusted_cache,cache)
probe=app/'Contents/Helpers/SignumTrustProbe'
def run(name,args):
 r=subprocess.run(list(map(str,args)),env=env,capture_output=True,timeout=120)
 (root/(name+'.stdout.log')).write_bytes(r.stdout);(root/(name+'.dyld.log')).write_bytes(r.stderr)
 assert r.returncode==0,r.stderr.decode(errors='replace')[-1000:]
 recipe.audit_loaded(r.stderr.decode(errors='replace'),app)
 return r.stdout.decode()
tl=run('authenticated-cache',[probe,'offline',cache]);assert 'freshness=current' in tl and 'source=cache' in tl
verification=run('infocamere',[probe,'evidence',cache,a.infocamere_document,'--online'])
assert 'integrity=verified' in verification
assert all('integrity=verified' in line for line in verification.splitlines() if line.startswith('integrity='))
# Read-only native metadata confirms that the fixture is actually issued by InfoCamere,
# without recording subject names, payload, certificates or document bytes.
raw=a.infocamere_document.read_bytes();r=subprocess.run([str(app/'Contents/Helpers/signum-pades-local'),'--verify-stdin-v1'],input=raw,env=env,capture_output=True,timeout=30)
assert r.returncode==0
import struct
n,m=struct.unpack('>II',r.stdout[:8]);assert len(r.stdout)==8+n+m
metadata=json.loads(r.stdout[8:8+n]);assert metadata['signatures']
assert any('infocamere' in s.get('issuer','').lower() for s in metadata['signatures'])
recipe.audit_loaded(r.stderr.decode(errors='replace'),app)
process=subprocess.Popen([str(app/'Contents/MacOS/Signum')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 out,err=process.communicate(timeout=4)
 raise RuntimeError('GUI exited during startup: '+str(process.returncode))
except subprocess.TimeoutExpired:
 process.terminate();out,err=process.communicate(timeout=10)
(root/'main-startup.dyld.log').write_bytes(err);recipe.audit_loaded(err.decode(errors='replace'),app)
assert b'libxmlsec1' in err and b'libcrypto.3' in err
result={'status':'passed','bundleID':identity,'relocatedBundle':str(app),'architecture':'arm64','minimumOS':'13.0','macOS13RuntimeTested':False,
 'macho':macho,'trustedCache':'Production OJ/LOTL/AgID authentication, current cache',
 'infocamere':{'sha256':hashlib.sha256(raw).hexdigest(),'signatures':len(metadata['signatures']),'cryptographicIntegrity':'verified','assessment':verification},
 'mainStartup':'alive after 4 seconds, test terminated','environment':'system PATH; no DYLD search overrides; loaded closure audited'}
(root/'results.json').write_text(json.dumps(result,indent=2)+'\n');print('Build 5 packaging, relocation, startup and InfoCamere verification passed.')
