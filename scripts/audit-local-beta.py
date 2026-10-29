#!/usr/bin/env python3
"""Manual candidate audit only. Does not rebuild native dependencies or publish."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import time

REPO=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,REPO/'scripts'/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
beta=load('beta','build-beta-app.py');notices=load('notices','notices_contract.py');profile=load('profile','native_profile_contract.py')


def run(command,timeout=20):
    try:return subprocess.check_output([str(c) for c in command],stderr=subprocess.STDOUT,text=True,timeout=timeout)
    except subprocess.CalledProcessError as error:
        print(error.output,file=sys.stderr);raise


def read_json(path):return json.loads(path.read_text())

def contained(root,relative):
    root=root.resolve();p=(root/relative).resolve(strict=True)
    if Path(relative).is_absolute() or root not in p.parents:raise ValueError('Artifact path escapes its root: '+relative)
    return p


def tree(root):
    return {str(p.relative_to(root)): {'symlink':os.readlink(p)} if p.is_symlink() else {'sha256':profile.sha(p)}
            for p in sorted(root.rglob('*')) if p.is_file() or p.is_symlink()}


def schema_audit(resources):
    catalog=read_json(resources/'SchemaLicenseCatalog.json')
    bundles=list(resources.glob('Signum_SignumTrustAuthentication.bundle'))
    if len(bundles)!=1:raise ValueError('Missing/ambiguous schema bundle')
    dirs=[p for p in bundles[0].rglob('Schemas') if p.is_dir()]
    if len(dirs)!=1:raise ValueError('Missing/ambiguous bundled Schemas directory')
    schemas=dirs[0]
    listed={Path(row['file']).name for row in catalog['resources']}
    if listed!={p.name for p in schemas.glob('*.xsd')} or len(listed)!=7:raise ValueError('Schema inventory mismatch')
    def material(name):
        if name=='LICENSE':return resources/'Signum-LICENSE.txt'
        if name.startswith('Resources/'):return contained(resources,name[len('Resources/'):])
        if name.startswith('Sources/SignumTrustAuthentication/Schemas/'):return contained(schemas,Path(name).name)
        raise ValueError('Unknown schema license locator')
    for row in catalog['resources']:
        if row['status']!='local-license-text-present' or not row['licenseFile']:raise ValueError('Unqualified schema resource')
        if profile.sha(schemas/Path(row['file']).name)!=row['sha256']:raise ValueError('Bundled XSD changed')
        for name,digest in [(row['licenseFile'],row['licenseSHA256'])]+list(row.get('additionalNotices',{}).items()):
            if profile.sha(material(name))!=digest:raise ValueError('Bundled schema license/notice mismatch: '+name)
    return len(listed)


def launch(app,tmp):
    gate=tmp/'startup-check';process=None;success=False
    run(['/usr/bin/xcrun','--sdk','macosx','clang','-arch','arm64','-mmacosx-version-min=13.0',
         '-framework','AppKit',REPO/'scripts/beta-startup-check.m','-o',gate],timeout=30)
    log=tmp.parent/'app-startup.log'
    try:
        env={'PATH':'/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(tmp)+'/',
             'LC_ALL':'C','DYLD_PRINT_LIBRARIES':'1'}
        with log.open('x') as stream:
            # Inherit the auditor's owned group so outer timeout cleanup also covers
            # a parent interruption during Popen, before its PID is assigned here.
            process=subprocess.Popen([str(app/'Contents/MacOS/Signum')],env=env,stdout=stream,stderr=subprocess.STDOUT)
            evidence=run([gate,str(process.pid),'io.github.tiertoast.Signum'],timeout=12)
            time.sleep(2)
            if process.poll() is not None:raise ValueError('App exited immediately after finishedLaunching')
        text=log.read_text(errors='replace');beta.audit_loaded(text,app);success=True
        return {'finishedLaunching':True,'runningAfterTwoSeconds':True,'bundleIdentifier':'io.github.tiertoast.Signum',
                'evidence':evidence.strip(),'scope':'Launch/runtime loader only; no functional GUI or hardware qualification'}
    finally:
        if process is not None:
            try:process.terminate()
            except ProcessLookupError:pass
            try:process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:process.kill()
                except ProcessLookupError:pass
                process.wait(timeout=1)
        # Successful launch evidence is compact; keep detailed output only on failure.
        if success:log.unlink(missing_ok=True)


def app_audit(app,prefix,tmp):
    kit,source=profile.validate(prefix,REPO)
    resources=app/'Contents/Resources';info=plistlib.loads((app/'Contents/Info.plist').read_bytes());manifest=read_json(resources/'BuildManifest.json')
    expected={'CFBundleIdentifier':'io.github.tiertoast.Signum','CFBundleShortVersionString':'0.7.0','CFBundleVersion':'14','LSMinimumSystemVersion':'13.0'}
    if any(info.get(k)!=v for k,v in expected.items()) or 'Beta' not in info.get('CFBundleDisplayName',''):raise ValueError('Wrong local Beta metadata')
    if manifest.get('signingMode')!='adhoc' or manifest.get('sourceTrackedDirty') is not False:raise ValueError('Clean ad-hoc candidate required')
    if manifest.get('distributionPrerequisites',{}).get('nativeProvenance')!=source:raise ValueError('Candidate did not select verified source kit')
    run(['/usr/bin/codesign','--verify','--deep','--strict',app])
    signing=run(['/usr/bin/codesign','-d','--verbose=4',app])
    if 'Signature=adhoc' not in signing or 'Authority=' in signing:raise ValueError('Ad-hoc signature expected')
    for name,digest in manifest['nestedCodeSHA256'].items():
        if profile.sha(contained(app,name))!=digest:raise ValueError('Nested code integrity mismatch')
    for name,digest in [('AppIcon.icns',manifest['appIconSHA256']),('Assets.car',manifest['appIconAssetsSHA256'])]:
        if profile.sha(resources/name)!=digest:raise ValueError('Icon resource changed')
    if profile.sha(resources/'SignedDocument.icns')!=profile.sha(REPO/'Resources/DocumentIcons/SignedDocument.icns'):
        raise ValueError('Document icon missing/changed')
    if profile.sha(resources/'Signum-LICENSE.txt')!=profile.sha(REPO/'LICENSE'):raise ValueError('Signum license missing/changed')
    bundled=resources/'ThirdPartySources'
    # Original verified source material must arrive byte-for-byte, not the old global dossier.
    for relative,entry in read_json(prefix.parent/'native-build-manifest.json')['outputPrefixInventory'].items():
        if not relative.startswith('share/signum-sources/'):continue
        local=relative[len('share/signum-sources/'):]
        if entry.get('sha256') and profile.sha(contained(bundled,local))!=entry['sha256']:raise ValueError('Corresponding source material changed: '+local)
    if profile.sha(bundled/'NATIVE_BUILD_PROVENANCE.json')!=source['sourceProofSHA256']:raise ValueError('Native provenance changed')
    if read_json(bundled/'STATUS.json').get('distributionPrerequisitesRecorded') is not True:raise ValueError('Source obligations not recorded')
    binary_paths,frameworks,notice_root,native=notices.bundle_inputs(app)
    proof=notices.audit(binary_paths,frameworks,notice_root,native,read_json(resources/'ThirdPartyNotices.json'))
    old=read_json(prefix.parent/'native-build-manifest.json')['basePrefix'].encode()
    binary_result={}
    for binary in binary_paths:
        data=binary.read_bytes()
        if old in data:raise ValueError('Old native prefix found in distributed code')
        beta.portable(data)
        if run(['/usr/bin/lipo','-archs',binary]).strip()!='arm64':raise ValueError('Wrong Mach-O architecture')
        load=run(['/usr/bin/otool','-l',binary]);beta.enforce_minimum([beta.minimum(load)],'13.0')
        if any(not beta.system(p) for p in beta.rpaths(load)):raise ValueError('Unexpected non-system rpath')
        binary_result[str(binary.relative_to(app))]={'sha256':profile.sha(binary),'architecture':'arm64','minimumOS':list(beta.minimum(load))}
    report={'status':'verified-app','metadata':expected,'nativeProvenance':source,'schemas':schema_audit(resources),
            'binaries':binary_result,'components':proof['components'],'noticeFiles':len(proof['notices']),
            'oldPrefixReferences':0,'signing':'adhoc','publicationQualified':False}
    before=tree(app);report['startup']=launch(app,tmp)
    if tree(app)!=before:raise ValueError('App resources changed during startup')
    report['appFiles']=before
    return report


def verify_volume(root,app,expected):
    if not (root/'Applications').is_symlink() or os.readlink(root/'Applications')!='/Applications':raise ValueError('Invalid Applications link')
    seen=set()
    for line in (root/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1);p=contained(root,name)
        if name in seen or p.is_symlink() or profile.sha(p)!=digest:raise ValueError('DMG inventory checksum mismatch')
        seen.add(name)
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and not p.is_symlink()}-{'SHA256SUMS'}
    if seen!=actual:raise ValueError('Incomplete DMG checksum inventory')
    if tree(root/app.name)!=expected['appFiles']:raise ValueError('Mounted app differs from audited app')
    if profile.sha(root/'BuildManifest.json')!=profile.sha(root/app.name/'Contents/Resources/BuildManifest.json'):raise ValueError('DMG manifest mismatch')
    run(['/usr/bin/codesign','--verify','--deep','--strict',root/app.name])


def dmg_audit(app,dmg,app_report,tmp):
    expected=read_json(app_report)
    if expected.get('status')!='verified-app' or not expected.get('startup',{}).get('finishedLaunching'):raise ValueError('Verified app launch required before DMG')
    digest=profile.sha(dmg)
    if (dmg.with_name(dmg.name+'.sha256')).read_text().strip()!=digest+'  '+dmg.name:raise ValueError('DMG sidecar mismatch')
    run(['/usr/bin/hdiutil','verify',dmg],timeout=60)
    mount=tmp/'dmg-mount';mount.mkdir(exist_ok=False);attached=False
    try:
        attached=True  # also attempt cleanup if attach is interrupted after mounting
        result=subprocess.check_output(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-plist','-mountpoint',str(mount),str(dmg)],timeout=30)
        volumes=plistlib.loads(result).get('system-entities',[])
        if not any(x.get('mount-point')==str(mount) for x in volumes):raise ValueError('Unexpected DMG mount')
        verify_volume(mount,app,expected)
    finally:
        if attached and os.path.ismount(mount):run(['/usr/bin/hdiutil','detach',mount],timeout=5)
        if mount.is_dir() and not os.path.ismount(mount):mount.rmdir()
    return {'status':'verified-local-beta','publicationQualified':False,'dmg':{'file':dmg.name,'sha256':digest,'bytes':dmg.stat().st_size,'readOnlyMountedAudit':True},
            'appAudit':app_report.name,'appAuditSHA256':profile.sha(app_report),'nativeProvenance':expected['nativeProvenance'],
            'metadata':expected['metadata'],'startup':expected['startup'],'binaries':expected['binaries']}


def interrupted(signum,frame):raise InterruptedError('Candidate audit interrupted: '+str(signum))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--app',type=Path,required=True);p.add_argument('--native-prefix',type=Path)
    p.add_argument('--dmg',type=Path);p.add_argument('--app-audit',type=Path);p.add_argument('--tmp',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Audit output must be NEW')
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    result=dmg_audit(a.app,a.dmg,a.app_audit,a.tmp) if a.dmg else app_audit(a.app,a.native_prefix,a.tmp)
    with a.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k in ('status','publicationQualified','dmg','nativeProvenance')}))

if __name__=='__main__':main()
