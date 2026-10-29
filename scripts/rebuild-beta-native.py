#!/usr/bin/env python3
"""MANUAL Phase7 checkpoint: rebuild only FreeType/PoDoFo, verify new isolated prefix.
No app/DMG, source-repository mutation, global installation or hardware access.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[1]
SOURCES = REPO / 'Resources/ThirdPartySources'
ARCHIVES = {
    'freetype': ('freetype.tar.xz', 'freetype-2.13.3', '0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289'),
    'podofo': ('podofo.tar.gz', 'podofo-1.1.2', 'd6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a'),
}
spec = importlib.util.spec_from_file_location('beta', REPO / 'scripts/build-beta-app.py')
beta = importlib.util.module_from_spec(spec); spec.loader.exec_module(beta)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(1024*1024), b''):
            h.update(data)
    return h.hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): (dict(symlink=os.readlink(p)) if p.is_symlink() else dict(sha256=sha(p)))
            for p in sorted(Path(root).rglob('*')) if p.is_symlink() or p.is_file()}


def extract_pinned(archive, destination):
    with tarfile.open(archive) as source:
        for m in source.getmembers():
            p = (destination / m.name).resolve()
            if destination.resolve() not in p.parents or not (m.isfile() or m.isdir()):
                raise ValueError('Unsafe/non-regular archive member: ' + m.name)
        source.extractall(destination)


def interrupt(signum, frame):
    raise InterruptedError('Interrupted: ' + str(signum))


class Runner:
    def __init__(self, root, budget):
        self.root, self.deadline = root, time.monotonic() + budget
        self.steps = []; self.current = None
        self.env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'HOME':os.environ['HOME'],
                    'TMPDIR':str(root/'tmp')+'/', 'LC_ALL':'C', 'MACOSX_DEPLOYMENT_TARGET':'13.0',
                    'PKG_CONFIG_LIBDIR':'/nonexistent', 'PYTHONDONTWRITEBYTECODE':'1'}

    def remaining(self):
        remaining = self.deadline - time.monotonic() - 5
        if remaining <= 0: raise TimeoutError('Overall native build budget exhausted')
        return remaining

    def run(self, label, args, cwd=None, capture=False, expected_exit=0):
        log = self.root/(label+'.log'); started=time.monotonic(); process=None
        row = {'name':label, 'command':[str(x) for x in args], 'cwd':str(cwd or REPO)}
        self.steps.append(row)
        try:
            with log.open('x') as f:
                process = subprocess.Popen(row['command'], cwd=cwd or REPO, env=self.env,
                                           stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
                self.current = process
                row['exit'] = process.wait(timeout=self.remaining())
            row['expectedExit']=expected_exit
            if row['exit'] != expected_exit: raise RuntimeError(label+' failed: '+str(row['exit']))
            text=log.read_text(errors='replace')
            # Command, timing and evidence are retained in the manifest, not bulky successful logs.
            if capture: row['evidence']=text
            log.unlink()
            return text
        except BaseException as error:
            row['error']=str(error); row['log']=str(log)
            raise
        finally:
            if process is not None:
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try: os.killpg(process.pid,sig)
                    except ProcessLookupError: pass
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired: pass
            self.current=None;row['seconds']=round(time.monotonic()-started,3)


def seed_dependencies(base, prefix):
    """Copy only reused permissive dependencies; never copy old FT/PoDoFo."""
    before={};prefix.mkdir();(prefix/'lib').mkdir();(prefix/'include').mkdir()
    for name in ('openssl','libxml2','xmlsec1'):
        shutil.copytree(base/'include'/name,prefix/'include'/name,symlinks=True)
    for p in sorted((base/'lib').glob('*.dylib')):
        if not re.fullmatch(r'lib(?:crypto|ssl|xml2|xmlsec1(?:-openssl)?)(?:\.[0-9]+)*\.dylib',p.name):continue
        resolved=p.resolve(strict=True)
        if base not in resolved.parents:raise ValueError('Reused library escapes base prefix')
        before[p.name]={'originalSHA256':sha(resolved),'symlink':os.readlink(p) if p.is_symlink() else None}
        if p.is_symlink():(prefix/'lib'/p.name).symlink_to(resolved.name)
        else:shutil.copyfile(p,prefix/'lib'/p.name)
    if not {'libcrypto.3.dylib','libssl.3.dylib','libxml2.dylib','libxmlsec1.dylib'} <= before.keys():
        raise ValueError('Incomplete reused dependency set')
    for folder,exclude in [('lib/pkgconfig',{'freetype2.pc'}),('lib/cmake',{'freetype','podofo'})]:
        source=base/folder;target=prefix/folder;target.mkdir(parents=True,exist_ok=True)
        for p in source.iterdir():
            if p.name in exclude:continue
            if p.is_dir():shutil.copytree(p,target/p.name,symlinks=True)
            else:shutil.copyfile(p,target/p.name)
        for p in target.rglob('*'):
            if p.is_file() and p.suffix in ('.pc','.cmake'):
                p.write_text(p.read_text().replace(str(base),str(prefix)).replace('/signum-native',str(prefix)))
    return before


def cmake_options(prefix, root, sdk):
    mapping='-ffile-prefix-map='+str(root)+'=.'
    return ['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX='+str(prefix),
            '-DCMAKE_PREFIX_PATH='+str(prefix),'-DCMAKE_OSX_ARCHITECTURES=arm64',
            '-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0','-DCMAKE_OSX_SYSROOT='+sdk,
            '-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
            '-DCMAKE_C_FLAGS='+mapping,'-DCMAKE_CXX_FLAGS='+mapping,
            '-DCMAKE_BUILD_RPATH='+str(prefix/'lib'),'-DCMAKE_INSTALL_RPATH=@loader_path',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
            '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF','-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
            '-DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=TRUE']


def check_junit(path):
    root=ET.parse(path).getroot();tests=root.findall('.//testcase')
    if len(tests)!=1 or tests[0].get('name')!='signum-pades-reliability' or root.findall('.//failure') or root.findall('.//error') or root.findall('.//skipped'):
        raise ValueError('Missing, skipped or failed native integration test')
    return len(tests)


def perform(args, runner, manifest):
    root=runner.root;prefix=root/'prefix';base=args.base_prefix.resolve(strict=True)
    if platform.system()!='Darwin' or platform.machine()!='arm64':raise ValueError('macOS arm64 required')
    dirty=runner.run('git-status',['/usr/bin/git','status','--short','--ignored'],capture=True)
    if dirty.strip():raise ValueError('Clean frozen checkout required, including ignored files')
    manifest['sourceCommit']=runner.run('git-head',['/usr/bin/git','rev-parse','HEAD'],capture=True).strip()
    native=json.loads((base/'signum-native-build.json').read_text())
    if native.get('recipe')!=1 or native.get('architecture')!='arm64' or native.get('deploymentTarget')!='13.0':raise ValueError('Expected approved macOS13 native base')
    archive_hashes={}
    for key,(name,version,digest) in ARCHIVES.items():
        if sha(SOURCES/name)!=digest or native['sources'][key]!={'version':version,'sha256':digest}:raise ValueError('Pinned archive/metadata mismatch: '+name)
        archive_hashes[name]=digest
    manifest.update(archives=archive_hashes,baseMetadata=native,basePrefix=str(base))
    sdk=runner.run('sdk-path',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],capture=True).strip()
    manifest['toolchain']={name:runner.run('tool-'+name,command,capture=True).strip() for name,command in {
        'clang':['/usr/bin/clang','--version'],'cmake':[args.cmake,'--version'],
        'sdkVersion':['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version'],
        'xcode':['/usr/bin/xcodebuild','-version']}.items()}
    manifest['toolSHA256']={'cmake':sha(args.cmake),'clang':sha(Path('/usr/bin/clang').resolve()),
                           'driver':sha(Path(__file__)), 'componentTest':sha(REPO/'scripts/native-phase7-check.c')}
    compiler=Path(runner.run('selected-clang',['/usr/bin/xcrun','--find','clang'],capture=True).strip())
    manifest['selectedCompiler']={'path':str(compiler),'sha256':sha(compiler)}
    runner.env['SDKROOT']=sdk
    manifest['buildEnvironment']={k:v for k,v in runner.env.items() if k!='HOME'}
    source=root/'sources';source.mkdir()
    for name,_,_ in ARCHIVES.values():extract_pinned(SOURCES/name,source)
    pristine=inventory(source);manifest['pristineSourceSHA256']=pristine
    manifest['reusedLibraries']=seed_dependencies(base,prefix)
    manifest['reusedHeaders']={name:inventory(base/'include'/name) for name in ('openssl','libxml2','xmlsec1')}
    # Rewrite only owned copies; reject any transitive dependency outside this prefix.
    for p in sorted((prefix/'lib').glob('*.dylib')):
        if p.is_symlink():continue
        refs=beta.dependencies(runner.run('seed-deps-'+p.name,['/usr/bin/otool','-L',p],capture=True))
        changes=['/usr/bin/install_name_tool','-id','@rpath/'+p.name]
        for ref in refs:
            if beta.system(ref):continue
            if not (prefix/'lib'/Path(ref).name).is_file():raise ValueError('Unmapped reused dependency: '+ref)
            changes+=['-change',ref,'@rpath/'+Path(ref).name]
        for rpath in beta.rpaths(runner.run('seed-rpaths-'+p.name,['/usr/bin/otool','-l',p],capture=True)):
            if not beta.system(rpath):changes+=['-delete_rpath',rpath]
        runner.run('seed-rewrite-'+p.name,changes+[p])
    common=cmake_options(prefix,root,sdk)
    ft=['-DBUILD_SHARED_LIBS=OFF','-DFT_DISABLE_HARFBUZZ=ON','-DFT_DISABLE_BROTLI=ON','-DFT_DISABLE_BZIP2=ON','-DFT_DISABLE_PNG=ON']
    pdf=['-DPODOFO_BUILD_LIB_ONLY=ON','-DPODOFO_BUILD_STATIC=OFF','-DPODOFO_WITH_FONTMANAGER=OFF','-DPODOFO_WITH_AFDKO=OFF',
         '-DOPENSSL_ROOT_DIR='+str(prefix),'-DOPENSSL_USE_STATIC_LIBS=FALSE',
         '-DFREETYPE_LIBRARY_RELEASE='+str(prefix/'lib/libfreetype.a'),'-DFREETYPE_INCLUDE_DIRS='+str(prefix/'include/freetype2'),
         '-DLIBXML2_INCLUDE_DIR='+str(prefix/'include/libxml2'),'-DLIBXML2_LIBRARY='+str(prefix/'lib/libxml2.dylib'),
         '-DCMAKE_DISABLE_FIND_PACKAGE_JPEG=TRUE','-DCMAKE_DISABLE_FIND_PACKAGE_PNG=TRUE','-DCMAKE_DISABLE_FIND_PACKAGE_TIFF=TRUE',
         '-DCMAKE_DISABLE_FIND_PACKAGE_LCMS2=TRUE','-DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=TRUE']
    for name,options in [('freetype',ft),('podofo',pdf)]:
        build=root/('build-'+name)
        runner.run(name+'-configure',[args.cmake,'-S',source/ARCHIVES[name][1],'-B',build]+common+options)
        runner.run(name+'-build',[args.cmake,'--build',build,'--parallel',str(args.jobs)])
        runner.run(name+'-install',[args.cmake,'--install',build])
    if inventory(source)!=pristine:raise ValueError('Source changed during build; inspect and record before attesting patches')
    manifest['patchInventory']={'applied':[],'sourceUnchangedAfterBuild':True,'basis':'Every extracted regular source file SHA256 matched before/after out-of-source build'}
    for p in sorted((prefix/'lib').glob('*.dylib')):
        if not p.is_symlink():runner.run('adhoc-'+p.name,['/usr/bin/codesign','--force','--sign','-','--timestamp=none',p])
    helper=root/'build-helper'
    runner.run('helper-configure',[args.cmake,'-S',REPO/'Tools/PAdESPrototype','-B',helper]+common+[
        '-DOPENSSL_ROOT_DIR='+str(prefix),'-DOPENSSL_USE_STATIC_LIBS=FALSE','-DSIGNUM_BUILD_OFFLINE_TESTS=ON'])
    runner.run('helper-build',[args.cmake,'--build',helper,'--parallel',str(args.jobs)])
    junit=root/'native-tests.xml'
    runner.run('native-integration',[args.cmake.with_name('ctest'),'--test-dir',helper,'--output-on-failure',
                                    '-R','^signum-pades-reliability$','--output-junit',junit])
    manifest['nativeIntegrationTests']=check_junit(junit)
    vendor=source/'podofo-1.1.2/3rdparty/utf8proc';probe=root/'native-component-check'
    runner.run('component-compile',['/usr/bin/clang','-arch','arm64','-isysroot',sdk,'-mmacosx-version-min=13.0',
                                   '-ffile-prefix-map='+str(root)+'=.','-DUTF8PROC_STATIC','-I'+str(vendor),
                                   '-I'+str(prefix/'include/freetype2'),REPO/'scripts/native-phase7-check.c',
                                   vendor/'utf8proc.c',prefix/'lib/libfreetype.a','-lz','-o',probe])
    evidence=runner.run('component-check',[probe],capture=True)
    if 'native components: 3 passed' not in evidence:raise ValueError('Missing component test evidence')
    manifest['componentTests']=3
    if runner.run('freetype-arch',['/usr/bin/lipo','-archs',prefix/'lib/libfreetype.a'],capture=True).strip()!='arm64':
        raise ValueError('FreeType archive architecture mismatch')
    binaries=[p for p in (prefix/'lib').glob('*.dylib') if not p.is_symlink()]+[helper/'signum-pades-local']
    manifest['machO']={}
    for index,p in enumerate(binaries):
        arch=runner.run('arch-'+str(index),['/usr/bin/lipo','-archs',p],capture=True).strip()
        load=runner.run('load-'+str(index),['/usr/bin/otool','-l',p],capture=True)
        if arch!='arm64' or beta.enforce_minimum([beta.minimum(load)],'13.0')!='13.0':raise ValueError('Mach-O platform mismatch')
        for rpath in beta.rpaths(load):
            if not (rpath.startswith(('@loader_path','@executable_path')) or str(prefix) in rpath or beta.system(rpath)):
                raise ValueError('External runtime search path: '+rpath)
        manifest['machO'][str(p.relative_to(root))]={'sha256':sha(p),'architecture':arch,'minimumOS':list(beta.minimum(load))}
    loaded=runner.run('loader-smoke',['/usr/bin/env','DYLD_PRINT_LIBRARIES=1',helper/'signum-pades-local'],capture=True,expected_exit=2)
    # Actual loader evidence must contain the fresh PoDoFo and no previous prefix/Homebrew library.
    paths=re.findall(r'dyld\[\d+\]: <[^>]+> (/.+)',loaded)
    if not any('libpodofo' in p and prefix in Path(p).resolve().parents for p in paths):raise ValueError('No fresh PoDoFo loader evidence')
    if any(not beta.system(p) and prefix not in Path(p).resolve().parents and Path(p).resolve()!=(helper/'signum-pades-local').resolve() for p in paths):raise ValueError('External library loaded')
    spec=importlib.util.spec_from_file_location('notices',REPO/'scripts/notices_contract.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    proof=n.audit([helper/'signum-pades-local'],prefix,REPO/'Resources/Notices',native)
    manifest['closure']=proof
    if runner.run('final-git-status',['/usr/bin/git','status','--short','--ignored'],capture=True).strip() or runner.run('final-git-head',['/usr/bin/git','rev-parse','HEAD'],capture=True).strip()!=manifest['sourceCommit']:
        raise ValueError('Source checkout changed during build')
    if inventory(source)!=pristine:raise ValueError('Source inputs changed during verification')
    for name, before in manifest['reusedHeaders'].items():
        if inventory(base/'include'/name)!=before:raise ValueError('Read-only dependency headers changed')
    for name, before in manifest['reusedLibraries'].items():
        if sha(base/'lib'/name)!=before['originalSHA256']:raise ValueError('Read-only dependency library changed')
    evidence=root/'evidence';evidence.mkdir()
    for name in ('freetype','podofo','helper'):
        for file in ('CMakeCache.txt','compile_commands.json'):
            p=root/('build-'+name)/file
            if p.is_file():shutil.copyfile(p,evidence/(name+'-'+file))
    native['phase7Controlled']={'rebuilt':['freetype','podofo'],'reused':['openssl','libxml2','xmlsec'],'manifest':'../native-build-manifest.json'}
    (prefix/'signum-native-build.json').write_text(json.dumps(native,indent=2)+'\n')
    kit=prefix/'share/signum-sources';shutil.copytree(SOURCES,kit)
    shutil.copyfile(REPO/'scripts/rebuild-beta-native.py',kit/'rebuild-beta-native.py')
    shutil.copyfile(REPO/'scripts/native-phase7-check.c',kit/'native-phase7-check.c')
    manifest['status']='verified-native-checkpoint';manifest['packagingQualified']=False
    # Only the isolated kit changes state; the global/old prefix dossier stays unattested.


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-prefix',type=Path,required=True);p.add_argument('--cmake',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--budget-seconds',type=int,default=900)
    p.add_argument('--jobs',type=int,default=6)
    args=p.parse_args(argv)
    if args.budget_seconds<10 or args.jobs<1 or args.jobs>16:p.error('Budget >=10 and jobs 1..16 required')
    root=beta.external_workspace(args.output);base=args.base_prefix.resolve(strict=True)
    args.cmake=args.cmake.resolve(strict=True)
    if not os.access(args.cmake,os.X_OK) or not os.access(args.cmake.with_name('ctest'),os.X_OK):
        raise ValueError('Existing CMake and adjacent CTest required; nothing is installed')
    if base==root or base in root.parents or root in base.parents:raise ValueError('Output overlaps read-only base prefix')
    root.mkdir(parents=True,exist_ok=False);(root/'tmp').mkdir()
    runner=Runner(root,args.budget_seconds);started=time.monotonic()
    manifest={'status':'failed','publicationQualified':False,'packagingQualified':False,'budgetSeconds':args.budget_seconds,
              'minimumOS':'13.0','architecture':'arm64','sourceDecisions':{'podofo':'MPL-2.0','freetype':'FTL'}}
    old={sig:signal.signal(sig,interrupt) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM,signal.SIGHUP)}
    signal.alarm(args.budget_seconds-2)
    try:perform(args,runner,manifest)
    except (Exception,KeyboardInterrupt) as error:manifest['error']=str(error)
    finally:
        signal.alarm(0)
        manifest['steps']=runner.steps
        if manifest['status']!='verified-native-checkpoint':
            # Preserve bounded diagnostic files before deleting failed build intermediates.
            for folder in ('build-freetype','build-podofo','build-helper'):
                for relative in ('CMakeCache.txt','CMakeFiles/CMakeConfigureLog.yaml',
                                 'CMakeFiles/CMakeError.log','Testing/Temporary/LastTest.log'):
                    source=root/folder/relative
                    if source.is_file() and source.stat().st_size<8*1024*1024 and time.monotonic()<runner.deadline-1:
                        target=root/'failure-details'/folder/relative;target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(source,target)
        # Keep source inputs, final prefix, manifest and compact evidence; remove intermediates.
        incomplete=[]
        for name in ('tmp','build-freetype','build-podofo','build-helper','native-component-check'):
            path=root/name
            if not path.exists():continue
            remaining=runner.deadline-time.monotonic()-0.2
            try:
                if remaining<=0:raise TimeoutError()
                subprocess.run(['/bin/rm','-rf','--',str(path)],check=True,timeout=remaining)
            except (OSError,subprocess.SubprocessError,TimeoutError):incomplete.append(str(path))
        if incomplete:manifest['cleanupIncomplete']=incomplete;manifest['status']='failed'
        for sig,handler in old.items():signal.signal(sig,handler)
        manifest['seconds']=round(time.monotonic()-started,3)
        if manifest['status']=='verified-native-checkpoint':
            kit=root/'prefix/share/signum-sources'
            dossier=json.loads((kit/'podofo.json').read_text())
            dossier.update(patchStatus='verified',sourceCorrespondence='attested',
                           status='Verified ONLY for this new controlled native prefix; not for the original prefix',
                           nativeBuildEvidence='NATIVE_BUILD_PROVENANCE.json')
            (kit/'podofo.json').write_text(json.dumps(dossier,indent=2)+'\n')
            (kit/'SOURCE_ACCESS.md').write_text(
                '# Sources for this controlled native prefix\n\n'
                'This kit is scoped ONLY to the fresh FreeType/PoDoFo libraries verified in '
                'NATIVE_BUILD_PROVENANCE.json, not the earlier installed prefix. Source archive '
                'hashes, zero-patch source comparison, toolchain, commands, reused dependency '
                'hashes, tests and resulting hashes are recorded there.\n\n'
                'The original archives and licenses are beside this file. Use '
                'BUILD_NATIVE_SOURCES.md for library-only rebuild instructions without the '
                'private Signum repository. The copied Python driver is recipe evidence; its '
                'Signum helper integration check requires the authorized Signum worktree. '
                'Global adoption, app/DMG testing and public distribution remain unqualified.\n')
            manifest['outputPrefixInventory']=inventory(root/'prefix')
            manifest['outputHashScope']='All prefix inputs/output files except NATIVE_BUILD_PROVENANCE.json itself (avoids a self-hash cycle)'
            portable=json.dumps(manifest,indent=2).replace(str(base),'/Signum/reused-native-base').replace(str(REPO),'/Signum').replace(str(root),'/Signum/native-build').replace('/opt/homebrew','/Signum/build-tools/homebrew').replace('/usr/local','/Signum/build-tools/local')
            (kit/'NATIVE_BUILD_PROVENANCE.json').write_text(portable+'\n')
        (root/'native-build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        summary={k:manifest[k] for k in ('status','seconds','budgetSeconds','packagingQualified','publicationQualified')}
        summary.update(prefix=str(root/'prefix'),manifest=str(root/'native-build-manifest.json'),
                       steps=len(runner.steps),failedSteps=[s['name'] for s in runner.steps if 'error' in s],
                       nativeIntegrationTests=manifest.get('nativeIntegrationTests',0),componentTests=manifest.get('componentTests',0))
        if 'error' in manifest:summary['error']=manifest['error']
        (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
    return 0 if manifest['status']=='verified-native-checkpoint' else 1


if __name__=='__main__':raise SystemExit(main())
