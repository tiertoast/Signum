"""Read-only adoption gate for the author-executed Phase7 prefix. Never rebuilds."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

PROOF = 'share/signum-sources/NATIVE_BUILD_PROVENANCE.json'
REQUIRED_STEPS = {'freetype-build','freetype-install','podofo-build','podofo-install',
                  'native-integration','component-check','loader-smoke','final-git-status','final-git-head'}


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def inventory(root):
    root=Path(root).resolve();result={}
    for p in sorted(root.rglob('*')):
        relative=str(p.relative_to(root))
        if relative==PROOF:continue  # Explicit self-hash exclusion of the native run.
        if p.is_symlink():
            if root not in p.resolve(strict=True).parents:raise ValueError('Native symlink escapes prefix: '+relative)
            result[relative]={'symlink':os.readlink(p)}
        elif p.is_file():result[relative]={'sha256':sha(p)}
    return result


def validate(prefix, repo):
    prefix,repo=Path(prefix).resolve(strict=True),Path(repo).resolve(strict=True)
    native=json.loads((prefix/'signum-native-build.json').read_text())
    control=native.get('phase7Controlled')
    if not control or control.get('manifest')!='../native-build-manifest.json':raise ValueError('Controlled Phase7 native prefix required')
    record=prefix.parent/'native-build-manifest.json';summary_path=prefix.parent/'summary.json'
    m=json.loads(record.read_text());s=json.loads(summary_path.read_text())
    if (m.get('status')!='verified-native-checkpoint' or s.get('status')!=m['status'] or
        m.get('minimumOS')!='13.0' or m.get('architecture')!='arm64' or m.get('cleanupIncomplete') or
        m.get('error') or s.get('failedSteps') or m.get('nativeIntegrationTests')!=1 or m.get('componentTests')!=3 or
        s.get('nativeIntegrationTests')!=1 or s.get('componentTests')!=3 or
        Path(s.get('prefix','')).resolve()!=prefix or Path(s.get('manifest','')).resolve()!=record):
        raise ValueError('Native checkpoint incomplete or not scoped to this prefix')
    steps=m.get('steps',[]);names=[x.get('name') for x in steps]
    if len(steps)!=s.get('steps') or len(names)!=len(set(names)) or not REQUIRED_STEPS<=set(names):raise ValueError('Native checkpoint steps missing or duplicated')
    for step in steps:
        if step.get('error') or 'exit' not in step or step['exit']!=step.get('expectedExit',0):raise ValueError('Native step failed: '+str(step.get('name')))
    if m.get('patchInventory',{}).get('applied')!=[] or m['patchInventory'].get('sourceUnchangedAfterBuild') is not True:
        raise ValueError('Native zero-patch source comparison missing')
    if m.get('sourceDecisions')!={'podofo':'MPL-2.0','freetype':'FTL'}:raise ValueError('Native license selection mismatch')
    if native!=m.get('baseMetadata'):raise ValueError('Native metadata differs from frozen build record')
    # Check the trusted driver used at the recorded Git revision; allow later packaging-only commits.
    commit=m['sourceCommit']
    subprocess.run(['/usr/bin/git','merge-base','--is-ancestor',commit,'HEAD'],cwd=repo,check=True,timeout=5,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    for field,file in [('driver','scripts/rebuild-beta-native.py'),('componentTest','scripts/native-phase7-check.c')]:
        data=subprocess.check_output(['/usr/bin/git','show',commit+':'+file],cwd=repo,timeout=5)
        if hashlib.sha256(data).hexdigest()!=m['toolSHA256'][field]:raise ValueError('Native driver/source evidence mismatch')
    if inventory(prefix)!=m.get('outputPrefixInventory'):raise ValueError('Native prefix content differs from verified inventory')
    expected=json.dumps(m,indent=2).replace(m['basePrefix'],'/Signum/reused-native-base').replace(str(repo),'/Signum').replace(str(prefix.parent),'/Signum/native-build').replace('/opt/homebrew','/Signum/build-tools/homebrew').replace('/usr/local','/Signum/build-tools/local')+'\n'
    if (prefix/PROOF).read_text()!=expected:raise ValueError('Portable source proof differs from original checkpoint')
    kit=prefix/'share/signum-sources';dossier=json.loads((kit/'podofo.json').read_text())
    if dossier.get('nativeBuildEvidence')!='NATIVE_BUILD_PROVENANCE.json' or dossier.get('sourceCorrespondence')!='attested' or dossier.get('patchStatus')!='verified':
        raise ValueError('Source kit is not attested for the new prefix')
    for name,digest in m['archives'].items():
        if sha(kit/name)!=digest or sha(repo/'Resources/ThirdPartySources'/name)!=digest:raise ValueError('Source archive changed')
    return kit,dict(kind='verified-native-checkpoint',sourceCommit=commit,manifestSHA256=sha(record),
                    sourceProofSHA256=sha(prefix/PROOF),verifiedPrefixFiles=len(m['outputPrefixInventory']),
                    sourceEvidence='Contents/Resources/ThirdPartySources/NATIVE_BUILD_PROVENANCE.json')
