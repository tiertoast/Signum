#!/usr/bin/env python3
"""Offline Mach-O closure -> versioned local notice contract. No legal verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

CATALOG = Path(__file__).with_name('third-party-notices.json')


def dependencies(binary):
    text = subprocess.check_output(['/usr/bin/otool','-L',str(binary)],text=True,timeout=15)
    return re.findall(r'^\s+(.+?) \(compatibility version ',text,re.M)


def closure(binaries, prefix, inspect=dependencies):
    prefix=Path(prefix).resolve();todo=[Path(p).resolve() for p in binaries];seen={};system=set()
    if not todo:raise ValueError('No product Mach-O binaries supplied')
    while todo:
        binary=todo.pop(0)
        if str(binary) in seen:continue
        if not binary.is_file():raise ValueError('Missing binary: '+str(binary))
        refs=inspect(binary);edges=[]
        for ref in refs:
            if ref.startswith(('/usr/lib/','/System/Library/')):system.add(ref);continue
            if ref.startswith('@rpath/'):path=prefix/ref[len('@rpath/'):]
            elif ref.startswith('@loader_path/'):path=binary.parent/ref[len('@loader_path/'):]
            elif ref.startswith('/'):path=Path(ref)
            else:raise ValueError('Unsupported dependency locator: '+ref)
            path=path.resolve()
            if prefix not in path.parents or not path.is_file():raise ValueError('Unresolved or external private dependency: '+ref)
            if path==binary:continue # dylib install ID, not a transitive edge.
            edges.append(dict(reference=ref,path=str(path)));todo.append(path)
        seen[str(binary)]=dict(sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),dependencies=edges)
    return seen,sorted(system)


def required_components(graph, prefix, catalog):
    prefix=Path(prefix).resolve();selected=set()
    for name in graph:
        path=Path(name)
        if prefix not in path.parents:continue
        matches=[key for key,item in catalog['components'].items() if any(re.fullmatch(p,path.name) for p in item.get('libraryPatterns',[]))]
        if len(matches)!=1:raise ValueError('Unknown or ambiguous private library without notice entry: '+path.name)
        selected.add(matches[0])
    todo=list(selected)
    while todo:
        for embedded in catalog['components'][todo.pop() ].get('embedded',[]):
            if embedded not in catalog['components']:raise ValueError('Missing embedded component entry: '+embedded)
            if embedded not in selected:selected.add(embedded);todo.append(embedded)
    return selected


def check_notices(root, catalog, selected, native):
    root=Path(root).resolve();proof={}
    for name in sorted(selected):
        item=catalog['components'][name]
        if item.get('nativeKey'):
            declared=native.get('sources',{}).get(item['nativeKey'],{}).get('version')
            if declared!=item['nativeVersion']:raise ValueError('Native source version mismatch for '+name+': '+str(declared))
        for relative,digest in item['notices'].items():
            path=(root/relative).resolve()
            if root not in path.parents or not path.is_file():raise ValueError('Missing notice for '+name+': '+relative)
            data=path.read_bytes()
            if len(data)<item.get('minimumNoticeBytes',1):raise ValueError('Notice is only a placeholder/referral: '+relative)
            if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Notice content differs from approved local text for '+name+': '+relative)
            proof[relative]=dict(sha256=digest,bytes=len(data))
    return proof


def audit(binaries, prefix, root, native, catalog=None, inspect=dependencies):
    catalog=catalog or json.loads(CATALOG.read_text())
    graph,system=closure(binaries,prefix,inspect)
    selected=required_components(graph,prefix,catalog)
    notices=check_notices(root,catalog,selected,native)
    return dict(binaryGraph=graph,systemReferences=system,components=sorted(selected),notices=notices,
                scope='Technical local notice/version coverage; not source correspondence or legal approval')


def bundle_inputs(app):
    app=Path(app).resolve();prefix=app/'Contents/Frameworks';resources=app/'Contents/Resources'
    binaries=[]
    for folder in [app/'Contents/MacOS',app/'Contents/Helpers',prefix]:
        for p in folder.glob('*'):
            if p.is_file():
                with p.open('rb') as handle:magic=handle.read(4)
                if magic in [b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf']:binaries.append(p)
    native=json.loads((resources/'BuildManifest.json').read_text())['native']
    return binaries,prefix,resources/'Notices',native


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--prefix',type=Path)
    parser.add_argument('--binary',type=Path,action='append',default=[])
    parser.add_argument('--notice-root',type=Path)
    parser.add_argument('--catalog',type=Path,default=CATALOG)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        if args.bundle:binaries,prefix,root,native=bundle_inputs(args.bundle)
        else:
            if not args.prefix or not args.notice_root:parser.error('--prefix and --notice-root are required outside bundle mode')
            binaries,prefix,root,native=args.binary,args.prefix,args.notice_root,json.loads((args.prefix/'signum-native-build.json').read_text())
        result=audit(binaries,prefix,root,native,json.loads(args.catalog.read_text()))
        if args.output:args.output.write_text(json.dumps(result,indent=2))
        print(json.dumps(dict(components=result['components'],noticeFiles=len(result['notices']),binaries=len(result['binaryGraph'])),indent=2))
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        print('NOTICE CONTRACT ERROR: '+str(error));raise SystemExit(1)
