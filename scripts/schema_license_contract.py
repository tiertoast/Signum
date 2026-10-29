"""Offline resource inventory and explicit missing-license gate; no legal verdict."""
import argparse,hashlib,json
from pathlib import Path
W=Path(__file__).resolve().parents[1]
def check(root,catalog,require_ready=False):
 root=Path(root).resolve();pending=[]
 actual={str(p.relative_to(root)) for p in (root/'Sources/SignumTrustAuthentication/Schemas').glob('*.xsd')}
 listed=[r['file'] for r in catalog['resources']]
 if len(listed)!=len(set(listed)) or set(listed)!=actual:raise ValueError('Schema inventory differs from actual resources')
 for row in catalog['resources']:
  for name,digest in [(row['file'],row['sha256']),(row.get('licenseFile'),row.get('licenseSHA256'))]+list(row.get('additionalNotices',{}).items()):
   if name is None:continue
   path=(root/name).resolve()
   if root not in path.parents or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Resource/license missing or hash changed: '+name)
  if not row.get('licenseFile') or not row.get('licenseSHA256') or row.get('status')!='local-license-text-present':pending.append(row['file'])
 result=dict(inventoryValid=True,resources=len(listed),redistributionReady=not pending,unresolvedLicenses=pending,scope='Technical inventory; no legal approval or upstream correspondence attestation')
 if require_ready and pending:raise ValueError('Original schema licenses unresolved: '+', '.join(pending))
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=W);p.add_argument('--require-ready',action='store_true');a=p.parse_args()
 try:print(json.dumps(check(a.root,json.loads((a.root/'scripts/schema-license-catalog.json').read_text()),a.require_ready),indent=2))
 except (ValueError,OSError,KeyError) as e:print('SCHEMA LICENSE GATE: '+str(e));raise SystemExit(1)
