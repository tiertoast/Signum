"""Offline Phase8 gates. No app build, app launch, mounting or signing."""
import copy,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
W=Path(__file__).resolve().parents[2]
def module(name,file):
 s=importlib.util.spec_from_file_location(name,W/'scripts'/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
n=module('profile8','native_profile_contract.py');a=module('audit8','audit-local-beta.py')
class ProfileTests(unittest.TestCase):
 def test_inventory_detects_changed_file_and_unrecorded_input(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);(root/'file').write_text('original');before=n.inventory(root)
   (root/'file').write_text('tampered');self.assertNotEqual(before,n.inventory(root))
   (root/'file').write_text('original');(root/'extra').write_text('unrecorded');self.assertNotEqual(before,n.inventory(root))
 def test_escaping_native_symlink_is_rejected(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);(root/'link').symlink_to(W/'LICENSE')
   with self.assertRaisesRegex(ValueError,'escapes'):n.inventory(root)
 def test_incomplete_checkpoint_cannot_be_adopted(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);prefix=root/'prefix';prefix.mkdir()
   (prefix/'signum-native-build.json').write_text(json.dumps({'phase7Controlled':{'manifest':'../native-build-manifest.json'}}))
   (root/'native-build-manifest.json').write_text(json.dumps({'status':'failed'}));(root/'summary.json').write_text(json.dumps({'status':'failed'}))
   with self.assertRaisesRegex(ValueError,'incomplete'):n.validate(prefix,W)
class PipelineTests(unittest.TestCase):
 def test_audits_are_required_before_and_after_dmg_creation(self):
  p=module('prepare8','prepare-public-beta.py')
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d)/'new';order=[]
   def step(name,command,folder,deadline):
    order.append(name)
    if name=='dmg-audit':(folder/'ArtifactManifest.json').write_text('{}')
    return {'name':name,'exit':0,'seconds':0}
   with patch.object(p,'preflight',return_value={'ready':True,'blockers':[]}),patch.object(p,'run_step',side_effect=step),patch.object(p,'app_checksums',return_value=1):
    code=p.main(['--native-prefix','/synthetic/prefix','--cmake','/synthetic/cmake','--output-root',str(root),'--build-number','14','--bundle-id','io.github.tiertoast.Signum','--trust-probe','include','--signing-mode','adhoc','--release-notes',str(W/'docs/BETA_LOCAL_RELEASE_NOTES.md'),'--build','--verify-local-beta'])
   self.assertEqual(code,0);self.assertEqual(order,['app','app-audit','dmg','dmg-audit'])
   summary=json.loads((root/'summary.json').read_text());self.assertEqual(summary['status'],'verified-local-beta');self.assertFalse(summary['publicationQualified'])
class VolumeTests(unittest.TestCase):
 def fixture(self,root):
  app=root/'Signum.app';(app/'Contents').mkdir(parents=True);(app/'Contents/file').write_text('signed content')
  (app/'Contents/Resources').mkdir();(app/'Contents/Resources/BuildManifest.json').write_text('{}')
  (root/'BuildManifest.json').write_text('{}');(root/'Applications').symlink_to('/Applications')
  self.sums(root);return app,{'appFiles':a.tree(app)}
 def sums(self,root):
  rows=[n.sha(p)+'  '+str(p.relative_to(root)) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink() and p.name!='SHA256SUMS']
  (root/'SHA256SUMS').write_text('\n'.join(rows)+'\n')
 def test_valid_volume_matches_exact_audited_app(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);app,expected=self.fixture(root)
   with patch.object(a,'run') as run:a.verify_volume(root,app,expected)
   run.assert_called_once()
 def test_modified_app_cannot_be_hidden_by_regenerated_volume_sums(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);app,expected=self.fixture(root);(app/'Contents/file').write_text('modified');self.sums(root)
   with self.assertRaisesRegex(ValueError,'differs'):a.verify_volume(root,app,expected)
 def test_incomplete_checksum_list_is_rejected(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);app,expected=self.fixture(root);(root/'unlisted').write_text('extra')
   with self.assertRaisesRegex(ValueError,'Incomplete'):a.verify_volume(root,app,expected)
 def test_traversal_checksum_is_rejected(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);app,expected=self.fixture(root);(root/'SHA256SUMS').write_text('0'*64+'  ../escape\n')
   with self.assertRaises((ValueError,FileNotFoundError)):a.verify_volume(root,app,expected)
class SchemaTests(unittest.TestCase):
 def test_actual_license_and_schema_material_must_be_present(self):
  # Use tiny fixture with the real seven catalog entries, without copying/modifying runtime XSDs.
  import shutil
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   r=Path(d);schema=r/'Signum_SignumTrustAuthentication.bundle/Contents/Resources/Schemas';schema.mkdir(parents=True)
   catalog=json.loads((W/'scripts/schema-license-catalog.json').read_text())
   shutil.copytree(W/'Resources/Notices',r/'Notices')
   (r/'ThirdPartySources/Evidence').mkdir(parents=True)
   for row in catalog['resources']:
    shutil.copyfile(W/row['file'],schema/Path(row['file']).name)
    for path in row.get('additionalNotices',{}):
     if path.startswith('Resources/ThirdPartySources/'):shutil.copyfile(W/path,r/path[len('Resources/'):])
   shutil.copyfile(W/'Sources/SignumTrustAuthentication/Schemas/ETSI-LICENSE',schema/'ETSI-LICENSE')
   shutil.copyfile(W/'LICENSE',r/'Signum-LICENSE.txt');(r/'SchemaLicenseCatalog.json').write_text(json.dumps(catalog))
   self.assertEqual(a.schema_audit(r),7)
   (r/'Notices/W3C-XML-Namespace-Notice.txt').unlink()
   with self.assertRaises((ValueError,FileNotFoundError)):a.schema_audit(r)
if __name__=='__main__':unittest.main()
