"""Offline Phase6 guards. Never constructs an app or runs signing/build tools."""
import importlib.util,json,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
W=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('recipe',W/'scripts/build-beta-app.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class PublicBetaContractTests(unittest.TestCase):
 def test_external_workspace_is_required_and_exclusive(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d).resolve()
   with self.assertRaises(ValueError):p.external_workspace(W/'generated')
   with self.assertRaises(ValueError):p.external_workspace(root)
   self.assertEqual(p.external_workspace(root/'new'),root/'new')
 def test_metadata_is_explicit_and_legacy_preview_stays_unchanged(self):
  with self.assertRaises(ValueError):p.public_beta_metadata(0,'io.github.tiertoast.Signum.Beta')
  with self.assertRaises(ValueError):p.public_beta_metadata(1,'')
  data=p.public_beta_metadata(1,'io.github.tiertoast.Signum.Beta')
  self.assertEqual(data['CFBundleShortVersionString'],'0.7.0');self.assertIn('Beta',data['CFBundleDisplayName'])
  self.assertEqual(p.preview_metadata('0.7.0',14)[0],'io.github.tiertoast.Signum.DevelopmentPreview.V07.B14')
 def test_unsigned_never_invokes_signing_or_runtime_smoke(self):
  calls=[];old=p.run;p.run=lambda *a,**kw:calls.append(a[0])
  try:
   r=p.seal_code([Path('/synthetic/Signum')],Path('/synthetic/Signum.app'),'none')
   self.assertFalse(r);self.assertEqual(calls,[[ '/usr/bin/codesign','--remove-signature',Path('/synthetic/Signum')]])
  finally:p.run=old
 def test_invalid_signing_mode_is_rejected(self):
  with self.assertRaises(ValueError):p.seal_code([],Path('/synthetic/Signum.app'),'developer-id')
 def test_unsigned_cannot_bypass_public_license_gate(self):
  with self.assertRaisesRegex(ValueError,'prerequisite gate'):
   p.build(Path('/synthetic/Signum.app'),'release',Path('/synthetic/prefix'),Path('/synthetic/cmake'),signing_mode='none')
 def test_unresolved_licenses_stop_before_any_build_or_copy(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   root=Path(folder);prefix=root/'prefix';prefix.mkdir();(prefix/'signum-native-build.json').write_text(json.dumps({'recipe':1,'architecture':'arm64'}))
   def git_only(command,**kwargs):
    self.assertEqual(command[0],'/usr/bin/git')
    return '' if command[1]=='status' else 'frozen-commit'
   with patch.object(p.platform,'system',return_value='Darwin'),patch.object(p.platform,'machine',return_value='arm64'),patch.object(p,'run',side_effect=git_only),patch.object(p,'distribution_prerequisites',return_value={'ready':False,'blockers':['schema license missing']}):
    with self.assertRaisesRegex(ValueError,'schema license missing'):
     p.build(root/'Signum.app','release',prefix,Path('/synthetic/cmake'),scratch_root=root/'scratch',signing_mode='none',public_beta_build=1,bundle_id='test.Signum',trust_probe='exclude')
   self.assertFalse((root/'scratch').exists());self.assertFalse((root/'Signum.app').exists())

class ManualAndDMGGuards(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  def module(name,file):
   spec=importlib.util.spec_from_file_location(name,W/'scripts'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
  cls.manual=module('manual_beta','prepare-public-beta.py');cls.dmg=module('beta_dmg','build-beta-dmg.py')
 def test_preflight_blocked_produces_summary_and_never_builds(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   output=Path(folder)/'new'
   with patch.object(self.manual,'preflight',return_value={'ready':False,'blockers':['missing original license']}), patch.object(self.manual,'run_step') as step:
    code=self.manual.main(['--native-prefix','/synthetic/prefix','--cmake','/synthetic/cmake','--output-root',str(output),'--build-number','1','--bundle-id','test.Signum','--trust-probe','exclude','--build'])
   self.assertEqual(code,1);step.assert_not_called()
   summary=json.loads((output/'summary.json').read_text())
   self.assertEqual(summary['status'],'blocked');self.assertFalse(summary['publicationQualified'])
   self.assertEqual([f.name for f in output.iterdir()],['summary.json'])
 def test_real_preflight_accepts_its_owned_new_summary_directory(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   root=Path(folder);prefix=root/'prefix';prefix.mkdir();(prefix/'signum-native-build.json').write_text(json.dumps({'recipe':1,'architecture':'arm64','deploymentTarget':'13.0'}))
   with patch.object(self.manual.recipe,'distribution_prerequisites',return_value={'ready':False,'blockers':['license missing']}),patch.object(self.manual.platform,'system',return_value='Darwin'),patch.object(self.manual.platform,'machine',return_value='arm64'),patch.object(self.manual.os,'access',return_value=True),patch.object(self.manual.subprocess,'check_output',side_effect=['','frozen-commit']):
    code=self.manual.main(['--native-prefix',str(prefix),'--cmake','/synthetic/cmake','--output-root',str(root/'new'),'--build-number','1','--bundle-id','test.Signum','--trust-probe','exclude'])
   summary=json.loads((root/'new/summary.json').read_text())
   self.assertEqual(code,1);self.assertEqual(summary['prerequisites']['blockers'],['license missing']);self.assertEqual(summary['prerequisites']['sourceCommit'],'frozen-commit')
 def test_child_timeout_is_bounded_and_logs_are_retained(self):
  import sys,time
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   result=self.manual.run_step('timeout',[sys.executable,'-c','import time;time.sleep(60)'],Path(folder),time.monotonic()+2.1)
   self.assertIn('error',result);self.assertLess(result['seconds'],2);self.assertTrue(Path(result['log']).is_file())
 def test_success_removes_detailed_log(self):
  import sys,time
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   result=self.manual.run_step('success',[sys.executable,'-c','print("ok")'],Path(folder),time.monotonic()+5)
   self.assertEqual(result['exit'],0);self.assertNotIn('error',result);self.assertFalse((Path(folder)/'success.log').exists())
 def test_unsigned_dmg_rejects_missing_opt_in_or_tampered_main_before_tools(self):
  import hashlib,plistlib
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   root=Path(folder);app=root/'Signum.app';resources=app/'Contents/Resources';resources.mkdir(parents=True)
   binary=app/'Contents/MacOS/Signum';binary.parent.mkdir();binary.write_bytes(b'original')
   (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString':'0.7.0','CFBundleVersion':'1'}))
   manifest={'configuration':'release','architecture':'arm64','sourceTrackedDirty':False,'version':'0.7.0','build':'1','signingMode':'none','distributionChannel':'public-beta-staging','publicationQualified':False,'mainExecutableSHA256':hashlib.sha256(b'original').hexdigest(),'nestedCodeSHA256':{}}
   (resources/'BuildManifest.json').write_text(json.dumps(manifest));notes=root/'notes.md';notes.write_text('Beta')
   with patch.object(self.dmg,'run') as run:
    with self.assertRaisesRegex(ValueError,'explicit staging'):self.dmg.build(app,notes,root/'new.dmg')
    binary.write_bytes(b'tampered')
    with self.assertRaisesRegex(ValueError,'hash mismatch'):self.dmg.build(app,notes,root/'new.dmg',True)
    run.assert_not_called()
 def test_app_checksum_does_not_follow_links(self):
  import time
  with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
   root=Path(folder);app=root/'Signum.app';app.mkdir();(app/'file').write_text('content');(app/'link').symlink_to('/private/tmp/nonexistent')
   self.assertEqual(self.manual.app_checksums(app,root/'Signum.app.SHA256SUMS',time.monotonic()+5),1)
   self.assertEqual(json.loads((root/'Signum.app.symlinks.json').read_text()),{'link':'/private/tmp/nonexistent'})

if __name__=='__main__':unittest.main()
