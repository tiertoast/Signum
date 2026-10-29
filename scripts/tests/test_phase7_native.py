"""Offline safety checks; never runs CMake, a compiler, signing, or packaging."""
import importlib.util
from pathlib import Path
import sys,tarfile,tempfile,time,unittest
W=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('phase7_native',W/'scripts/rebuild-beta-native.py');n=importlib.util.module_from_spec(s);s.loader.exec_module(n)
class NativeCheckpointTests(unittest.TestCase):
 def test_tar_traversal_is_rejected_before_extraction(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);archive=root/'bad.tar'
   with tarfile.open(archive,'w') as t:t.addfile(tarfile.TarInfo('../escaped'))
   target=root/'source';target.mkdir()
   with self.assertRaisesRegex(ValueError,'Unsafe'):n.extract_pinned(archive,target)
   self.assertFalse((root/'escaped').exists())
 def test_junit_requires_the_real_nonempty_unskipped_test(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   p=Path(d)/'report.xml'
   for text in ['<testsuite/>','<testsuite><testcase name="unrelated"/></testsuite>','<testsuite><testcase name="signum-pades-reliability"><skipped/></testcase></testsuite>','<testsuite><testcase name="signum-pades-reliability"><failure/></testcase></testsuite>']:
    p.write_text(text)
    with self.assertRaises(ValueError):n.check_junit(p)
   p.write_text('<testsuite><testcase name="signum-pades-reliability"/></testsuite>');self.assertEqual(n.check_junit(p),1)
 def test_expected_usage_exit_is_not_a_failed_smoke(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);r=n.Runner(root,10)
   self.assertEqual(r.run('usage',[sys.executable,'-c','print("usage");raise SystemExit(2)'],capture=True,expected_exit=2).strip(),'usage')
   self.assertFalse((root/'usage.log').exists());self.assertEqual(r.steps[0]['exit'],2)
 def test_unexpected_failure_retains_log(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);r=n.Runner(root,10)
   with self.assertRaises(RuntimeError):r.run('failed',[sys.executable,'-c','print("failure");raise SystemExit(2)'])
   self.assertIn('failure',(root/'failed.log').read_text());self.assertIn('error',r.steps[0])
 def test_child_timeout_is_bounded(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);r=n.Runner(root,5.1);start=time.monotonic()
   with self.assertRaises(Exception):r.run('timeout',[sys.executable,'-c','import time;time.sleep(60)'])
   self.assertLess(time.monotonic()-start,2);self.assertTrue((root/'timeout.log').exists())
 def test_prefix_seed_excludes_old_podofo_freetype(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
   root=Path(d);base=root/'base';(base/'lib/pkgconfig').mkdir(parents=True);(base/'lib/cmake').mkdir()
   for name in ['openssl','libxml2','xmlsec1','freetype2','podofo']:
    p=base/'include'/name;p.mkdir(parents=True);(p/'header.h').write_text(name)
   for name in ['libcrypto.3.dylib','libssl.3.dylib','libxml2.dylib','libxmlsec1.dylib','libpodofo.1.1.2.dylib','libfreetype.a']:(base/'lib'/name).write_text(name)
   for name in ['freetype','podofo','OpenSSL','libxml2']:(base/'lib/cmake'/name).mkdir()
   (base/'lib/pkgconfig/freetype2.pc').write_text('old FT')
   (base/'lib/pkgconfig/openssl.pc').write_text('prefix='+str(base))
   prefix=root/'new';n.seed_dependencies(base,prefix)
   self.assertFalse((prefix/'include/podofo').exists());self.assertFalse((prefix/'include/freetype2').exists())
   self.assertFalse((prefix/'lib/libpodofo.1.1.2.dylib').exists());self.assertFalse((prefix/'lib/libfreetype.a').exists())
   self.assertFalse((prefix/'lib/pkgconfig/freetype2.pc').exists());self.assertIn(str(prefix),(prefix/'lib/pkgconfig/openssl.pc').read_text())
   self.assertIn(str(base),(base/'lib/pkgconfig/openssl.pc').read_text())
 def test_options_preserve_target_and_disable_external_registry(self):
  options=n.cmake_options(Path('/new/prefix'),Path('/new'),'/sdk')
  self.assertIn('-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0',options);self.assertIn('-DCMAKE_OSX_ARCHITECTURES=arm64',options)
  self.assertIn('-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',options);self.assertIn('-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',options)
if __name__=='__main__':unittest.main()
