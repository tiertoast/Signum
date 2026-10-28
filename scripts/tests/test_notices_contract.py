"""S08 controlled closure, notice bytes and failure fixtures; no real libraries load."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('notice_contract',Path(__file__).resolve().parents[1]/'notices_contract.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class NoticeContractTests(unittest.TestCase):
    def fixture(self,body):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();prefix=root/'lib';prefix.mkdir();app=root/'product';app.write_bytes(b'product');library=prefix/'libfixture.1.dylib';library.write_bytes(b'library')
            notices=root/'Notices';notices.mkdir();data=b'SYNTHETIC COMPLETE NOTICE\n'+b'x'*1200;(notices/'fixture.txt').write_bytes(data)
            catalog={'components':{'fixture':{'libraryPatterns':[r'libfixture\.1\.dylib'],'notices':{'fixture.txt':hashlib.sha256(data).hexdigest()},'minimumNoticeBytes':1000,'nativeKey':'fixture','nativeVersion':'fixture-1'}}}
            native={'sources':{'fixture':{'version':'fixture-1'}}}
            inspect=lambda p:['@rpath/libfixture.1.dylib','/usr/lib/libSystem.B.dylib']
            body(app,prefix,notices,native,catalog,inspect)
    def test_complete_local_text_covers_derived_transitive_closure(self):
        self.fixture(lambda a,p,n,m,s,i:self.assertEqual(c.audit([a],p,n,m,s,i)['components'],['fixture']))
    def test_missing_changed_and_referral_notices_fail(self):
        def body(a,p,n,m,s,i):
            file=n/'fixture.txt';original=file.read_bytes()
            for data in [b'See Copyright',b'wrong'+original]:
                file.write_bytes(data)
                with self.assertRaises(ValueError):c.audit([a],p,n,m,s,i)
            file.unlink()
            with self.assertRaisesRegex(ValueError,'Missing notice'):c.audit([a],p,n,m,s,i)
        self.fixture(body)
    def test_unknown_library_and_external_reference_fail(self):
        def body(a,p,n,m,s,i):
            unknown=p/'libunknown.dylib';unknown.write_bytes(b'unknown')
            with self.assertRaisesRegex(ValueError,'without notice'):c.audit([a],p,n,m,s,lambda _:['@rpath/libunknown.dylib'])
            with self.assertRaisesRegex(ValueError,'external'):c.audit([a],p,n,m,s,lambda _:['/outside-prefix/libfixture.dylib'])
        self.fixture(body)
    def test_wrong_version_and_missing_embedded_entry_fail(self):
        def body(a,p,n,m,s,i):
            m['sources']['fixture']['version']='other'
            with self.assertRaisesRegex(ValueError,'version mismatch'):c.audit([a],p,n,m,s,i)
            m['sources']['fixture']['version']='fixture-1';s['components']['fixture']['embedded']=['unknown-embedded']
            with self.assertRaisesRegex(ValueError,'embedded'):c.audit([a],p,n,m,s,i)
        self.fixture(body)


if __name__=='__main__':unittest.main()
