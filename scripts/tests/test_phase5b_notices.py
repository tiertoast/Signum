"""S17 credit contract: actual packaged notice catalog, no native loads."""
import importlib.util,json,shutil,tempfile,unittest
from pathlib import Path
W=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('notices',W/'scripts/notices_contract.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class FreeTypeCreditTests(unittest.TestCase):
 def inputs(self):
  catalog=json.loads((W/'scripts/third-party-notices.json').read_text())
  self.assertIn('FreeType-acknowledgment.txt',catalog['components']['freetype']['notices'])
  return catalog,{'sources':{'freetype':{'version':'freetype-2.13.3'}}}
 def test_credit_is_in_the_packaged_notice_contract(self):
  catalog,native=self.inputs()
  result=n.check_notices(W/'Resources/Notices',catalog,{'freetype'},native)
  self.assertIn('FreeType-acknowledgment.txt',result)
  self.assertIn('based in part on the work of the FreeType Team',(W/'Resources/Notices/FreeType-acknowledgment.txt').read_text())
 def test_missing_credit_is_rejected(self):
  catalog,native=self.inputs()
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   for name in catalog['components']['freetype']['notices']:
    if name!='FreeType-acknowledgment.txt':shutil.copyfile(W/'Resources/Notices'/name,root/name)
   with self.assertRaisesRegex(ValueError,'Missing notice'):n.check_notices(root,catalog,{'freetype'},native)
if __name__=='__main__':unittest.main()
