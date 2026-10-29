import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
W=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('schema_license_contract',W/'scripts/schema_license_contract.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
class SchemaLicenseTests(unittest.TestCase):
 def catalog(self):return json.loads((W/'scripts/schema-license-catalog.json').read_text())
 def test_inventory_has_all_seven_documented_licenses(self):
  r=c.check(W,self.catalog(),True);self.assertEqual(r['resources'],7);self.assertTrue(r['redistributionReady']);self.assertEqual(r['unresolvedLicenses'],[])
 def test_distribution_rejects_unresolved_licenses(self):
  data=self.catalog();row=next(r for r in data['resources'] if r['file'].endswith('/xml.xsd'));row.update(licenseFile=None,licenseSHA256=None,status='unresolved-original-license-required')
  with self.assertRaisesRegex(ValueError,'unresolved'):c.check(W,data,True)
 def test_missing_or_changed_resource_and_license_are_rejected(self):
  for field in ['sha256','licenseSHA256']:
   data=self.catalog();row=next(r for r in data['resources'] if r['licenseFile']);row[field]='0'*64
   with self.assertRaisesRegex(ValueError,'hash changed'):c.check(W,data)
 def test_inventory_cannot_omit_a_resource(self):
  data=self.catalog();data['resources']=[r for r in data['resources'] if not r['file'].endswith('/xades.xsd')]
  with self.assertRaisesRegex(ValueError,'inventory'):c.check(W,data)
 def test_derivative_notice_cannot_be_missing_or_changed(self):
  data=self.catalog();row=next(r for r in data['resources'] if r['file'].endswith('/xml.xsd'))
  row['additionalNotices']['Resources/Notices/W3C-XML-Namespace-Notice.txt']='0'*64
  with self.assertRaisesRegex(ValueError,'hash changed'):c.check(W,data,True)
if __name__=='__main__':unittest.main()
