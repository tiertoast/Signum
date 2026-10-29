import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
W=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('schema_license_contract',W/'scripts/schema_license_contract.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
class SchemaLicenseTests(unittest.TestCase):
 def catalog(self):return json.loads((W/'scripts/schema-license-catalog.json').read_text())
 def test_inventory_preserves_three_explicit_unknown_licenses(self):
  r=c.check(W,self.catalog());self.assertEqual(r['resources'],7);self.assertFalse(r['redistributionReady']);self.assertEqual({Path(x).name for x in r['unresolvedLicenses']},{'xades.xsd','xmldsig.xsd','xml.xsd'})
 def test_distribution_rejects_unresolved_licenses(self):
  with self.assertRaisesRegex(ValueError,'unresolved'):c.check(W,self.catalog(),True)
 def test_missing_or_changed_resource_and_license_are_rejected(self):
  for field in ['sha256','licenseSHA256']:
   data=self.catalog();row=next(r for r in data['resources'] if r['licenseFile']);row[field]='0'*64
   with self.assertRaisesRegex(ValueError,'hash changed'):c.check(W,data)
 def test_inventory_cannot_omit_an_unlicensed_resource(self):
  data=self.catalog();data['resources']=[r for r in data['resources'] if not r['file'].endswith('/xades.xsd')]
  with self.assertRaisesRegex(ValueError,'inventory'):c.check(W,data)
if __name__=='__main__':unittest.main()
