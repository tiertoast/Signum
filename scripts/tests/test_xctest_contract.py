"""S07 controls: coverage and execution must fail closed, independent of Swift."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('xctest_contract', Path(__file__).resolve().parents[1]/'xctest_contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class XCTestContractTests(unittest.TestCase):
    def manifest(self): return {'groups': {'unit': ['FixtureTests']}, 'excluded': {}}
    def text(self): return "SignumCoreTests.FixtureTests/testOne\nSignumCoreTests.FixtureTests/testTwo\n"
    def test_correct_catalog_is_covered(self):
        methods = contract.parse_catalog('Build complete!\n'+self.text())
        self.assertEqual(len(methods), 2)
        self.assertEqual(contract.check_classes({m.split('/')[0] for m in methods},self.manifest())['classes'],1)
    def test_missing_class_fails(self):
        with self.assertRaisesRegex(ValueError,'unclassified'): contract.check_classes({'SignumCoreTests.NewTests'},self.manifest())
    def test_stale_class_fails(self):
        with self.assertRaisesRegex(ValueError,'absent'): contract.check_classes(set(),self.manifest())
    def test_duplicate_assignment_fails(self):
        m=self.manifest();m['groups']['other']=['SignumCoreTests.FixtureTests']
        with self.assertRaisesRegex(ValueError,'more than once'): contract.declared_classes(m)
    def test_explicit_exclusion_requires_reason(self):
        m=self.manifest();m['excluded']={'Other.ExcludedTests':''}
        with self.assertRaisesRegex(ValueError,'nonempty reason'): contract.declared_classes(m)
        m['excluded']['Other.ExcludedTests']='Unavailable on this host'
        contract.check_classes({'SignumCoreTests.FixtureTests','Other.ExcludedTests'},m)
    def test_empty_or_duplicate_discovery_fails(self):
        for text in ['Build complete!',self.text()+self.text()]:
            with self.assertRaises(ValueError):contract.parse_catalog(text)
    def execution(self, methods):
        return '\n'.join("Test Case '-["+m.replace('/',' ')+"]' "+s+" (0.001 seconds)." for m in methods for s in ['started','passed'])
    def test_real_method_pairs_match(self):
        methods=contract.parse_catalog(self.text());proof=contract.verify_execution(self.execution(methods),methods)
        self.assertEqual(proof['byTarget'],{'SignumCoreTests':2})
    def test_empty_missing_duplicate_and_skipped_execution_fail(self):
        methods=contract.parse_catalog(self.text());valid=self.execution(methods)
        for invalid in ['',self.execution(methods[:1]),valid+'\n'+valid,valid.replace('passed','skipped'),valid.replace('passed','failed')]:
            with self.assertRaises(ValueError):contract.verify_execution(invalid,methods)


if __name__ == '__main__':unittest.main()
