"""Test runner setup and classification without launching suites."""
import argparse
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('local_runner', ROOT/'scripts/test-local.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class LocalRunnerTests(unittest.TestCase):
    def test_every_swift_test_class_has_one_explicit_group(self):
        manifest = runner.test_groups()
        self.assertEqual(len(manifest['groups']), 6)
        self.assertIn('PAdESDefaultPlacementTests', manifest['groups']['ui'])
        self.assertIn('PAdESOrientationOutputTests', manifest['groups']['poppler'])

    def test_missing_tool_is_a_clear_setup_error(self):
        with self.assertRaisesRegex(ValueError, 'Missing prerequisite CMake'):
            runner.executable('/synthetic/unavailable/cmake', 'CMake')

    def test_full_suite_never_assumes_an_old_native_prefix(self):
        args = argparse.Namespace(group='swift', native_prefix='/synthetic/missing/prefix', cmake='/usr/bin/true', ctest='/usr/bin/true', poppler='/usr/bin/true')
        with self.assertRaisesRegex(ValueError, 'Missing native prerequisite'):
            runner.setup(args)

    def test_complete_skip_sanitizers_preserves_all_regular_gates(self):
        run = runner.Run.__new__(runner.Run)
        run.config = dict(group='complete', helper=True, fullSwift=True, selected=[],
                          swift='/synthetic/swift', skipSanitizers=True)
        run.env = {}
        calls = []
        def native(name, *args, **kwargs):
            calls.append(name)
            return Path('/synthetic/native')
        def swift(*args, **kwargs):
            calls.append('swift')
            return Path('/synthetic/swift')
        def command(name, *args, **kwargs):
            calls.append(name)
            return '/synthetic/bin\n'
        run.native, run.swift, run.command = native, swift, command
        run.write_summary = lambda status: calls.append(status)
        run.run()
        self.assertEqual(calls, ['pades-debug', 'pades-release', 'pkcs11-debug',
                                 'swift', 'swift-bin-path', 'packaging', 'passed'])

    def test_sanitizer_selection_preserves_14a_and_covers_14b(self):
        for name in ['OneShotContextTests','PostLoginCertificateTests','SigningReviewTests','VerificationDropLifecycleTests','PAdESSourcePreflightTests','SignumFileOutputTests','FileAcquisitionTests']:
            self.assertIn(name, runner.SANITIZER_FILTER)


if __name__ == '__main__': unittest.main()
