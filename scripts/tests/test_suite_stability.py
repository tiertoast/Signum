"""Controls for the measurement tool; no product, XCTest or budget changes."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import os

spec = importlib.util.spec_from_file_location('stability', Path(__file__).resolve().parents[1]/'test-suite-stability.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class StabilityMeasurementTests(unittest.TestCase):
    def test_execution_requires_every_started_and_completed_method_once(self):
        name = 'Target.Case/testOne'
        good = "Test Case '-[Target.Case testOne]' started.\nTest Case '-[Target.Case testOne]' passed (0.125 seconds).\n"
        proof = s.parse_execution(good, [name])
        self.assertTrue(proof['completeCoverage'])
        self.assertEqual(proof['passed'], 1)
        for bad in ['', good+good, good.splitlines()[0]]:
            self.assertFalse(s.parse_execution(bad, [name])['completeCoverage'])
        for status in ['failed', 'skipped']:
            proof = s.parse_execution(good.replace('passed', status), [name])
            self.assertTrue(proof['completeCoverage'])
            self.assertEqual(proof[status], 1)
            self.assertEqual(proof['passed'], 0)

    def test_selection_does_not_drop_a_historical_method(self):
        cases = dict(failedMethods=['Target.Case/testOne'], classes=['Target.Case'], pertinentFilter='Case')
        methods = ['Target.Case/testOne', 'Target.Case/testTwo']
        self.assertEqual(s.expected_methods(methods, cases, 'failed-methods'), methods[:1])
        self.assertEqual(s.expected_methods(methods, cases, 'failed-classes'), methods)
        with self.assertRaisesRegex(ValueError, 'absent'):
            s.expected_methods(methods[1:], cases, 'failed-methods')

    def test_real_command_nonzero_and_timeout_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body, timeout, code in [('success', 'print("control")', 3, 0),
                    ('failure', 'raise SystemExit(7)', 3, 7),
                    ('timeout', 'import signal; signal.pause()', 0.15, 124)]:
                record = s.measure_command([sys.executable, '-c', body], root/(name+'.log'), dict(os.environ), timeout)
                self.assertEqual(record['exit'], code)
                self.assertTrue(Path(record['events']).is_file())
                self.assertGreater(record['durationMonotonicSeconds'], 0)
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                s.measure_command([sys.executable, '-c', 'print(1)'], root/'success.log', dict(os.environ), 3)

    def test_cpu_load_processes_start_then_terminate_and_are_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            load = s.CPULoad(2, Path(directory)/'load', 10)
            try:
                load.start()
                self.assertEqual(len(load.processes), 2)
                self.assertTrue(all(child.poll() is None for child, _, _ in load.processes))
            finally:
                load.stop()
            self.assertTrue(all(row['reaped'] and row['workerGone'] and row['receipt'] for row in load.records))

    def test_source_checkout_is_not_an_output(self):
        with self.assertRaises(ValueError):
            s.outside_checkout(s.ROOT/'fake-output')


if __name__ == '__main__':
    unittest.main()
