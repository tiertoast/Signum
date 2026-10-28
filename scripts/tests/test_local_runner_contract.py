"""S07 prerequisites and real timeout/failure controls. No product code runs."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('runner_contract',ROOT/'scripts/test-local.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class LocalRunnerContractTests(unittest.TestCase):
    def args(self,root):
        prefix=root/'prefix'
        for name in ['lib/cmake/podofo/podofo-config.cmake','include/openssl/cms.h','include/freetype2/ft2build.h','lib/pkgconfig/xmlsec1-openssl.pc','include/libxml2/libxml/parser.h']:
            p=prefix/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
        return argparse.Namespace(group='swift',native_prefix=str(prefix),cmake='/usr/bin/true',ctest='/usr/bin/true',poppler='/usr/bin/true',xmlsec='/usr/bin/true',python=sys.executable,output_root=str(root/'out'))
    def test_explicit_tools_work_without_inherited_signum_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            args=self.args(Path(folder))
            with patch.dict(os.environ,{},clear=True),patch.object(runner.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'xmlsec1 9.9.9 (fixture)\nzipfile\ncmake version 9.9.9\nctest version 9.9.9',b'')):
                config=runner.setup(args)
            self.assertEqual(config['xmlsec'],'/usr/bin/true')
            self.assertEqual(config['python'],str(Path(sys.executable).resolve()))
    def test_missing_xmlsec_and_nonexecutable_python_fail_at_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);args=self.args(root);args.xmlsec=str(root/'missing')
            with self.assertRaisesRegex(ValueError,'Missing prerequisite XMLSec'):runner.setup(args)
            args.xmlsec='/usr/bin/true';args.python=str(root/'not-executable');Path(args.python).write_text('fixture');Path(args.python).chmod(0o600)
            with self.assertRaisesRegex(ValueError,'Missing prerequisite Python'):runner.setup(args)
    def test_unusable_xmlsec_is_not_accepted_by_existence_alone(self):
        with tempfile.TemporaryDirectory() as folder:
            args=self.args(Path(folder))
            with patch.object(runner.subprocess,'run',return_value=subprocess.CompletedProcess([],7,b'',b'bad dependency')):
                with self.assertRaisesRegex(ValueError,'Unusable prerequisite XMLSec'):runner.setup(args)
    def test_source_checkout_cannot_be_an_output_root(self):
        with self.assertRaisesRegex(ValueError,'outside the source checkout'):runner.Run(argparse.Namespace(output_root=str(ROOT/'.build/s07-forbidden')), {})
    def test_real_timeout_and_nonzero_exit_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            run=runner.Run.__new__(runner.Run);run.root=Path(folder);run.logs=run.root/'logs';run.logs.mkdir();run.config={};run.env=dict(os.environ);run.results=[]
            run.command('control',[sys.executable,'-c','print("control")'],timeout=10)
            self.assertEqual(run.results[-1]['exit'],0)
            with self.assertRaises(RuntimeError):run.command('failure',[sys.executable,'-c','raise SystemExit(7)'],timeout=10)
            self.assertEqual(run.results[-1]['exit'],7)
            with self.assertRaises(RuntimeError):run.command('timeout',[sys.executable,'-c','import signal; signal.pause()'],timeout=.05)
            self.assertEqual(run.results[-1]['exit'],124)


if __name__=='__main__':unittest.main()
