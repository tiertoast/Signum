#!/usr/bin/env python3
"""Bounded, offline, synthetic macOS test runner. No global installs or remote CI."""
import argparse
import datetime
import json
import importlib.util
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'scripts/local-test-groups.json'
_spec = importlib.util.spec_from_file_location('xctest_contract', ROOT / 'scripts/xctest_contract.py')
contract = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(contract)
SANITIZER_FILTER = '(' + '|'.join('CAdESMemoryContractTests BatchCleanupContractTests PostLoginCertificateTests OneShotContextTests PAdESInputContractTests SecurePINBufferTests SecureBatchNativeTests BatchAuthenticationTests BatchAuthIntegrationTests PKCS11WorkerTests PKCS11LifecycleIntegrationTests ProcessCoordinationTests SigningReviewTests VerificationDropLifecycleTests PAdESSourcePreflightTests SignumFileOutputTests SigningJobTests FileAcquisitionTests FixtureInfrastructureTests SnapshotRetirementTests PDFPreviewPreparationTests DocumentSnapshotTests PAdESRenderCoordinationTests PAdESPlacementPerformanceTests SignaturePlacementOverlayTests SupervisedProcessTests ConcurrencyOwnershipTests SigningOperationTests SigningWorkspaceTests DynamicFormatWorkspaceTests'.split()) + ')/'


def test_groups(root=ROOT):
    manifest = json.loads((root / 'scripts/local-test-groups.json').read_text())
    contract.check_classes(contract.source_classes(root), manifest)
    return manifest


def executable(value, label):
    path = shutil.which(value) if value else None
    if not path or not os.access(path, os.X_OK):
        raise ValueError('Missing prerequisite ' + label + ': ' + str(value))
    return str(Path(path).resolve())


def setup(args):
    if platform.system() != 'Darwin':
        raise ValueError('Local suites require macOS and the Apple developer toolchain')
    manifest = test_groups()
    full = args.group in ('complete', 'swift')
    selected = sum(manifest['groups'].values(), []) if full else manifest['groups'].get(args.group, [])
    helper = full or args.group in ('pades', 'sanitizers') or bool(set(selected) & set(manifest['requires']['helper']))
    poppler = full or bool(set(selected) & set(manifest['requires']['poppler']))
    ui = full or args.group == 'sanitizers' or bool(set(selected) & set(manifest['requires']['windowserver']))
    native = helper or args.group in ('complete', 'pkcs11', 'sanitizers')
    config = {'group': args.group, 'selected': selected, 'fullSwift': full, 'helper': helper, 'ui': ui, 'skipSanitizers': getattr(args, 'skip_sanitizers', False),
              'deploymentTarget': os.environ.get('MACOSX_DEPLOYMENT_TARGET', '13.0'),
              'triple': getattr(args, 'triple', None) or platform.machine() + '-apple-macosx' + os.environ.get('MACOSX_DEPLOYMENT_TARGET', '13.0'),
              'swift': executable('/usr/bin/swift', 'Swift'), 'cc': executable('/usr/bin/cc', 'C compiler'),
              'openssl': executable('/usr/bin/openssl', 'OpenSSL fixture tool')}
    if native:
        config['cmake'] = executable(args.cmake, 'CMake >= 3.23')
        config['ctest'] = executable(args.ctest, 'CTest')
    if helper or full or selected or args.group == 'sanitizers':
        if not args.native_prefix: raise ValueError('Missing native prerequisite: pass --native-prefix or SIGNUM_NATIVE_PREFIX for the offline prefix')
        prefix = Path(args.native_prefix).expanduser().resolve()
        for relative in ('lib/cmake/podofo/podofo-config.cmake', 'include/openssl/cms.h', 'include/freetype2/ft2build.h', 'lib/pkgconfig/xmlsec1-openssl.pc', 'include/libxml2/libxml/parser.h'):
            if not (prefix / relative).is_file():
                raise ValueError('Missing native prerequisite: ' + str(prefix / relative) + '; pass --native-prefix')
        config['prefix'] = str(prefix)
        config['xmlsec'] = executable(getattr(args, 'xmlsec', None) or os.environ.get('SIGNUM_TEST_XMLSEC') or str(prefix/'bin/xmlsec1'), 'XMLSec fixture CLI; pass --xmlsec or SIGNUM_TEST_XMLSEC')
        config['python'] = executable(getattr(args, 'python', None) or os.environ.get('SIGNUM_TEST_PYTHON') or sys.executable, 'Python fixture CLI; pass --python or SIGNUM_TEST_PYTHON')
        xmlenv = dict(os.environ, DYLD_LIBRARY_PATH=str(prefix/'lib'))
        for label, command, environment in [('XMLSec', [config['xmlsec'], '--version'], xmlenv), ('Python zipfile', [config['python'], '-c', 'import zipfile; print(zipfile.__name__)'], dict(os.environ))]:
            probe = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=30)
            output = (probe.stdout + probe.stderr).decode(errors='replace')
            required = r'xmlsec1\s+\d+\.\d+' if label=='XMLSec' else r'zipfile'
            if probe.returncode or not re.search(required, output): raise ValueError('Unusable prerequisite ' + label + ': ' + output[-1000:])
    if native:
        config['toolVersions'] = {}
        for key, pattern in [('cmake',r'cmake version (\d+)\.(\d+)\.(\d+)'),('ctest',r'ctest version (\d+)\.(\d+)\.(\d+)')]:
            probe = subprocess.run([config[key],'--version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            match = re.search(pattern,(probe.stdout+probe.stderr).decode(errors='replace'))
            if probe.returncode or not match or tuple(map(int,match.groups()[:2])) < (3,23):
                raise ValueError('Unusable prerequisite '+key+' >= 3.23')
            config['toolVersions'][key] = match[0]
    if poppler:
        config['poppler'] = executable(args.poppler, 'Poppler pdftoppm; pass --poppler')
    if ui:
        parent = Path(getattr(args, 'output_root', None) or Path(tempfile.gettempdir()).resolve()/'signum-local-tests').expanduser().resolve()
        if parent == ROOT or ROOT in parent.parents: raise ValueError('--output-root must be outside the source checkout')
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='signum-windowserver-', dir=parent) as cache:
            check = subprocess.run([config['swift'], '-module-cache-path', cache, '-e', 'import AppKit; import Darwin; exit(NSScreen.screens.isEmpty ? 1 : 0)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if check.returncode:
            raise ValueError('WindowServer is required for the complete/UI suite; use an explicit optional group on a headless host')
    config['optionalGroupsNotSelected'] = [] if args.group == 'complete' else ['No complete-suite claim: only group ' + args.group + ' selected']
    return config


class Run:
    def __init__(self, args, config):
        self.config = config
        parent = Path(args.output_root).expanduser().resolve()
        if parent == ROOT or ROOT in parent.parents: raise ValueError('--output-root must be outside the source checkout')
        parent.mkdir(parents=True, exist_ok=True)
        self.root = parent / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:10])
        self.root.mkdir(mode=0o700)
        self.logs = self.root / 'evidence'; self.logs.mkdir()
        self.results = []
        self.env = {key:value for key,value in os.environ.items() if not key.startswith('SIGNUM_TEST_')}
        self.env.update(SIGNUM_TEST_FIXTURE_ROOT=str(self.root / 'fixtures'), SIGNUM_TEST_EVIDENCE_ROOT=str(self.logs / 'artifacts'))
        (self.root/'tmp').mkdir()
        self.env['TMPDIR'] = str(self.root/'tmp') + '/'
        if 'poppler' in config: self.env['SIGNUM_TEST_POPPLER'] = config['poppler']
        for key, name in [('xmlsec','SIGNUM_TEST_XMLSEC'),('python','SIGNUM_TEST_PYTHON')]:
            if key in config: self.env[name] = config[key]
        if 'prefix' in config:
            pkgconfig = str(Path(config['prefix'])/'lib/pkgconfig')
            self.env.update(PKG_CONFIG_PATH=pkgconfig, PKG_CONFIG_LIBDIR=pkgconfig)
        self.env['MACOSX_DEPLOYMENT_TARGET'] = config.get('deploymentTarget','13.0')
        self.write_summary('running')
        print('Test run: ' + str(self.root), flush=True)

    def write_summary(self, status):
        (self.root / 'results.json').write_text(json.dumps({'status': status, 'source': str(ROOT), 'setup': self.config, 'results': self.results}, indent=2) + '\n')

    def command(self, name, command, timeout=300, env=None):
        log = self.logs / (name + '.log'); started = time.monotonic()
        with log.open('wb') as output:
            output.write((json.dumps({'command': [str(x) for x in command], 'cwd': str(ROOT), 'timeout': timeout}) + '\n').encode()); output.flush()
            process = subprocess.Popen([str(x) for x in command], cwd=ROOT, env=env or self.env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try: code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3)
                code = 124
        result = {'name': name, 'exit': code, 'seconds': round(time.monotonic()-started, 3), 'log': str(log)}
        self.results.append(result); self.write_summary('running'); print(json.dumps(result), flush=True)
        if code: raise RuntimeError(name + ' failed; inspect ' + str(log))
        return log.read_text(errors='replace')

    def native(self, name, source, configuration='Debug', sanitizer=None):
        build = self.root / name
        flags = ['-DCMAKE_BUILD_TYPE=' + configuration, '-DCMAKE_OSX_DEPLOYMENT_TARGET=' + self.config.get('deploymentTarget','13.0'), '-DCMAKE_OSX_ARCHITECTURES=' + platform.machine()]
        if source == 'Tools/PAdESPrototype':
            flags += ['-DCMAKE_PREFIX_PATH=' + self.config['prefix'], '-DOPENSSL_ROOT_DIR=' + self.config['prefix'], '-DSIGNUM_BUILD_OFFLINE_TESTS=ON']
        if sanitizer:
            option = '-fsanitize=' + sanitizer + ' -fno-omit-frame-pointer'
            flags += ['-DCMAKE_C_FLAGS=' + option, '-DCMAKE_CXX_FLAGS=' + option]
        self.command(name+'-configure', [self.config['cmake'], '-S', source, '-B', build] + flags)
        self.command(name+'-build', [self.config['cmake'], '--build', build, '--parallel', '4'], 600)
        env = dict(self.env)
        if sanitizer == 'address': env['ASAN_OPTIONS'] = 'detect_leaks=0'
        text = self.command(name, [self.config['ctest'], '--test-dir', build, '--output-on-failure', '--verbose'], 120, env)
        if not re.search(r'100% tests passed(?:,.*?)? out of [1-9][0-9]*',text):
            self.results[-1]['contractError'] = 'No nonempty passing CTest summary'
            raise RuntimeError('No nonempty passing CTest summary in '+name)
        return build

    def swift_arguments(self, scratch):
        args = ['--scratch-path', str(scratch), '--jobs', '4', '--triple', self.config['triple']]
        if 'prefix' in self.config: args += ['-Xlinker', '-rpath', '-Xlinker', str(Path(self.config['prefix'])/'lib')]
        return args

    def catalog(self, name='swift'):
        args = [self.config['swift'], 'test'] + self.swift_arguments(self.root/name)
        text = self.command(name+'-catalog', args+['list'], 900)
        methods = contract.parse_catalog(text)
        proof = contract.check_classes({m.split('/')[0] for m in methods}, test_groups())
        (self.logs/(name+'-catalog.json')).write_text(json.dumps(dict(methods=methods, **proof), indent=2))
        return methods, proof

    def swift(self, name='swift', sanitizer=None, selected=None):
        scratch = self.root/name
        methods, coverage = self.catalog(name)
        args = [self.config['swift'], 'test'] + self.swift_arguments(scratch)
        if sanitizer: args += ['--sanitize='+sanitizer, '--filter', SANITIZER_FILTER]
        elif selected is not None: args += ['--filter', '('+'|'.join(selected)+')/']
        if sanitizer:
            expected = [m for m in methods if re.search(SANITIZER_FILTER,m)]
        elif selected is not None:
            classes = {contract.qualified(c) for c in selected}
            expected = [m for m in methods if m.split('/')[0] in classes]
        else:
            if coverage['excluded']: raise RuntimeError('Full Swift cannot exclude classes: '+repr(coverage['excluded']))
            expected = methods
        if not expected: raise RuntimeError('Selected group contains no discovered XCTest methods')
        env = dict(self.env)
        if sanitizer == 'address': env['ASAN_OPTIONS'] = 'detect_leaks=0'
        text = self.command(name, args, 1800, env)
        try: proof = contract.verify_execution(text, expected)
        except ValueError as error:
            self.results[-1]['contractError'] = str(error)
            raise RuntimeError(str(error)) from error
        self.results[-1]['xctest'] = proof; self.write_summary('running')
        return scratch

    def run(self):
        group = self.config['group']
        if self.config['helper']:
            build = self.native('pades-debug', 'Tools/PAdESPrototype')
            self.env['SIGNUM_TEST_PADES_HELPER'] = str(build / 'signum-pades-local')
        if group in ('complete', 'pades'): self.native('pades-release', 'Tools/PAdESPrototype', 'Release')
        if group in ('complete', 'pkcs11'): self.native('pkcs11-debug', 'Tools/PKCS11Tests')
        if self.config['fullSwift'] or self.config['selected']:
            scratch = self.swift(selected=None if self.config['fullSwift'] else self.config['selected'])
            text = self.command('swift-bin-path', [self.config['swift'], 'build', '--scratch-path', scratch, '--show-bin-path'], 60)
            binary = Path(text.strip().splitlines()[-1]) / 'SignumPKCS11Worker'
            self.env['SIGNUM_TEST_LOCK_REFUSAL_WORKER'] = str(binary)
        if group in ('complete', 'packaging'):
            self.command('packaging', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v'])
        if group == 'sanitizers' or (group == 'complete' and not self.config['skipSanitizers']):
            if group == 'sanitizers':
                self.command('sanitizer-control-worker', [self.config['swift'], 'build', '--scratch-path', self.root/'swift', '--product', 'SignumPKCS11Worker', '--jobs', '4'], 600)
                text = self.command('swift-bin-path', [self.config['swift'], 'build', '--scratch-path', self.root/'swift', '--show-bin-path'], 60)
                self.env['SIGNUM_TEST_LOCK_REFUSAL_WORKER'] = str(Path(text.strip().splitlines()[-1]) / 'SignumPKCS11Worker')
            self.swift('swift-asan', 'address'); self.swift('swift-tsan', 'thread')
            self.native('pkcs11-asan', 'Tools/PKCS11Tests', sanitizer='address')
            self.native('pades-asan', 'Tools/PAdESPrototype', sanitizer='address')
            self.native('pkcs11-tsan', 'Tools/PKCS11Tests', sanitizer='thread')
        self.write_summary('passed')


def main():
    try: manifest = json.loads(MANIFEST.read_text())
    except (OSError, ValueError) as error: print('SETUP ERROR: '+str(error), file=sys.stderr); return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=['complete','swift','pades','pkcs11','packaging','sanitizers'] + list(manifest['groups']), default='complete')
    parser.add_argument('--native-prefix', default=os.environ.get('SIGNUM_NATIVE_PREFIX'))
    parser.add_argument('--cmake', default=os.environ.get('SIGNUM_CMAKE', 'cmake'))
    parser.add_argument('--ctest', default=os.environ.get('SIGNUM_CTEST', 'ctest'))
    parser.add_argument('--poppler', default=os.environ.get('SIGNUM_TEST_POPPLER', 'pdftoppm'))
    parser.add_argument('--xmlsec', default=os.environ.get('SIGNUM_TEST_XMLSEC'))
    parser.add_argument('--python', default=os.environ.get('SIGNUM_TEST_PYTHON'))
    parser.add_argument('--triple', help='Swift target triple; defaults to host architecture and deployment target')
    parser.add_argument('--output-root', default=str(Path(tempfile.gettempdir()).resolve()/'signum-local-tests'))
    parser.add_argument('--skip-sanitizers', action='store_true', help='Omit sanitizer reruns for Swift-only changes; all regular complete gates remain mandatory')
    parser.add_argument('--check', action='store_true', help='Validate prerequisites and compiled XCTest catalog; build in external scratch without running test cases')
    args = parser.parse_args()
    try: config = setup(args)
    except (ValueError, subprocess.SubprocessError) as error:
        print('SETUP ERROR: ' + str(error), file=sys.stderr); return 2
    try:
        run = Run(args, config)
        if args.check:
            if config['fullSwift'] or config['selected'] or args.group=='sanitizers':
                methods, coverage = run.catalog(); config['discovery'] = dict(methods=len(methods), **coverage)
            run.write_summary('checked'); print(json.dumps(config, indent=2)); return 0
        run.run()
    except (ValueError, RuntimeError, subprocess.SubprocessError, OSError) as error:
        if 'run' in locals(): run.write_summary('failed')
        print(str(error), file=sys.stderr); return 1
    return 0


if __name__ == '__main__': sys.exit(main())
