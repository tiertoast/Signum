#!/usr/bin/env python3
"""Bounded, offline, synthetic macOS test runner. No global installs or remote CI."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'scripts/local-test-groups.json'
SANITIZER_FILTER = '(' + '|'.join('BatchCleanupContractTests PostLoginCertificateTests OneShotContextTests PAdESInputContractTests SecurePINBufferTests SecureBatchNativeTests BatchAuthenticationTests BatchAuthIntegrationTests PKCS11WorkerTests PKCS11LifecycleIntegrationTests ProcessCoordinationTests SigningReviewTests VerificationDropLifecycleTests PAdESSourcePreflightTests SignumFileOutputTests SigningJobTests FixtureInfrastructureTests'.split()) + ')/'


def test_groups(root=ROOT):
    manifest = json.loads((root / 'scripts/local-test-groups.json').read_text())
    declared = [c for group in manifest['groups'].values() for c in group]
    actual = [c for p in (root / 'Tests/SignumCoreTests').glob('*.swift') for c in re.findall(r'(?:final )?class (\w+Tests):', p.read_text())]
    if sorted(actual) != sorted(declared) or len(set(declared)) != len(declared):
        raise ValueError('Test classes changed: classify every class exactly once in scripts/local-test-groups.json')
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
    ui = full or bool(set(selected) & set(manifest['requires']['windowserver']))
    native = helper or args.group in ('complete', 'pkcs11', 'sanitizers')
    config = {'group': args.group, 'selected': selected, 'fullSwift': full, 'helper': helper, 'ui': ui,
              'swift': executable('/usr/bin/swift', 'Swift'), 'cc': executable('/usr/bin/cc', 'C compiler'),
              'openssl': executable('/usr/bin/openssl', 'OpenSSL fixture tool')}
    if native:
        config['cmake'] = executable(args.cmake, 'CMake >= 3.23')
        config['ctest'] = executable(args.ctest, 'CTest')
    if helper:
        prefix = Path(args.native_prefix).expanduser().resolve() if args.native_prefix else ROOT / '.build/native-prefix'
        for relative in ('lib/cmake/podofo/podofo-config.cmake', 'include/openssl/cms.h', 'include/freetype2/ft2build.h'):
            if not (prefix / relative).is_file():
                raise ValueError('Missing native prerequisite: ' + str(prefix / relative) + '; pass --native-prefix')
        config['prefix'] = str(prefix)
    if poppler:
        config['poppler'] = executable(args.poppler, 'Poppler pdftoppm; pass --poppler')
    if ui:
        check = subprocess.run([config['swift'], '-e', 'import AppKit; import Darwin; exit(NSScreen.screens.isEmpty ? 1 : 0)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if check.returncode:
            raise ValueError('WindowServer is required for the complete/UI suite; use an explicit optional group on a headless host')
    config['optionalGroupsNotSelected'] = [] if args.group == 'complete' else ['No complete-suite claim: only group ' + args.group + ' selected']
    return config


class Run:
    def __init__(self, args, config):
        self.config = config
        parent = Path(args.output_root).expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.root = parent / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:10])
        self.root.mkdir(mode=0o700)
        self.logs = self.root / 'evidence'; self.logs.mkdir()
        self.results = []
        self.env = dict(os.environ)
        self.env.update(SIGNUM_TEST_FIXTURE_ROOT=str(self.root / 'fixtures'), SIGNUM_TEST_EVIDENCE_ROOT=str(self.logs / 'artifacts'))
        if 'poppler' in config: self.env['SIGNUM_TEST_POPPLER'] = config['poppler']
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
        flags = ['-DCMAKE_BUILD_TYPE=' + configuration]
        if source == 'Tools/PAdESPrototype':
            flags += ['-DCMAKE_PREFIX_PATH=' + self.config['prefix'], '-DOPENSSL_ROOT_DIR=' + self.config['prefix'], '-DSIGNUM_BUILD_OFFLINE_TESTS=ON']
        if sanitizer:
            option = '-fsanitize=' + sanitizer + ' -fno-omit-frame-pointer'
            flags += ['-DCMAKE_C_FLAGS=' + option, '-DCMAKE_CXX_FLAGS=' + option]
        self.command(name+'-configure', [self.config['cmake'], '-S', source, '-B', build] + flags)
        self.command(name+'-build', [self.config['cmake'], '--build', build, '--parallel', '4'], 600)
        env = dict(self.env)
        if sanitizer == 'address': env['ASAN_OPTIONS'] = 'detect_leaks=0'
        self.command(name, [self.config['ctest'], '--test-dir', build, '--output-on-failure', '--verbose'], 120, env)
        return build

    def swift(self, name='swift', sanitizer=None, selected=None):
        scratch = self.root / name
        args = [self.config['swift'], 'test', '--scratch-path', scratch, '--jobs', '2' if sanitizer else '4']
        if sanitizer: args += ['--sanitize=' + sanitizer, '--filter', SANITIZER_FILTER]
        elif selected is not None: args += ['--filter', '(' + '|'.join(selected) + ')/']
        env = dict(self.env)
        if sanitizer == 'address': env['ASAN_OPTIONS'] = 'detect_leaks=0'
        text = self.command(name, args, 900, env)
        # XCTest emits both per-class and aggregate counts. A complete suite
        # accepts no skipped test and requires actual execution.
        if not re.search(r'Executed [1-9][0-9]* tests?', text): raise RuntimeError('No XCTest result in ' + name)
        if re.search(r'\b[1-9][0-9]* tests? skipped\b|Test Case .* skipped', text): raise RuntimeError('Unexpected XCTest skip in selected mandatory group ' + name)
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
        if group in ('complete', 'sanitizers'):
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
    manifest = test_groups()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=['complete','swift','pades','pkcs11','packaging','sanitizers'] + list(manifest['groups']), default='complete')
    parser.add_argument('--native-prefix', default=os.environ.get('SIGNUM_NATIVE_PREFIX'))
    parser.add_argument('--cmake', default=os.environ.get('SIGNUM_CMAKE', 'cmake'))
    parser.add_argument('--ctest', default=os.environ.get('SIGNUM_CTEST', 'ctest'))
    parser.add_argument('--poppler', default=os.environ.get('SIGNUM_TEST_POPPLER', 'pdftoppm'))
    parser.add_argument('--output-root', default=str(ROOT / '.build/local-tests'))
    parser.add_argument('--check', action='store_true', help='Validate prerequisites without creating a test run')
    args = parser.parse_args()
    try: config = setup(args)
    except (ValueError, subprocess.SubprocessError) as error:
        print('SETUP ERROR: ' + str(error), file=sys.stderr); return 2
    if args.check: print(json.dumps(config, indent=2)); return 0
    run = Run(args, config)
    try: run.run()
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        run.write_summary('failed'); print(str(error), file=sys.stderr); return 1
    return 0


if __name__ == '__main__': sys.exit(main())
