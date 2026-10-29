#!/usr/bin/env python3
"""Author-run, bounded offline Phase5b verification. Never packages or runs Swift."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
W = Path(__file__).resolve().parents[1]
S = W.parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, W / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-prefix', type=Path, required=True, help='Validated prefix, read only')
    parser.add_argument('--output', type=Path, help='NEW directory under Signum-Stabilization/diagnostics')
    parser.add_argument('--budget-seconds', type=int, default=900)
    parser.add_argument('--cmake', default='/opt/homebrew/bin/cmake')
    parser.add_argument('--ctest', default='/opt/homebrew/bin/ctest')
    args = parser.parse_args()
    if args.budget_seconds < 30:
        parser.error('Budget must allow at least 30 seconds including cleanup')
    base = (S / 'diagnostics').resolve()
    output = (args.output or base / ('phase5b-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])).resolve()
    if S.resolve() not in base.parents or base not in output.parents or W in output.parents:
        parser.error('Output must be a new diagnostics subdirectory outside the repository')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'tmp').mkdir()
    prefix = args.native_prefix.resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SIGNUM_TEST_', 'PKG_CONFIG_', 'DYLD_'))}
    env.update(PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(output / 'tmp') + '/',
               MACOSX_DEPLOYMENT_TARGET='13.0', PKG_CONFIG_PATH=str(prefix / 'lib/pkgconfig'),
               PKG_CONFIG_LIBDIR=str(prefix / 'lib/pkgconfig'), ASAN_OPTIONS='detect_leaks=0')
    started = time.monotonic()
    summary = dict(schema=1, status='running', budgetSeconds=args.budget_seconds,
                   commands=[], blockers=[], failedTests=[], counts={},
                   scope='Offline targeted checks only; no M3-M6, Swift suite, packaging, signing or release')
    active = None

    def stop():
        nonlocal active
        if active is None:
            return
        # Kill the owned group even if its leader exited with descendants alive.
        try:
            os.killpg(active.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            active.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(active.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        active.wait(timeout=1)
        active = None

    def interrupted(number, frame):
        raise TimeoutError('Overall budget expired' if number == signal.SIGALRM else 'Interrupted by signal ' + str(number))

    def run(label, command, limit=90):
        nonlocal active
        remaining = args.budget_seconds - 15 - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError('Overall budget exhausted')
        seconds = min(limit, remaining)
        log = output / (label + '.log')
        begin = time.monotonic()
        # External timeout plus process-group cleanup in the Python supervisor.
        actual = ['/usr/bin/timeout', '-k', '1s', str(seconds) + 's'] + [str(x) for x in command]
        code = None
        try:
            with log.open('wb') as handle:
                active = subprocess.Popen(actual, cwd=W, env=env, stdout=handle,
                                          stderr=subprocess.STDOUT, start_new_session=True)
                code = active.wait(timeout=seconds + 1.5)
        finally:
            stop()
            data = log.read_bytes() if log.exists() else b''
            text = data.decode(errors='replace')
            row = dict(label=label, command=actual, exit=code, seconds=time.monotonic() - begin,
                       log=str(log), sha256=hashlib.sha256(data).hexdigest())
            for raw in re.findall(r'\{"cases":[^\n]+', text):
                result = json.loads(raw)
                row['scalarCases'] = result
                summary['failedTests'].extend(result['failed'])
            tests = re.search(r'Ran (\d+) tests?', text)
            if tests:
                row['pythonTests'] = int(tests[1])
            targets = re.search(r'(\d+)% tests passed.*?out of (\d+)', text)
            if targets:
                row['ctestTargets'] = int(targets[2])
            row['failedTestNames'] = re.findall(r'^(?:FAIL|ERROR): ([^\n]+)', text, re.M)
            if label.endswith('-ctest'):
                row['failedTestNames'].extend(re.findall(r'^\s*\d+\s+-\s+(\S+)\s+\(', text, re.M))
            summary['failedTests'].extend(row['failedTestNames'])
            diagnostic = bool(re.search(r'ERROR: AddressSanitizer|WARNING: ThreadSanitizer', text))
            coverage_ok = True
            if label.endswith('-ctest'):
                expected_targets = 1 if label.startswith(('asan-', 'tsan-')) else 3
                scalar = row.get('scalarCases', {})
                coverage_ok = (row.get('ctestTargets') == expected_targets and
                               scalar.get('cases') == 18 and scalar.get('passed') == 18 and
                               scalar.get('failed') == [])
            if label == 'python-contracts':
                coverage_ok = row.get('pythonTests', 0) >= 16
            row['coverageValid'] = coverage_ok
            row['passed'] = code == 0 and not diagnostic and coverage_ok
            summary['commands'].append(row)
            if row['passed']:
                log.unlink()  # Detailed success logs are deliberately not retained.
                row['log'] = None
                if label.endswith('-ctest'):
                    for detail in (output / ('native-' + label.removesuffix('-ctest')) / 'Testing').rglob('*.log'):
                        detail.unlink()
        if not row['passed']:
            raise RuntimeError('Check failed: ' + label)
        return text

    def git(*arguments):
        return subprocess.check_output(['/usr/bin/git', *arguments], cwd=W, text=True, timeout=5).strip()

    initial = None
    for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        signal.signal(number, interrupted)
    # Reserve cleanup and the two bounded final Git reads within the total.
    signal.setitimer(signal.ITIMER_REAL, args.budget_seconds - 15)
    try:
        initial = dict(head=git('rev-parse', 'HEAD'), status=git('status', '--short', '--ignored'))
        summary['initialRepository'] = initial
        if initial['status']:
            raise RuntimeError('Require a clean repository, including ignored files')
        native = json.loads((prefix / 'signum-native-build.json').read_text())
        if native.get('architecture') != 'arm64' or native.get('deploymentTarget') != '13.0':
            raise ValueError('Expected validated arm64/macOS13 native metadata')
        catalog = json.loads((W / 'scripts/third-party-notices.json').read_text())
        proof = module('notices_contract').check_notices(W / 'Resources/Notices', catalog, set(catalog['components']), native)
        summary['noticeInventoryFiles'] = len(proof)
        schemas = module('schema_license_contract').check(W, json.loads((W / 'scripts/schema-license-catalog.json').read_text()))
        summary['schemas'] = schemas
        summary['blockers'].extend('Original schema license missing: ' + f for f in schemas['unresolvedLicenses'])
        dossier = module('podofo_source_contract').check(json.loads((W / 'Resources/ThirdPartySources/podofo.json').read_text()),
                   {'components': list(catalog['components'])}, native, W / 'Resources/ThirdPartySources')
        summary['podofo'] = dossier
        summary['blockers'].extend(dossier['pending'])
        if catalog['components']['freetype'].get('licenseSelection') not in ('FTL', 'GPL-2.0-or-later'):
            summary['blockers'].append('FreeType FTL/GPL author selection pending')
        summary['distributionScope'] = 'Recorded prerequisites only; exact-candidate source/binary/package audit and legal assessment remain separate'
        run('python-contracts', ['/usr/bin/python3', '-m', 'unittest',
            'scripts.tests.test_notices_contract', 'scripts.tests.test_phase5b_notices',
            'scripts.tests.test_schema_licenses', 'scripts.tests.test_podofo_source_contract', '-v'], 60)
        run('actool-version', ['/usr/bin/xcrun', 'actool', '--version'], 20)
        for mode, sanitizer in [('debug', None), ('release', None), ('asan', 'address'), ('tsan', 'thread')]:
            build = output / ('native-' + mode)
            flags = [args.cmake, '-S', W / 'Tools/PKCS11Tests', '-B', build,
                     '-DCMAKE_BUILD_TYPE=' + ('Release' if mode == 'release' else 'Debug'),
                     '-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0', '-DCMAKE_OSX_ARCHITECTURES=arm64']
            if sanitizer:
                for language in ('C', 'CXX'):
                    flags.append('-DCMAKE_' + language + '_FLAGS=-fsanitize=' + sanitizer + ' -fno-omit-frame-pointer')
            run(mode + '-configure', flags)
            run(mode + '-build', [args.cmake, '--build', build, '--parallel', '4'] +
                (['--target', 'signum-find-count-tests'] if sanitizer else []), 180)
            run(mode + '-ctest', [args.ctest, '--test-dir', build, '--output-on-failure', '--verbose'] +
                (['-R', '^signum-find-count-contract$'] if sanitizer else []), 90)
        summary['status'] = 'blocked' if summary['blockers'] else 'passed'
    except (Exception, KeyboardInterrupt) as error:
        summary['status'] = 'failed'
        summary['error'] = str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        stop()
        if initial is not None:
            try:
                final = dict(head=git('rev-parse', 'HEAD'), status=git('status', '--short', '--ignored'))
                summary['repositoryUnchanged'] = final == initial
                if final != initial:
                    summary['status'] = 'failed'
                    summary['error'] = 'Repository changed during verification'
            except Exception as error:
                summary.update(status='failed', error=str(error))
        summary['counts'] = dict(commands=len(summary['commands']),
            pythonTests=sum(r.get('pythonTests', 0) for r in summary['commands']),
            ctestTargets=sum(r.get('ctestTargets', 0) for r in summary['commands']),
            scalarCaseExecutions=sum(r.get('scalarCases', {}).get('cases', 0) for r in summary['commands']))
        summary['seconds'] = time.monotonic() - started
        summary['cleanup'] = 'Owned command process groups terminated and leaders reaped; no repository cleanup performed'
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(dict(status=summary['status'], seconds=summary['seconds'], summary=str(output / 'summary.json'))))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
