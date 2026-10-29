#!/usr/bin/env python3
"""Manual, bounded Beta staging. Default: preflight only; never publication approval."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('beta_recipe', REPO / 'scripts/build-beta-app.py')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


def preflight(args):
    checks = recipe.distribution_prerequisites(args.native_prefix)
    blockers = checks['blockers']
    try:
        checks['metadata'] = recipe.public_beta_metadata(args.build_number, args.bundle_id)
        # main() already exclusively created the validated output root.
        native = json.loads((args.native_prefix / 'signum-native-build.json').read_text())
        if native.get('recipe') != 1 or native.get('architecture') != 'arm64':
            blockers.append('Native recipe 1 / arm64 required')
        if recipe.version_key(native['deploymentTarget']) > recipe.version_key('13.0'):
            blockers.append('Native prefix exceeds macOS 13.0')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            blockers.append('macOS arm64 host required')
        for tool in ('/usr/bin/xcrun', '/usr/bin/swift', '/usr/bin/otool', '/usr/bin/lipo',
                     '/usr/bin/install_name_tool', '/usr/bin/strip', '/usr/bin/codesign', '/usr/bin/hdiutil'):
            if not os.access(tool, os.X_OK):
                blockers.append('Tool missing: ' + tool)
        if not os.access(args.cmake, os.X_OK):
            blockers.append('Provide an existing CMake executable; nothing is installed automatically')
        status = subprocess.check_output(['/usr/bin/git', 'status', '--short', '--ignored'],
                                         cwd=REPO, text=True, timeout=5)
        if status.strip():
            blockers.append('Repository must be clean including ignored files')
        checks['sourceCommit'] = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'],
                                                         cwd=REPO, text=True, timeout=5).strip()
        if args.build and (args.release_notes is None or not args.release_notes.is_file()):
            blockers.append('Existing author-approved Beta release notes required for --build')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        blockers.append(str(error))
    checks['ready'] = not blockers
    return checks


def run_step(name, command, root, deadline):
    log = root / (name + '.log')
    started = time.monotonic()
    process = None
    result = dict(name=name, exit=None)
    try:
        remaining = deadline - started - 2  # reserve cleanup and summary time
        if remaining <= 0:
            raise TimeoutError('Overall time budget exhausted')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(root / 'tmp') + '/')
        with log.open('x') as stream:
            process = subprocess.Popen([str(x) for x in command], cwd=REPO, env=env,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            result['exit'] = process.wait(timeout=remaining)
        if result['exit'] != 0:
            raise RuntimeError(name + ' failed: exit ' + str(result['exit']))
        log.unlink()
    except BaseException as error:
        result['error'] = str(error)
        if log.exists():
            result['log'] = str(log)
    finally:
        if process is not None:
            # Kill the whole owned group, including grandchildren after parent exit.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        result['seconds'] = round(time.monotonic() - started, 3)
    return result


def app_checksums(app, target, deadline):
    """Hash regular files, record symlink targets; never pretend a directory is a file."""
    rows, links = [], {}
    for path in sorted(app.rglob('*')):
        relative = str(path.relative_to(app))
        if '\n' in relative or '\\' in relative:
            raise ValueError('Ambiguous checksum filename')
        if path.is_symlink():
            links[relative] = os.readlink(path)
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    if time.monotonic() >= deadline - 2:
                        raise TimeoutError('Checksum time budget exhausted')
                    digest.update(block)
            rows.append(digest.hexdigest() + '  ' + relative)
    with target.open('x') as stream:
        stream.write('\n'.join(rows) + '\n')
    with target.with_name('Signum.app.symlinks.json').open('x') as stream:
        json.dump(links, stream, indent=2)
    return len(rows)


def interrupted(signum, frame):
    raise InterruptedError('Interrupted by signal ' + str(signum))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-prefix', type=Path, required=True)
    parser.add_argument('--cmake', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True, help='NEW external folder, also for preflight summary')
    parser.add_argument('--build-number', type=int, required=True)
    parser.add_argument('--bundle-id', required=True)
    parser.add_argument('--trust-probe', choices=('include', 'exclude'), required=True)
    parser.add_argument('--signing-mode', choices=('none', 'adhoc'), default='none')
    parser.add_argument('--release-notes', type=Path)
    parser.add_argument('--budget-seconds', type=int, default=900)
    parser.add_argument('--build', action='store_true', help='Explicit manual staging only; never release approval')
    args = parser.parse_args(argv)
    if args.budget_seconds < 5:
        parser.error('Budget must be at least 5 seconds')
    # Refuse any existing/protected destination before creating even summary.json.
    root = recipe.external_workspace(args.output_root)
    args.output_root = root
    root.mkdir(parents=True, exist_ok=False)
    (root / 'tmp').mkdir()
    started = time.monotonic()
    deadline = started + args.budget_seconds
    summary = dict(mode='build-staging' if args.build else 'preflight', budgetSeconds=args.budget_seconds,
                   publicationQualified=False, signingMode=args.signing_mode, steps=[], status='failed')
    previous_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        previous_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, interrupted)
    signal.alarm(max(1, math.floor(args.budget_seconds - 1)))
    try:
        summary['prerequisites'] = preflight(args)
        if not summary['prerequisites']['ready']:
            summary['status'] = 'blocked'
        elif not args.build:
            summary['status'] = 'preflight-passed-artifact-unverified'
        else:
            app = root / 'Signum.app'
            commands = [('app', [sys.executable, REPO / 'scripts/build-beta-app.py', '--output', app,
                         '--configuration', 'release', '--native-prefix', args.native_prefix.resolve(),
                         '--cmake', args.cmake.resolve(), '--scratch-root', root / 'scratch',
                         '--signing-mode', args.signing_mode, '--public-beta-build', args.build_number,
                         '--bundle-id', args.bundle_id, '--trust-probe', args.trust_probe]),
                        ('dmg', [sys.executable, REPO / 'scripts/build-beta-dmg.py', '--app', app,
                         '--release-notes', args.release_notes.resolve(), '--output', root / 'Signum-0.7.0-beta-arm64.dmg']
                         + (['--allow-unsigned-staging'] if args.signing_mode == 'none' else []))]
            for name, command in commands:
                result = run_step(name, command, root, deadline)
                summary['steps'].append(result)
                if 'error' in result:
                    raise RuntimeError(result['error'])
            summary['appHashedRegularFiles'] = app_checksums(app, root / 'Signum.app.SHA256SUMS', deadline)
            summary['status'] = 'staging-complete-artifact-publication-unverified'
    except (Exception, KeyboardInterrupt) as error:
        summary['error'] = str(error)
    finally:
        signal.alarm(0)
        incomplete = []
        for path in [root / 'scratch', root / 'tmp'] + list(root.glob('.signum-bundle-*')) + list(root.glob('.signum-dmg-*')):
            if not path.exists():
                continue
            remaining = deadline - time.monotonic() - 0.2
            if remaining <= 0:
                incomplete.append(str(path))
                continue
            try:
                subprocess.run(['/bin/rm', '-rf', '--', str(path)], check=True, timeout=remaining)
            except (OSError, subprocess.SubprocessError):
                incomplete.append(str(path))
        if incomplete:
            summary['cleanupIncomplete'] = incomplete
            summary['status'] = 'failed'
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        summary['counts'] = dict(steps=len(summary['steps']),
                                 failed=sum('error' in step for step in summary['steps']),
                                 blockers=len(summary.get('prerequisites', {}).get('blockers', [])))
        summary['seconds'] = round(time.monotonic() - started, 3)
        with (root / 'summary.json').open('x') as stream:
            json.dump(summary, stream, indent=2)
            stream.write('\n')
    print(json.dumps(dict(status=summary['status'], summary=str(root / 'summary.json'),
                          publicationQualified=False, seconds=summary['seconds'])))
    return 0 if summary['status'] in ('preflight-passed-artifact-unverified', 'staging-complete-artifact-publication-unverified') else 1


if __name__ == '__main__':
    raise SystemExit(main())
