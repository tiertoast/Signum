#!/usr/bin/env python3
"""Offline stability measurements. Never retries away a failure or changes assertions."""
import argparse
from collections import Counter
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = Path(__file__).with_name('local-stability-cases.json')
SPEC = importlib.util.spec_from_file_location('xctest_contract', Path(__file__).with_name('xctest_contract.py'))
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
CASE_LINE = re.compile(r"^Test Case '-\[([^ ]+) ([^\]]+)\]' (started|passed|failed|skipped)(?: \(([\d.]+) seconds\))?")


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def outside_checkout(value):
    path = Path(value).expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError('Output/scratch must be outside the source checkout')
    return path


def expected_methods(methods, cases, selection):
    if selection == 'full':
        selected = methods
    elif selection == 'failed-methods':
        selected = [name for name in methods if name in cases['failedMethods']]
        if set(selected) != set(cases['failedMethods']):
            raise ValueError('A historical failure method is absent from compiled discovery')
    elif selection == 'failed-classes':
        selected = [name for name in methods if name.split('/')[0] in cases['classes']]
        if {name.split('/')[0] for name in selected} != set(cases['classes']):
            raise ValueError('A failure class is absent from compiled discovery')
    else:
        selected = [name for name in methods if re.search(cases['pertinentFilter'], name)]
    if not selected:
        raise ValueError('Empty selected XCTest catalog')
    return sorted(selected)


def filter_expression(cases, selection):
    if selection == 'failed-methods':
        return '(' + '|'.join(re.escape(name) for name in cases['failedMethods']) + ')$'
    if selection == 'failed-classes':
        return '(' + '|'.join(re.escape(name) for name in cases['classes']) + ')/'
    return cases['pertinentFilter'] if selection == 'pertinent' else None


def parse_execution(text, expected):
    started, cases, errors = [], [], []
    for number, line in enumerate(text.splitlines(), 1):
        match = CASE_LINE.match(line)
        if match:
            owner, method, status, duration = match.groups()
            name = owner + '/' + method
            if status == 'started':
                started.append(name)
            else:
                cases.append(dict(method=name, status=status, seconds=float(duration) if duration else None,
                                  logLine=number))
        if 'error:' in line:
            errors.append(dict(logLine=number, message=line))
    complete = Counter(started) == Counter(expected) == Counter(item['method'] for item in cases)
    return dict(expected=len(expected), started=len(started), completed=len(cases),
                completeCoverage=complete, cases=cases, errors=errors,
                passed=sum(item['status'] == 'passed' for item in cases),
                failed=sum(item['status'] == 'failed' for item in cases),
                skipped=sum(item['status'] == 'skipped' for item in cases))


def measure_command(command, log, env, timeout):
    """Timestamp receipt of output, not an unobservable XCTest emission time."""
    log = Path(log)
    if log.exists():
        raise ValueError('Refusing to overwrite evidence: ' + str(log))
    log.parent.mkdir(parents=True, exist_ok=True)
    begin, wall = time.monotonic(), time.time()
    record = dict(command=[str(value) for value in command], cwd=str(ROOT), startUTC=utc(), timeout=timeout)
    process = subprocess.Popen(record['command'], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
    record['pid'] = process.pid
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    pending = b''
    timed_out = False
    clock_jumps = []
    last_sample = -1.0
    events_path = log.with_suffix('.events.jsonl')
    try:
        with log.open('wb') as output, events_path.open('w') as events:
            while selector.get_map():
                elapsed = time.monotonic() - begin
                gap = time.time() - wall - elapsed
                if elapsed - last_sample >= 0.25:
                    sample = dict(kind='clock', receivedUTC=utc(), receivedMonotonicSeconds=elapsed,
                                  wallMinusMonotonicSeconds=gap, loadAverage=os.getloadavg())
                    events.write(json.dumps(sample) + '\n')
                    if abs(gap) > 1 and (not clock_jumps or abs(gap - clock_jumps[-1]['gap']) > 1):
                        clock_jumps.append(dict(observedMonotonicSeconds=elapsed, gap=gap, observedUTC=utc()))
                    last_sample = elapsed
                if elapsed > timeout and process.poll() is None:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                if elapsed > timeout + 15:
                    timed_out = True
                    break
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.write(chunk)
                    output.flush()
                    pending += chunk
                    while b'\n' in pending:
                        raw, pending = pending.split(b'\n', 1)
                        line = raw.decode(errors='replace')
                        if CASE_LINE.match(line) or 'error:' in line:
                            events.write(json.dumps(dict(kind='output-received', receivedUTC=utc(),
                                receivedMonotonicSeconds=time.monotonic()-begin, text=line))+'\n')
                events.flush()
            process.wait(timeout=5)
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    record.update(exit=124 if timed_out else process.returncode, endUTC=utc(),
                  durationMonotonicSeconds=time.monotonic()-begin, utcElapsedSeconds=time.time()-wall,
                  clockJumps=clock_jumps, outputTiming='receipt times; pipe buffering may delay delivery',
                  log=str(log), events=str(events_path), logSHA256=hashlib.sha256(log.read_bytes()).hexdigest())
    log.with_suffix('.json').write_text(json.dumps(record, indent=2)+'\n')
    return record


def cpu_worker(seconds, receipt):
    running = True
    def stop(_signal, _frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    started, cpu = time.monotonic(), time.process_time()
    value = 7
    print('READY', flush=True)
    while running and time.monotonic() - started < seconds:
        for _ in range(4096):
            value = (value * 1664525 + 1013904223) & 0xffffffff
    Path(receipt).write_text(json.dumps(dict(pid=os.getpid(), wallSeconds=time.monotonic()-started,
        cpuSeconds=time.process_time()-cpu, stoppedBySignal=not running, checksum=value)))


class CPULoad:
    def __init__(self, count, root, lifetime):
        self.processes = []
        self.root = Path(root)
        self.count = count
        self.lifetime = lifetime
        self.records = []

    def start(self):
        self.root.mkdir(parents=True)
        for index in range(self.count):
            receipt = self.root / ('worker-%02d.json' % index)
            command = ['/usr/bin/timeout', '-k', '5s', str(int(self.lifetime)+5)+'s', sys.executable,
                       str(Path(__file__).resolve()), '--cpu-worker', str(self.lifetime), '--receipt', str(receipt)]
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
            self.processes.append((child, receipt, command))
        selector = selectors.DefaultSelector()
        for child, _, _ in self.processes:
            selector.register(child.stdout, selectors.EVENT_READ, child.pid)
        ready = set()
        deadline = time.monotonic() + 20
        try:
            while len(ready) < self.count and time.monotonic() < deadline:
                for key, _ in selector.select(0.1):
                    data = os.read(key.fileobj.fileno(), 1024)
                    if b'READY' in data:
                        ready.add(key.data)
                        selector.unregister(key.fileobj)
                    elif not data:
                        raise RuntimeError('CPU worker exited before readiness')
            if len(ready) != self.count:
                raise RuntimeError('CPU load readiness deadline exceeded')
        finally:
            selector.close()
        return self

    def stop(self):
        for child, _, _ in self.processes:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        for child, receipt, command in self.processes:
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait(timeout=5)
            child.stdout.close()
            details = json.loads(receipt.read_text()) if receipt.exists() else None
            worker_gone = None
            if details:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        os.kill(details['pid'], 0)
                    except ProcessLookupError:
                        worker_gone = True
                        break
                    time.sleep(0.01)
                if worker_gone is None:
                    worker_gone = False
            self.records.append(dict(supervisorPID=child.pid, command=command, exit=code,
                reaped=child.poll() is not None, workerGone=worker_gone, receipt=details))
        (self.root/'cleanup.json').write_text(json.dumps(self.records, indent=2)+'\n')
        if len(self.records) != self.count or not all(item['reaped'] and item['workerGone'] is True for item in self.records):
            raise RuntimeError('Synthetic CPU supervisors were not reaped')


def summarize(records):
    by_method = {}
    for record in records:
        for case in record.get('execution', {}).get('cases', []):
            row = by_method.setdefault(case['method'], dict(passed=0, failed=0, skipped=0, durations=[], failures=[]))
            row[case['status']] += 1
            if case['seconds'] is not None:
                row['durations'].append(case['seconds'])
            if case['status'] != 'passed':
                row['failures'].append(dict(run=record['iteration'], log=record['log'], errors=record['execution']['errors']))
    for row in by_method.values():
        values = row.pop('durations')
        row['seconds'] = dict(minimum=min(values), median=statistics.median(values), maximum=max(values)) if values else None
    return by_method


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-file', type=Path, default=CASE_FILE)
    parser.add_argument('--configuration', choices=['debug', 'release'])
    parser.add_argument('--condition', choices=['idle', 'cpu'])
    parser.add_argument('--selection', choices=['failed-methods', 'failed-classes', 'pertinent', 'full'])
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scratch', type=Path)
    parser.add_argument('--native-prefix', type=Path)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--swift', default='/usr/bin/swift')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--xmlsec', type=Path)
    parser.add_argument('--poppler', type=Path)
    parser.add_argument('--triple', default='arm64-apple-macosx13.0')
    parser.add_argument('--load-processes', type=int, default=os.cpu_count())
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--cpu-worker', type=float)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    if args.cpu_worker is not None:
        cpu_worker(args.cpu_worker, args.receipt)
        return 0
    for key in ['configuration', 'condition', 'selection', 'output', 'scratch', 'native_prefix', 'helper', 'xmlsec', 'poppler']:
        if getattr(args, key) is None:
            parser.error('--'+key.replace('_', '-')+' is required')
    if args.repeat < 1 or args.load_processes < 1 or args.timeout < 1:
        parser.error('Repeat, CPU process count and timeout must be positive')
    output, scratch = outside_checkout(args.output), outside_checkout(args.scratch)
    output.mkdir(parents=True, exist_ok=False)
    prefix = args.native_prefix.resolve()
    for path in [args.helper, args.xmlsec, args.poppler]:
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError('Missing executable prerequisite: '+str(path))
    env = {key: value for key, value in os.environ.items() if not key.startswith('SIGNUM_TEST_')}
    env.update(MACOSX_DEPLOYMENT_TARGET='13.0', PKG_CONFIG_PATH=str(prefix/'lib/pkgconfig'),
               PKG_CONFIG_LIBDIR=str(prefix/'lib/pkgconfig'), PYTHONDONTWRITEBYTECODE='1',
               SIGNUM_TEST_PADES_HELPER=str(args.helper.resolve()), SIGNUM_TEST_XMLSEC=str(args.xmlsec.resolve()),
               SIGNUM_TEST_PYTHON=args.python, SIGNUM_TEST_POPPLER=str(args.poppler.resolve()), NSUnbufferedIO='YES')
    cases = json.loads(args.case_file.read_text())
    command = [args.swift, 'test', '-c', args.configuration, '--scratch-path', str(scratch), '--jobs', '4',
               '--triple', args.triple, '-Xlinker', '-rpath', '-Xlinker', str(prefix/'lib')]
    (output/'catalog-tmp').mkdir()
    env['TMPDIR'] = str(output/'catalog-tmp')+'/'
    catalog_record = measure_command(command+['list'], output/'catalog.log', env, 1200)
    if catalog_record['exit']:
        raise RuntimeError('Compiled discovery failed')
    methods = CONTRACT.parse_catalog((output/'catalog.log').read_text())
    CONTRACT.check_classes({name.split('/')[0] for name in methods}, json.loads((ROOT/'scripts/local-test-groups.json').read_text()))
    expected = expected_methods(methods, cases, args.selection)
    expression = filter_expression(cases, args.selection)
    if expression:
        command += ['--filter', expression]
    (output/'expected-methods.json').write_text(json.dumps(expected, indent=2))
    source_names = subprocess.check_output(['/usr/bin/git','ls-files'], cwd=ROOT, text=True, timeout=20).splitlines()
    fingerprint = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names if (ROOT/name).is_file()}
    report = dict(configuration=args.configuration, condition=args.condition, selection=args.selection,
                  requestedRepetitions=args.repeat, expectedMethods=len(expected), logicalCPUs=os.cpu_count(),
                  syntheticCPUProcesses=args.load_processes if args.condition=='cpu' else 0,
                  baselineSourceSHA256=fingerprint, environment={key:value for key,value in env.items() if key.startswith(('SIGNUM_TEST_', 'PKG_CONFIG_')) or key in ['MACOSX_DEPLOYMENT_TARGET','NSUnbufferedIO','PYTHONDONTWRITEBYTECODE']}, records=[], state='running',
                  quietCondition='No synthetic load; external host activity is not controlled, load averages recorded')
    load = CPULoad(args.load_processes, output/'cpu-load', args.timeout*args.repeat+60) if args.condition=='cpu' else None
    def save():
        report['methodSummary'] = summarize(report['records'])
        (output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    save()
    try:
        if load:
            load.start()
        for iteration in range(1, args.repeat+1):
            folder = output/('iteration-%02d' % iteration)
            folder.mkdir()
            (folder/'tmp').mkdir()
            current = dict(env, TMPDIR=str(folder/'tmp')+'/', SIGNUM_TEST_FIXTURE_ROOT=str(folder/'fixtures'),
                           SIGNUM_TEST_EVIDENCE_ROOT=str(folder/'artifacts'))
            record = measure_command(command, folder/'swift.log', current, args.timeout)
            record['iteration'] = iteration
            record['execution'] = parse_execution((folder/'swift.log').read_text(), expected)
            record['passed'] = record['exit']==0 and record['execution']['completeCoverage'] and not record['execution']['failed'] and not record['execution']['skipped']
            report['records'].append(record)
            save()
            print(json.dumps(dict(iteration=iteration, configuration=args.configuration, condition=args.condition,
                selection=args.selection, exit=record['exit'], completeCoverage=record['execution']['completeCoverage'],
                passed=record['execution']['passed'], failed=record['execution']['failed'],
                seconds=record['durationMonotonicSeconds'], clockJumps=record['clockJumps'])), flush=True)
        report['state'] = 'completed'
    finally:
        if load:
            load.stop()
            report['cpuLoadCleanup'] = load.records
        report['sourceUnchangedDuringMeasurements'] = all((ROOT/name).is_file() and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest for name,digest in fingerprint.items())
        if report['state'] != 'completed':
            report['state'] = 'interrupted'
        save()
    if not report['sourceUnchangedDuringMeasurements']:
        raise RuntimeError('Source changed during the measurement corpus')
    return 0 if all(record['passed'] for record in report['records']) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('STABILITY MEASUREMENT ERROR: '+str(error), file=sys.stderr)
        sys.exit(2)
