"""Offline repro instrument; current observer must accept a correctly restoring child."""
import argparse,base64,hashlib,json,re,subprocess,sys,tempfile,textwrap
from pathlib import Path
W=Path(__file__).resolve().parents[1]
S=W.parent

def extract(source):
    return textwrap.dedent(re.search(r'try Data\(#"""\n(.*?)\n\s*"""#\.utf8\)',source,re.S)[1])

def gated(body):
    body=body.replace('pid,fd=os.forkpty()', 'gate_read,gate_write=os.pipe()\npid,fd=os.forkpty()')
    body=body.replace("if pid==0: os.execv(config['args'][0],config['args'])", "if pid==0:\n    os.close(gate_write)\n    if os.read(gate_read,1)!=b'1': os._exit(125)\n    os.close(gate_read)\n    os.execv(config['args'][0],config['args'])\nos.close(gate_read)")
    return body.replace('initial=termios.tcgetattr(fd);', "initial=termios.tcgetattr(fd);os.write(gate_write,b'1');os.close(gate_write);")

def observe(body,root):
    ready=root/'ready';receipt=root/'child-receipt.json';child=root/'correct-child.py';runner=root/'observer.py'
    child.write_text('''import sys,os,termios,json
from pathlib import Path
original=termios.tcgetattr(0);changed=termios.tcgetattr(0);changed[3]&=~termios.ECHO
try:
 termios.tcsetattr(0,termios.TCSANOW,changed)
 Path(sys.argv[1]).write_text('protected')
 print('Token PIN: ',end='',flush=True)
 sys.stdin.buffer.readline()
finally:
 termios.tcsetattr(0,termios.TCSANOW,original)
 Path(sys.argv[2]).write_text(json.dumps(dict(initial=original[3],final=termios.tcgetattr(0)[3])))
''')
    # Fault injection models the parent being scheduled after child setup.
    # With a real launch gate the child cannot set ready yet: the bounded
    # preemption window expires, then the parent snapshots and releases it.
    injected="""probe_deadline=time.monotonic()+2
while not os.path.exists(%r) and time.monotonic()<probe_deadline:
    select.select([],[],[],0.001)
probe_child_ran_before_snapshot=os.path.exists(%r)
""" % (str(ready),str(ready))
    body=body.replace('initial=termios.tcgetattr(fd)',injected+'initial=termios.tcgetattr(fd)')
    body=body.replace("'sent':sent", "'probeChildBeforeSnapshot':probe_child_ran_before_snapshot,'initialLflag':initial[3],'finalLflag':termios.tcgetattr(fd)[3],'sent':sent")
    ready.unlink(missing_ok=True);receipt.unlink(missing_ok=True);runner.write_text(body)
    config=dict(args=[sys.executable,str(child),str(ready),str(receipt)],input=base64.b64encode(b'SYNTHETIC-control-only').decode())
    result=subprocess.run([sys.executable,str(runner)],input=json.dumps(config),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    if result.returncode:raise RuntimeError(result.stderr)
    observed=json.loads(result.stdout);own=json.loads(receipt.read_text())
    if own['initial']!=own['final'] or not all(observed[key] for key in ['sent','protected','clean']):
        raise RuntimeError('Invalid known-good terminal control: '+str((observed,own)))
    return dict(observer=observed,child=own)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--scratch-root',type=Path,required=True)
    parser.add_argument('--source',type=Path,default=W/'Tests/SignumCoreTests/S03PINFidelityTests.swift')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();source=args.source.read_text();body=extract(source)
    with tempfile.TemporaryDirectory(prefix='pty-observer-repro-',dir=args.scratch_root.resolve()) as directory:
        root=Path(directory)
        if args.self_test:
            # Frozen legacy observer keeps calibration independent of a later correction.
            legacy=(W/'scripts/tests/fixtures/s03-pty-observer-baseline.py').read_text()
            bad=observe(legacy,root);good=observe(gated(legacy),root)
            assert bad['observer']['probeChildBeforeSnapshot'] and not bad['observer']['restored']
            assert good['observer']['restored'] and not good['observer']['probeChildBeforeSnapshot']
            proof=dict(controlsPassed=True,knownWrong=bad,knownCorrect=good)
        else:
            current=observe(body,root);proof=dict(current=current,passed=current['observer']['restored'])
        proof['sourceSHA256']=hashlib.sha256(source.encode()).hexdigest()
        if args.output:args.output.write_text(json.dumps(proof,indent=2))
        print(json.dumps(proof,indent=2))
        raise SystemExit(0 if args.self_test or proof['passed'] else 1)
