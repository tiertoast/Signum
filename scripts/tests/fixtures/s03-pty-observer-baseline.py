import os,sys,json,base64,time,select,termios,signal
config=json.load(sys.stdin);payload=base64.b64decode(config['input'])
pid,fd=os.forkpty()
if pid==0: os.execv(config['args'][0],config['args'])
initial=termios.tcgetattr(fd);output=b'';sent=False;protected=False;status=None
deadline=time.monotonic()+15
try:
    while time.monotonic()<deadline:
        ready,_,_=select.select([fd],[],[],0.02)
        if ready:
            try: chunk=os.read(fd,8192)
            except OSError: chunk=b''
            output+=chunk
            if not sent and b'Token PIN' in output and output.endswith(b': '):
                protected=not bool(termios.tcgetattr(fd)[3]&termios.ECHO)
                os.write(fd,payload+b'\n');sent=True
        done,value=os.waitpid(pid,os.WNOHANG)
        if done: status=value;break
    if status is None:
        os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
    restored=termios.tcgetattr(fd)==initial
    print(json.dumps({'sent':sent,'protected':protected,'restored':restored,'clean':len(payload)<8 or payload not in output,'failed':os.waitstatus_to_exitcode(status)!=0,'reason':next((line for line in output.decode('utf-8','replace').splitlines() if line.startswith('Signum error:')),'').replace(payload.decode('utf-8','replace') or 'unused','[redacted]'),'pinError':b'PIN' in output and (b'rifiut' in output or b'represent' in output or b'Invalid' in output)}))
finally: os.close(fd)
