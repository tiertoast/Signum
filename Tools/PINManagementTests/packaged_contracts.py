#!/usr/bin/env python3
"""Darwin packaged-worker/barrier tests. Only locally compiled synthetic modules.
No hardware path, credential input, configuration change or mutating opcode is
sent to an installed provider. Run serially: Signum's barrier is user-global.
"""
import argparse, contextlib, hashlib, json, os, platform, selectors, subprocess, tempfile, uuid
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--bundle',type=Path,required=True)
args=parser.parse_args()
assert platform.system()=='Darwin'
source=Path(__file__).resolve().parents[2]
worker=args.bundle.resolve()/'Contents/Helpers/SignumPKCS11Worker'
pades=args.bundle.resolve()/'Contents/Helpers/signum-pades-local'
def run(argv,data=None):
    return subprocess.run([str(x) for x in argv],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
def checked(argv):
    r=run(argv)
    if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[:2000])
    return r.stdout
uid=lambda:str(uuid.uuid4()).upper()
with tempfile.TemporaryDirectory(prefix='signum-pin-packaged-') as directory:
    root=Path(directory).resolve()
    holder=root/'lease-holder'
    checked(['/usr/bin/cc','-std=c11','-pthread','-I'+str(source/'Sources/CProcessCoordination/include'),'-I'+str(source/'Sources/COutputPermissions/include'),source/'Tools/PINManagementTests/lease_holder.c',source/'Sources/CProcessCoordination/process_coordination.c',source/'Sources/COutputPermissions/output_permissions.c','-o',holder])
    modules=[]
    for name in ['A','B']:
        module=root/(name+'.dylib');audit=root/(name+'.audit')
        checked(['/usr/bin/cc','-dynamiclib','-pthread','-DSIGNUM_MOCK_PIN_ADMIN','-DSIGNUM_MOCK_REPORT_VERSION','-DSIGNUM_MOCK_AUDIT_PATH="'+str(audit)+'"','-I'+str(source/'Sources/CPKCS11'),source/'Tools/PKCS11Tests/mock_provider.c','-o',module])
        modules.append((module,audit))
    a,b=modules[0][0],modules[1][0]
    audit=modules[1][1]
    def calls():return audit.read_text().splitlines() if audit.exists() else []
    def ordinary(module):
        return dict(version=1,id=uid(),action='scan',provider=str(module),leaseWaitMilliseconds=0)
    def send(request,admin=False):
        return run([worker]+(['--pin-admin-v1'] if admin else []),json.dumps(request).encode())
    scan=json.loads(send(ordinary(b)).stdout)
    assert scan['succeeded'] and len(scan['tokens'])==1
    token=scan['tokens'][0]
    info=b.stat()
    identity=dict(device=info.st_dev,inode=info.st_ino,size=info.st_size,modifiedSeconds=info.st_mtime_ns//10**9,modifiedNanoseconds=info.st_mtime_ns%10**9,changedSeconds=info.st_ctime_ns//10**9,changedNanoseconds=info.st_ctime_ns%10**9)
    context=dict(version=1,provider=str(b),moduleIdentity=identity,automatic=False,token=token,discoveryID=uid(),profile=dict(id='unqualified-12A',changeEvidence='unknown',unblockEvidence='unknown'))
    def public():return dict(version=1,id=uid(),operation='readPublicStatus',context=context)
    before=len(calls());request=public();response=send(request,True)
    assert response.returncode==0
    observed=json.loads(response.stdout)
    assert observed['id']==request['id'] and observed['version']==1 and observed['snapshot']['moduleVersion']=='1.2'
    assert not (set(calls()[before:]) & {'5','8','9','10','15','16','17','18'})
    print('PASS packaged public read: zero sessions/login/sign/mutations',flush=True)
    for operation in ['changePIN','unblockPIN','reset','C_Login','C_SetPIN','C_InitPIN','C_InitToken']:
        request=public();request['operation']=operation;before=calls()
        result=send(request,True)
        assert result.returncode==2 and not result.stdout and calls()==before
    print('PASS seven forbidden opcodes rejected before loading a provider',flush=True)
    for field in ['pin','puk']:
        request=public();request[field]='SYNTHETIC-REJECTED';before=calls()
        assert send(request,True).returncode==2 and calls()==before
    print('PASS credential fields rejected before vendor load',flush=True)
    @contextlib.contextmanager
    def held(mode,module):
        process=subprocess.Popen([holder,mode,module],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(process.stdout,selectors.EVENT_READ)
                assert sel.select(5),'lease holder did not become ready'
                assert process.stdout.readline()==b'READY\n'
            yield
        finally:
            if process.poll() is None:
                process.communicate(b'Q',timeout=5)
            assert process.returncode==0
    with held('ordinary',a):
        before=calls();reply=json.loads(send(public(),True).stdout)
        assert reply['failure']=='busy' and 'snapshot' not in reply and calls()==before
        # Ordinary operations on another provider still share the barrier.
        assert json.loads(send(ordinary(b)).stdout)['succeeded']
    print('PASS ordinary cross-provider lease blocks admin but permits ordinary helper',flush=True)
    # Minimal real PDF source; the helper must reject before middleware loading.
    pdf=root/'source.pdf';data=b'%PDF-1.7\n';offsets=[0]
    stream=b'BT /F1 12 Tf 72 700 Td (Synthetic barrier test) Tj ET\n'
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'endstream',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for i,obj in enumerate(objects,1):offsets.append(len(data));data+=str(i).encode()+b' 0 obj\n'+obj+b'\nendobj\n'
    start=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'+b''.join(f'{n:010d} 00000 n \n'.encode() for n in offsets[1:])+b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(start).encode()+b'\n%%EOF\n';pdf.write_bytes(data)
    with held('admin',a):
        before=calls();reply=json.loads(send(ordinary(b)).stdout)
        assert not reply['succeeded'] and calls()==before
        reply=json.loads(send(public(),True).stdout)
        assert reply['failure']=='busy' and calls()==before
        output=root/'not-published.pdf'
        result=run([pades,pdf,output,b,'7','01','--pin-stdin','--job-id',uid(),'--snapshot-id',uid(),'--expected-document-sha256',hashlib.sha256(data).hexdigest(),'--expected-cert-sha256','0'*64,'--verified-output-v4'],b'')
        reply=json.loads(result.stdout)
        assert reply['outcome']=='rejectedBeforeAuthentication' and reply.get('reason')=='busy' and not output.exists() and calls()==before,reply
    print('PASS administrative barrier blocks ordinary worker, admin worker and packaged PAdES before loading/authentication',flush=True)
    assert json.loads(send(public(),True).stdout)['snapshot']['version']==1
    print('PASS leases released after helper teardown; public read available again',flush=True)
    print('6 packaged contract groups passed (including 7 forbidden opcodes); synthetic providers only',flush=True)
