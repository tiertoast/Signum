#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile,json,base64,hashlib,uuid,shutil,os,time,statistics
import argparse
parser=argparse.ArgumentParser(description="Synthetic checks against one freshly packaged Signum bundle. Never launches GUI or installed middleware.")
parser.add_argument('--bundle',type=Path,required=True)
parser.add_argument('--output-root',type=Path,default=Path(tempfile.gettempdir())/'SignumPackagedTests')
args=parser.parse_args()
source=Path(__file__).resolve().parents[1]
args.output_root.mkdir(parents=True,exist_ok=True)
root=Path(tempfile.mkdtemp(prefix='synthetic-packaged-',dir=args.output_root)).resolve()
app=args.bundle.resolve()
assert app.is_dir() and (app/'Contents/Helpers/SignumPKCS11Worker').is_file()
def run(args, data=None, okay=True):
    result=subprocess.run([str(v) for v in args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if okay and result.returncode:raise RuntimeError('Synthetic fixture command failed: '+str(args[0])+' code '+str(result.returncode)+((': '+result.stderr.decode(errors='replace')[:1000]) if str(args[1])=='dgst' else ''))
    return result
b64=lambda b:base64.b64encode(b).decode()
hashbytes=lambda b:hashlib.sha256(b).hexdigest()
uid=lambda:str(uuid.uuid4()).upper()
def identity(path):
    s=path.stat()
    return dict(device=s.st_dev,inode=s.st_ino,size=s.st_size,modifiedSeconds=s.st_mtime_ns//10**9,modifiedNanoseconds=s.st_mtime_ns%10**9,changedSeconds=s.st_ctime_ns//10**9,changedNanoseconds=s.st_ctime_ns%10**9)
def wire(c):
    m=c['moduleIdentity'];t=c['token'];h=lambda value:value.encode().hex()
    return ':'.join(['1',h(c['provider'])]+[str(m[k]) for k in ['device','inode','size','modifiedSeconds','modifiedNanoseconds','changedSeconds','changedNanoseconds']]+['0',str(t['slot'])]+[h(t[k]) for k in ['label','manufacturer','model','reader','serial']]+[base64.b64decode(c['objectID']).hex(),c['certificateSHA256'],c['routeID'],c['discoveryID']])
def count(op):
    return (root/'operations').read_text().splitlines().count(str(op)) if (root/'operations').exists() else 0
try:
    (root/'certificate.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=signer\n[dn]\n[signer]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n')
    run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'certificate.pem','-days','2','-subj','/CN=Signum Synthetic Packaging','-config',root/'certificate.cnf'])
    run(['/usr/bin/openssl','x509','-in',root/'certificate.pem','-outform','DER','-out',root/'certificate.der'])
    run(['/usr/bin/openssl','rsa','-in',root/'key.pem','-outform','DER','-out',root/'key.der'])
    (root/'public.pem').write_bytes(run(['/usr/bin/openssl','x509','-in',root/'certificate.pem','-pubkey','-noout']).stdout)
    der=(root/'certificate.der').read_bytes();key=(root/'key.der').read_bytes()
    (root/'bootstrap.h').write_text('#define SIGNUM_MOCK_BOOTSTRAP_CERTIFICATE 1\n#define SIGNUM_MOCK_SOFTWARE_KEY 1\nstatic const unsigned char bootstrap_certificate[]={'+','.join(map(str,der))+'};\nstatic const unsigned char bootstrap_private_key[]={'+','.join(map(str,key))+'};\n')
    module=root/'mock.dylib'
    run(['/usr/bin/cc','-dynamiclib','-pthread','-I',source/'Sources/CPKCS11','-include',root/'bootstrap.h','-DSIGNUM_MOCK_AUDIT_PATH="'+str(root/'operations')+'"',source/'Tools/PKCS11Tests/mock_provider.c','-framework','Security','-framework','CoreFoundation','-o',module])
    data=b'%PDF-1.7\n'; offsets=[0]
    stream=b'BT /F1 12 Tf 72 700 Td (Signum synthetic fixture) Tj ET\n'
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'endstream',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for i,obj in enumerate(objects,1):offsets.append(len(data));data+=str(i).encode()+b' 0 obj\n'+obj+b'\nendobj\n'
    xref=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'+b''.join(f'{n:010d} 00000 n \n'.encode() for n in offsets[1:])+b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n'
    pdf=root/'source.pdf';pdf.write_bytes(data)
    for configuration in [app.name]:
        helpers=app/'Contents/Helpers'
        worker=helpers/'SignumPKCS11Worker';helper=helpers/'signum-pades-local'
        scan=dict(version=1,id=uid(),action='scan',provider=str(module),leaseWaitMilliseconds=1000)
        observed=json.loads(run([worker],json.dumps(scan).encode()).stdout)
        assert observed['succeeded'] and len(observed['tokens'])==1
        token=observed['tokens'][0]
        context=dict(version=1,provider=str(module),moduleIdentity=identity(module),automatic=False,token=token,objectID=b64(b'\x53'),certificateSHA256=hashbytes(der),routeID=hashbytes(b'packaging-observed-route'),discoveryID=uid())
        attributes=b'Synthetic approved signing attributes'
        request=dict(version=2,id=uid(),action='rsaSHA256',provider=str(module),leaseWaitMilliseconds=1000,slot=7,certificate=dict(label='Synthetic',identifier=b64(b'\x53'),der=b64(der)),attributes=b64(attributes),pin='synthetic-fixture',expectedModule=context['moduleIdentity'],automaticModule=False,providerContext=context)
        response=json.loads(run([worker],json.dumps(request).encode()).stdout)
        assert response['version']==2 and response['succeeded'] and response['validatedContext']==context
        (root/'attributes').write_bytes(attributes);(root/'signature').write_bytes(base64.b64decode(response['signature']))
        run(['/usr/bin/openssl','dgst','-sha256','-verify',root/'public.pem','-signature',root/'signature',root/'attributes'])
        print('PASS',configuration,'packaged CAdES worker v2 binding and independent RSA verification',flush=True)
        bad=json.loads(json.dumps(request));bad['providerContext']['token']['model']='changed'
        before=count(8);reply=json.loads(run([worker],json.dumps(bad).encode()).stdout)
        assert not reply['succeeded'] and reply['failureKind']=='contextChanged' and count(8)==before
        print('PASS',configuration,'packaged worker rejects token mismatch before authentication',flush=True)
        missing=json.loads(json.dumps(request));missing.pop('providerContext');before=count(8)
        assert run([worker],json.dumps(missing).encode(),okay=False).returncode!=0 and count(8)==before
        print('PASS',configuration,'packaged worker refuses incomplete v2 without downgrade',flush=True)
        def arguments(output,ctx):
            return [pdf,output,module,'7','53','--pin-stdin','--expected-output-directory-v1',str(root.stat().st_dev)+':'+str(root.stat().st_ino),'--provider-context-v1',wire(ctx),'--job-id',uid(),'--snapshot-id',uid(),'--expected-document-sha256',hashbytes(data),'--expected-cert-sha256',hashbytes(der),'--verified-output-v5']
        output=root/(configuration+'-signed.pdf');args=arguments(output,context)
        reply=json.loads(run([helper]+args,b'synthetic-fixture\n').stdout)
        assert reply['version']==5 and reply['outcome']=='published' and output.read_bytes().startswith(data) and pdf.read_bytes()==data
        verified=run([helper,'--verify-stdin-v1'],output.read_bytes()).stdout
        length=int.from_bytes(verified[:4],'big');report=json.loads(verified[8:8+length])
        assert report['state']=='signed' and report['signatures'] and all(v['integrity']=='verified' for v in report['signatures'])
        print('PASS',configuration,'packaged PAdES v5 publication and unified cryptographic verification; original unchanged',flush=True)
        existing=output.read_bytes();before=count(8)
        reply=json.loads(run([helper]+args,b'synthetic-fixture\n',okay=False).stdout)
        assert reply['outcome']=='rejectedBeforeAuthentication' and output.read_bytes()==existing and count(8)==before
        print('PASS',configuration,'packaged PAdES no-overwrite before authentication',flush=True)
        other=root/(configuration+'-rejected.pdf');badctx=json.loads(json.dumps(context));badctx['token']['serial']='changed';before=count(8)
        reply=json.loads(run([helper]+arguments(other,badctx),b'synthetic-fixture\n',okay=False).stdout)
        assert reply['version']==5 and reply['outcome']=='rejectedBeforeAuthentication' and not other.exists() and count(8)==before
        print('PASS',configuration,'packaged PAdES rejects changed token before authentication and publication',flush=True)
        # The same packaged helper validates exact snapshot bytes without loading a provider.
        before=count(8)
        preflight=json.loads(run([helper,'--source-preflight-stdin-v1'],data).stdout)
        assert preflight['status']=='accepted' and preflight['sha256']==hashbytes(data)
        previous=json.loads(run([helper,'--source-preflight-stdin-v1'],output.read_bytes()).stdout)
        assert previous['status']=='accepted' and previous['sha256']==hashbytes(output.read_bytes()) and count(8)==before
        print('PASS',configuration,'packaged read-only preflight accepts ordinary and supported signed snapshot',flush=True)
        wrong=root/(configuration+'-wrong-directory.pdf');wrong_args=arguments(wrong,context)
        index=wrong_args.index('--expected-output-directory-v1');wrong_args[index+1]=str(root.stat().st_dev)+':'+str(root.stat().st_ino+1)
        before=count(8);reply=json.loads(run([helper]+wrong_args,b'synthetic-fixture\n',okay=False).stdout)
        assert reply['outcome']=='rejectedBeforeAuthentication' and count(8)==before and not wrong.exists()
        print('PASS',configuration,'packaged writer rejects wrong approved directory before authentication',flush=True)
        # Compile an isolated copy of the existing mock with its certificate
        # disappearing on USER login. No production or original fixture changes.
        altered=root/'post-login.c'
        altered.write_text((source/'Tools/PKCS11Tests/mock_provider.c').read_text().replace('static int after_user_action, certificate_absent;', 'static int after_user_action=2, certificate_absent;'))
        post_module=root/'post-login.dylib';post_audit=root/'post-operations'
        run(['/usr/bin/cc','-dynamiclib','-pthread','-I',source/'Sources/CPKCS11','-I',source/'Tools/PKCS11Tests','-include',root/'bootstrap.h','-DSIGNUM_MOCK_AUDIT_PATH="'+str(post_audit)+'"',altered,'-framework','Security','-framework','CoreFoundation','-o',post_module])
        post_context=json.loads(json.dumps(context));post_context['provider']=str(post_module);post_context['moduleIdentity']=identity(post_module)
        post_request=json.loads(json.dumps(request));post_request['provider']=str(post_module);post_request['expectedModule']=identity(post_module);post_request['providerContext']=post_context
        reply=json.loads(run([worker],json.dumps(post_request).encode()).stdout)
        operations=post_audit.read_text().splitlines()
        assert not reply['succeeded'] and operations.count('8')==1 and '15' not in operations and '16' not in operations
        print('PASS',configuration,'packaged worker checks certificate after login before SignInit',flush=True)
        post_output=root/(configuration+'-post-login.pdf');post_args=arguments(post_output,post_context);post_args[2]=post_module
        reply=json.loads(run([helper]+post_args,b'synthetic-fixture\n',okay=False).stdout)
        operations=post_audit.read_text().splitlines()
        assert reply['outcome']!='published' and not post_output.exists() and operations.count('8')==2 and '15' not in operations and '16' not in operations
        print('PASS',configuration,'packaged PAdES checks certificate after login before SignInit',flush=True)
        # Measure only the new read-only source check. These tiny synthetic
        # samples are diagnostic, not a claim about large or real documents.
        samples=[];before=count(8)
        for _ in range(5):
            start=time.perf_counter()
            result=json.loads(run([helper,'--source-preflight-stdin-v1'],data).stdout)
            samples.append((time.perf_counter()-start)*1000)
            assert result['status']=='accepted' and result['sha256']==hashbytes(data)
        assert count(8)==before
        print('SOURCE_PREFLIGHT_MEDIAN_MS',json.dumps(dict(configuration=configuration,bytes=len(data),samples=5,median=statistics.median(samples))),flush=True)

    print('10 packaged contract checks passed; synthetic fixture/provider only',flush=True)
finally:
    shutil.rmtree(root)
