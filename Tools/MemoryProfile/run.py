#!/usr/bin/env python3
"""Fixed 14-C.2 experiment. Uses official Run watchdog; no shipped code instrumentation.
Build Core/worker Release with -Xswiftc -enable-testing in a new scratch first.
Every measured command is a fresh process; physical disk counters are cache dependent.
"""
from pathlib import Path
import argparse, importlib.util, json, hashlib, os, re, base64
p=argparse.ArgumentParser(description=__doc__)
for name in ('source','build','helper','fixture','output-root'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--label',required=True);p.add_argument('--fixtures',type=Path,required=True)
p.add_argument('--repetitions',type=int,default=3);p.add_argument('--sizes',default='1,16,50,100')
p.add_argument('--budget-only',action='store_true')
a=p.parse_args();source=a.source.resolve();here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('official',source/'scripts/test-local.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
r=m.Run(argparse.Namespace(output_root=str(a.output_root.resolve())),dict(group='fixed-14C2-memory-profile',label=a.label,source=str(source),configuration='Release',repetitions=a.repetitions))
products=a.build/'swift/out/Products/Release';maps=a.build/'swift/out/Intermediates.noindex/GeneratedModuleMaps'
try:
    r.command('metrics-build',['xcrun','clang','-O2','-target','arm64-apple-macos13.0','-c',here/'metrics.c','-o',r.root/'metrics.o'])
    cmd=['xcrun','swiftc','-O','-target','arm64-apple-macos13.0','-parse-as-library','-I',products]
    for name in ['CPKCS11','CCertificatePolicy','COutputPermissions','CProcessCoordination','CSecurePIN']:
        cmd+=['-Xcc','-fmodule-map-file='+str(maps/(name+'.modulemap'))]
    cmd += [here/'Probe.swift',source/'Sources/SignumApp/SignumPAdESHelper.swift',source/'Sources/SignumApp/PDFPreviewPreparation.swift',source/'Sources/SignumApp/PAdESPlacementPane.swift',source/'Sources/SignumApp/PAdESRenderCoordinator.swift',source/'Sources/SignumApp/SignaturePlacementOverlay.swift',r.root/'metrics.o']
    cmd += [products/(name+'.o') for name in ['SignumCore','CPKCS11','CCertificatePolicy','COutputPermissions','CProcessCoordination','CSecurePIN']]
    cmd += ['-framework','Security','-framework','CoreFoundation','-o',r.root/'probe']
    r.command('probe-build',cmd,120)
    fixture=a.fixtures.resolve();fixture.mkdir(mode=0o700,parents=True,exist_ok=True)
    sizes=[int(x) for x in a.sizes.split(',')]
    manifest={}
    for size in sizes:
        f=fixture/(str(size)+'.pdf')
        if not f.exists():
            # Inert unreferenced stream padding keeps parse complexity fixed, exact size.
            body=b'q 0.8 G 20 30 100 40 re S Q\n'
            def pdf(padding):
                objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>',b'<< /Length '+str(len(body)).encode()+b' >>\nstream\n'+body+b'endstream',b'<< /Length '+str(padding).encode()+b' >>\nstream\n'+b'x'*padding+b'\nendstream']
                data=b'%PDF-1.7\n';offsets=[]
                for i,o in enumerate(objects,1):offsets.append(len(data));data+=str(i).encode()+b' 0 obj\n'+o+b'\nendobj\n'
                x=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'+b''.join(('%010d 00000 n \n'%v).encode() for v in offsets)
                return data+b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(x).encode()+b'\n%%EOF\n'
            padding=size*1024*1024-1024
            for _ in range(4):padding+=size*1024*1024-len(pdf(padding))
            data=pdf(padding);assert len(data)==size*1024*1024;
            with f.open('xb') as stream:stream.write(data)
            second=bytearray(data);second[second.index(b'xxxxxxxx')]=ord('y');
            with Path(str(f)+'.second').open('xb') as stream:stream.write(second)
        manifest[str(size)]={'input':str(f),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}
    (r.root/'fixtures.json').write_text(json.dumps(manifest,indent=2)+'\n')
    cases=[]
    def measure(name,mode,input):
        out=r.root/name;out.mkdir(mode=0o700)
        cmd=['/usr/bin/time','-l','-o',out/'usage.txt',r.root/'probe',mode,input,out,a.fixture,a.helper,products/'SignumPKCS11Worker']
        r.command(name,cmd,120)
        checkpoints=[]
        for line in (r.logs/(name+'.log')).read_text().splitlines():
            if line.startswith('{') and '"phase"' in line:checkpoints.append(json.loads(line))
        cases.append(dict(name=name,mode=mode,input=str(input),out=str(out),checkpoints=checkpoints))
        (r.root/'measurements.json').write_text(json.dumps(cases,indent=2)+'\n')
        return out
    for repetition in range(a.repetitions if not a.budget_only else 0):
        for size in sizes:
            f=fixture/(str(size)+'.pdf');base=str(size)+'-'+str(repetition)
            cms=measure('cms-'+base,'cms',f)/'result.p7m'
            # Independently check exact extracted bytes, outside measured generation.
            extracted=r.root/('extracted-'+base)
            r.command('openssl-'+base,['/usr/bin/time','-l','-o',r.root/('openssl-usage-'+base+'.txt'),'/usr/bin/openssl','cms','-verify','-inform','DER','-binary','-noverify','-in',cms,'-out',extracted],120)
            assert hashlib.sha256(extracted.read_bytes()).hexdigest()==manifest[str(size)]['sha256'];extracted.unlink()
            os.link(f,Path(str(cms)+'.source'))
            for mode in ['acquisition','metadata','attached','cades-job','pades','pades-visible','verify','live-preview']:
                input=cms if mode in ['metadata','attached'] else f
                out=measure(mode+'-'+base,mode,input)
                if mode=='cades-job':
                    adapter=out/'worker-invoke.py'
                    adapter.write_text('import subprocess,sys\nwith open(sys.argv[1],"rb") as data,open(sys.argv[2],"wb") as output: subprocess.run(sys.argv[3:],stdin=data,stdout=output,check=True)\n')
                    r.command('standalone-worker-'+base,['python3',adapter,out/'worker-request.json',out/'worker-response.json','/usr/bin/time','-l','-o',out/'worker-usage.txt',products/'SignumPKCS11Worker'],30)
                    (out/'worker-request.json').unlink()
                    response=json.loads((out/'worker-response.json').read_text());assert response['succeeded'] and response['version']==2
                    (out/'signature').write_bytes(base64.b64decode(response['signature']))
                    pub=r.command('public-key-'+base,['/usr/bin/openssl','x509','-inform','DER','-in',a.fixture/'certificate.der','-pubkey','-noout'])
                    (out/'public.pem').write_text(pub[pub.index('-----BEGIN PUBLIC KEY-----'):])
                    r.command('independent-worker-rsa-'+base,['/usr/bin/openssl','dgst','-sha256','-verify',out/'public.pem','-signature',out/'signature',out/'attributes'])
                if mode=='pades-visible':
                    report=a.helper
                    # Independent unified verifier exercises the actual signed revision.
                    measure('verify-signed-'+base,'verify',out/'result.pdf')
                    if size<100:
                        incremental=measure('pades-incremental-'+base,'pades-incremental',out/'result.pdf')
                        measure('verify-incremental-'+base,'verify',incremental/'result.pdf')
            measure('verify-cms-'+base,'verify',cms)
            if size<=50:measure('batch-'+base,'batch',f) # two documents must fit 128 MiB.
    if a.budget_only:
        budget=fixture/'batch-budget';budget.mkdir(mode=0o700,exist_ok=True)
        for i in range(32):
            path=budget/(str(i)+'.bin')
            if not path.exists():
                with path.open('xb') as stream:stream.write(i.to_bytes(4,'big')+b'\xa5'*(4*1024*1024-4))
        for repetition in range(a.repetitions):measure('batch-budget-'+str(repetition),'batch-budget',budget)
    r.write_summary('passed')
except Exception:r.write_summary('failed');raise
