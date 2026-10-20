#!/usr/bin/env python3
"""Supplemental fixed phase markers in an isolated source copy, never shipped.
The main comparison always uses unmodified Release helper binaries as well.
"""
from pathlib import Path
import argparse, importlib.util, json, shutil, uuid, hashlib
p=argparse.ArgumentParser(description=__doc__)
for name in ('source','prefix','cmake','fixture','fixtures','output-root'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--unmodified-helper',type=Path)
p.add_argument('--repetitions',type=int,default=3);a=p.parse_args()
spec=importlib.util.spec_from_file_location('official',a.source/'scripts/test-local.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
r=m.Run(argparse.Namespace(output_root=str(a.output_root.resolve())),dict(group='14C2-native-phase-observation',cmake=str(a.cmake),ctest=str(a.cmake.with_name('ctest')),prefix=str(a.prefix)))
try:
    if not a.unmodified_helper:
        copy=r.root/'source';shutil.copytree(a.source,copy,ignore=shutil.ignore_patterns('.build','.git','__pycache__'))
        header='''#include <sys/resource.h>
    #include <time.h>
    #include <stdio.h>
    #include <libproc.h>
    #include <unistd.h>
    #include <stdlib.h>
    static void profile_mark(const char* phase, size_t bytes) {
     const char* fd=getenv("SIGNUM_PROFILE_PHASE_FD"); if (!fd) return; FILE* output=fdopen(dup(atoi(fd)),"a"); if (!output) return;
     struct rusage r{}; getrusage(RUSAGE_SELF,&r); struct timespec t{}; clock_gettime(CLOCK_MONOTONIC,&t);
     struct rusage_info_v4 io{}; proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t*)&io);
     fprintf(output,"{\\"phase\\":\\"%s\\",\\"bytes\\":%zu,\\"peakRSS\\":%ld,\\"cpu\\":%.9f,\\"wallAbsolute\\":%.9f,\\"diskRead\\":%llu,\\"diskWrite\\":%llu}\\n",phase,bytes,r.ru_maxrss,
     r.ru_utime.tv_sec+r.ru_stime.tv_sec+(r.ru_utime.tv_usec+r.ru_stime.tv_usec)/1e6,t.tv_sec+t.tv_nsec/1e9,io.ri_diskio_bytesread,io.ri_diskio_byteswritten); fclose(output);
    }
    '''
        native=copy/'Tools/PAdESPrototype';(native/'profile-mark.h').write_text(header)
        helper=native/'signum_pades_local.cpp';s=helper.read_text();s='#include "profile-mark.h"\n'+s
        changes=[('const auto source = signum::readSource(input.string());','profile_mark("read-source",source.size()); profile_mark("source-capacity",source.capacity());'),
                 ('signum::requireSupportedSource(source);','profile_mark("source-policy-parse",source.size());'),
                 ('charbuff pdfBytes(std::string(reinterpret_cast<const char*>(source.data()), source.size()));','profile_mark("podofo-buffer-copy",pdfBytes.size());'),
                 ('PdfMemDocument doc(io);','profile_mark("podofo-parse",pdfBytes.size());'),
                 ('PoDoFo::SignDocument(doc, *io, signer, field);','profile_mark("signed-incremental-appearance",pdfBytes.size());'),
                 ('transaction.write(signum::Bytes(pdfBytes.begin(), pdfBytes.end()));','profile_mark("writer-copy-finished",pdfBytes.size());'),
                 ('transaction.verifyAndPublish(source, der);','profile_mark("published",pdfBytes.size());')]
        for text,mark in changes:
            assert s.count(text)==1,text;s=s.replace(text,text+'\n        '+mark)
        helper.write_text(s)
        writer=native/'TransactionalOutput.cpp';s='#include "profile-mark.h"\n'+writer.read_text()
        s=s.replace('void TransactionalOutput::write(const Bytes& bytes) {','void TransactionalOutput::write(const Bytes& bytes) {\n    profile_mark("writer-copy-live",bytes.size());')
        s=s.replace('    verifyPDF(bytes, source, expectedCertificate);','    profile_mark("staged-readback",bytes.size());\n    verifyPDF(bytes, source, expectedCertificate);\n    profile_mark("staged-independent-verify",bytes.size());')
        writer.write_text(s)
        verifier=native/'PAdESVerification.cpp';s='#include "profile-mark.h"\n'+verifier.read_text()
        join='    signedBytes.insert(signedBytes.end(), pdf.begin() + end, pdf.begin() + revisionEnd);'
        s=s.replace(join,'    profile_mark("signature-prefix-capacity",signedBytes.capacity());\n'+join+'\n    profile_mark("signature-joined-capacity",signedBytes.capacity());')
        join='            signedBytes.insert(signedBytes.end(),pdf.begin()+r[2],pdf.begin()+r[2]+r[3]);'
        s=s.replace(join,'            profile_mark("inspection-prefix-capacity",signedBytes.capacity());\n'+join+'\n            profile_mark("inspection-joined-capacity",signedBytes.capacity());')
        verifier.write_text(s)
        m.ROOT=copy
        build=r.native('phase-release','Tools/PAdESPrototype','Release');engine=build/'signum-pades-local'
    else: engine=a.unmodified_helper.resolve()
    r.config.update(helper=str(engine),helperSHA256=hashlib.sha256(engine.read_bytes()).hexdigest(),instrumented=not bool(a.unmodified_helper))
    rows=[]
    for repetition in range(a.repetitions):
        for size in [1,16,50,100]:
            f=a.fixtures/(str(size)+'.pdf');out=r.root/(str(size)+'-'+str(repetition));out.mkdir(mode=0o700)
            args=[engine,f,out/'result.pdf',a.fixture/'synthetic-provider.dylib','7','01','--pin-stdin','--job-id',str(uuid.uuid4()),'--snapshot-id',str(uuid.uuid4()),'--expected-document-sha256',hashlib.sha256(f.read_bytes()).hexdigest(),'--expected-cert-sha256',hashlib.sha256((a.fixture/'certificate.der').read_bytes()).hexdigest(),'--verified-output-v4']
            # Only fixed synthetic input; no credential is supplied in argv/env.
            secret=out/'synthetic-input';secret.write_bytes(b'synthetic\n')
            # Pipe markers respect the verifier's RLIMIT_FSIZE=0. Only the
            # external adapter persists them after the helper has exited.
            adapter=out/'invoke.py';adapter.write_text('import subprocess,sys,os,json\n'
                'readfd,writefd=os.pipe(); env=dict(os.environ,SIGNUM_PROFILE_PHASE_FD=str(writefd))\n'
                'verify=sys.argv[3]=="verify"\n'
                'try:\n'
                ' with open(sys.argv[1],"rb") as data: result=subprocess.run(sys.argv[4:],stdin=data,stdout=subprocess.PIPE if verify else None,pass_fds=(writefd,),env=env,check=True)\n'
                'finally: os.close(writefd)\n'
                'with os.fdopen(readfd,"r") as pipe: text=pipe.read()\n'
                'with open(sys.argv[2],"w") as log: log.write(text)\n'
                'if verify:\n'
                ' b=result.stdout; n=int.from_bytes(b[:4],"big"); report=json.loads(b[8:8+n]); assert report["state"]=="signed" and report["signatures"] and all(x["integrity"]=="verified" for x in report["signatures"])\n')
            name='native-'+str(size)+'-'+str(repetition)
            r.command(name,['python3',adapter,secret,out/'phases.jsonl','sign','/usr/bin/time','-l','-o',out/'usage.txt']+args,120)
            secret.unlink()
            marks=[json.loads(x) for x in (out/'phases.jsonl').read_text().splitlines()]; assert len(marks)==(0 if a.unmodified_helper else 13)
            rows.append(dict(sizeMiB=size,repetition=repetition,markers=marks,out=str(out)))
            r.command('verify-'+name,['python3',adapter,out/'result.pdf',out/'verify-phases.jsonl','verify','/usr/bin/time','-l','-o',out/'verify-usage.txt',engine,'--verify-stdin-v1'],120)
    (r.root/'phases.json').write_text(json.dumps(rows,indent=2)+'\n');r.write_summary('passed')
except Exception:r.write_summary('failed');raise
