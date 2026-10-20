#!/usr/bin/env python3
"""Reuses the C corpus generator; creates synthetic multifirma CMS/PDF and TL.
Requires development OpenSSL/xmlsec and cryptography 50.0.2, no retained keys.
"""
from pathlib import Path
from datetime import timedelta
import os,runpy,tempfile,subprocess,hashlib,json,base64,copy,xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'Tests/SignumCertificateValidationTests/Fixtures/Binding';OUT.mkdir(exist_ok=True)
os.environ['SIGNUM_FIXTURE_OUTPUT']=str(OUT)
g=runpy.run_path(str(ROOT/'Tools/TrustPoC/generate-revocation-fixtures.py'))
keys,certs,now,der=g['keys'],g['certs'],g['NOW'],serialization.Encoding.DER
keys['leaf-two']=rsa.generate_private_key(public_exponent=65537,key_size=2048);g['cert']('leaf-two',20,issuer='other')
for name,issuer in [('leaf','issuer'),('leaf-two','other'),('tsa','issuer')]:
 old=certs[name];b=x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.issuer).serial_number(old.serial_number).public_key(keys[name].public_key()).not_valid_before(old.not_valid_before_utc).not_valid_after(old.not_valid_after_utc)
 for ext in old.extensions:b=b.add_extension(ext.value,ext.critical)
 b=b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier('http://ocsp.signum-fixture.example/status'))]),False)
 b=b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier('https://crl.signum-fixture.example/list.crl')],relative_name=None,reasons=None,crl_issuer=None)]),False)
 certs[name]=b.sign(keys[issuer],hashes.SHA256());(OUT/(name+'.der')).write_bytes(certs[name].public_bytes(der))
def response(name,certificate,issuer,status=ocsp.OCSPCertStatus.GOOD):
 b=ocsp.OCSPResponseBuilder().add_response(cert=certs[certificate],issuer=certs[issuer],algorithm=hashes.SHA256(),cert_status=status,this_update=now-timedelta(hours=1),next_update=now+timedelta(days=1),revocation_time=now-timedelta(days=2) if status==ocsp.OCSPCertStatus.REVOKED else None,revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH,certs[issuer])
 (OUT/(name+'.ocsp')).write_bytes(b.sign(keys[issuer],hashes.SHA256()).public_bytes(der))
response('leaf-good','leaf','issuer');response('leaf-two-revoked','leaf-two','other',ocsp.OCSPCertStatus.REVOKED);response('tsa-good','tsa','issuer')
# Full CRL for second issuer, with its own leaf revoked.
b=x509.CertificateRevocationListBuilder().issuer_name(certs['other'].subject).last_update(now-timedelta(hours=1)).next_update(now+timedelta(days=1)).add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(20).revocation_date(now-timedelta(days=2)).build())
(OUT/'other-revoked.crl').write_bytes(b.sign(keys['other'],hashes.SHA256()).public_bytes(der))
openssl=os.environ['SIGNUM_FIXTURE_OPENSSL'];prefix=Path(openssl).parents[1]
def run(*args):
 p=subprocess.run(list(map(str,args)),capture_output=True)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
with tempfile.TemporaryDirectory(prefix='signum-binding-fixtures-') as directory:
 tmp=Path(directory)
 for n in ['issuer','other','leaf','leaf-two','tsa']:
  (tmp/(n+'.key')).write_bytes(keys[n].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  (tmp/(n+'.pem')).write_bytes(certs[n].public_bytes(serialization.Encoding.PEM))
 (tmp/'chain.pem').write_bytes(certs['issuer'].public_bytes(serialization.Encoding.PEM)+certs['other'].public_bytes(serialization.Encoding.PEM))
 run('/usr/bin/clang++','-std=c++17','-I'+str(prefix/'include'),ROOT/'Tools/TrustPoC/bind-evidence-fixture.cpp','-L'+str(prefix/'lib'),'-lcrypto','-o',tmp/'compose')
 (tmp/'serial').write_text('01\n')
 (tmp/'tsa.cnf').write_text(f'''[tsa]
default_tsa=authority
[authority]
serial={tmp/'serial'}
signer_cert={tmp/'tsa.pem'}
certs={tmp/'issuer.pem'}
signer_key={tmp/'tsa.key'}
signer_digest=sha256
default_policy=1.2.3.4.5
digests=sha256
accuracy=secs:1
ordering=no
tsa_name=yes
ess_cert_id_chain=no
ess_cert_id_alg=sha256
''')
 fingerprints={n:hashlib.sha256(c.public_bytes(der)).hexdigest() for n,c in certs.items()}
 def signed(payload,path,names,detached=False):
  (tmp/'data').write_bytes(payload)
  args=[openssl,'cms','-sign','-binary','-md','sha256','-in',tmp/'data','-certfile',tmp/'chain.pem','-outform','DER','-out',path]
  if not detached:args+=['-nodetach']
  for n in names:args+=['-signer',tmp/(n+'.pem'),'-inkey',tmp/(n+'.key')]
  run(*args)
 def attach(path,name,ocspname,output,wrong=False):
  run(tmp/'compose','extract',path,tmp)
  value=tmp/(fingerprints[name]+'.bin')
  if wrong:value=OUT/'signature.bin'
  run(openssl,'ts','-query','-data',value,'-sha256','-cert','-out',tmp/'request.tsq')
  run(openssl,'ts','-reply','-config',tmp/'tsa.cnf','-queryfile',tmp/'request.tsq','-token_out','-out',tmp/'token.tst')
  run(tmp/'compose','attach',path,output,fingerprints[name],tmp/'token.tst',OUT/(ocspname+'.ocsp'),OUT/'tsa-good.ocsp',OUT/('good.crl' if name=='leaf' else 'other-revoked.crl'))
 signed(b'SIGNUM MULTISIGNER EVIDENCE FIXTURE\n',tmp/'multi.cms',['leaf','leaf-two'])
 attach(tmp/'multi.cms','leaf','leaf-good',tmp/'first.cms');attach(tmp/'first.cms','leaf-two','leaf-two-revoked',OUT/'multi.cms')
 attach(tmp/'multi.cms','leaf','leaf-good',OUT/'wrong-imprint.cms',wrong=True)
 # Detached PDF signatures composed around fixed-size ByteRange/Contents slots.
 def basepdf():
  objects={1:b'<< /Type /Catalog /Pages 2 0 R >>',2:b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',3:b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] /Resources << >> >>'}
  data=b'%PDF-1.7\n';offsets={}
  for n,v in objects.items():offsets[n]=len(data);data+=f'{n} 0 obj\n'.encode()+v+b'\nendobj\n'
  xref=len(data);data+=b'xref\n0 4\n0000000000 65535 f \n'+b''.join(f'{offsets[n]:010d} 00000 n \n'.encode() for n in range(1,4));data+=f'trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode();return data,xref
 def append(data,prev,objects,size):
  offsets={}
  for n,v in objects.items():offsets[n]=len(data);data+=f'\n{n} 0 obj\n'.encode()+v+b'\nendobj\n'
  xref=len(data);data+=b'xref\n'
  for n,o in offsets.items():data+=f'{n} 1\n{o:010d} 00000 n \n'.encode()
  data+=f'trailer\n<< /Size {size} /Root 1 0 R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n'.encode();return data,xref
 pdf,xref=basepdf();contents=[]
 for i,name in enumerate(['leaf','leaf-two']):
  form,field,sig=(5,6,7) if i==0 else (8,9,10)
  placeholder=b'0000000000 0000000000 0000000000 0000000000';zero=b'0'*(32768*2)
  objects={1:f'<< /Type /Catalog /Pages 2 0 R /AcroForm {form} 0 R >>'.encode(),form:(f'<< /Fields [6 0 R'+(' 9 0 R' if i else '')+'] /SigFlags 3 >>').encode(),field:f'<< /FT /Sig /T (sig{i+1}) /V {sig} 0 R >>'.encode(),sig:b'<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ['+placeholder+b'] /Contents <'+zero+b'> >>'}
  pdf,xref=append(pdf,xref,objects,11)
  marker=pdf.rfind(b'/Contents <');start=marker+len(b'/Contents ');end=start+len(zero)+2
  offset=pdf.rfind(placeholder);ranges=f'{0:010d} {start:010d} {end:010d} {len(pdf)-end:010d}'.encode();pdf=pdf[:offset]+ranges+pdf[offset+len(placeholder):]
  signed(pdf[:start]+pdf[end:],tmp/'detached.cms',[name],True)
  attach(tmp/'detached.cms',name,'leaf-good' if i==0 else 'leaf-two-revoked',tmp/'bound.cms')
  cms=(tmp/'bound.cms').read_bytes();assert len(cms)<32768;padded=cms+b'\x00'*(32768-len(cms));contents.append(hashlib.sha1(padded).hexdigest().upper());pdf=pdf[:start+1]+padded.hex().encode()+pdf[end-1:]
 # A later DSS revision, VRI explicitly selects each prior signature. Unknown VRI
 # and global DSS are preserved as unassociated, never assigned to all signers.
 def stream(raw):return f'<< /Length {len(raw)} >>\nstream\n'.encode()+raw+b'\nendstream'
 objects={1:b'<< /Type /Catalog /Pages 2 0 R /AcroForm 8 0 R /DSS 20 0 R >>',20:b'<< /OCSPs [23 0 R 24 0 R 27 0 R] /VRI 21 0 R >>',21:f'<< /{contents[0]} 22 0 R /{contents[1]} 26 0 R /{"0"*40} 28 0 R >>'.encode(),22:b'<< /OCSP [23 0 R 24 0 R] >>',26:b'<< /OCSP [27 0 R 24 0 R] >>',28:b'<< /OCSP [23 0 R] >>',23:stream((OUT/'leaf-good.ocsp').read_bytes()),24:stream((OUT/'tsa-good.ocsp').read_bytes()),27:stream((OUT/'leaf-two-revoked.ocsp').read_bytes())}
 pdf,xref=append(pdf,xref,objects,29);(OUT/'multi.pdf').write_bytes(pdf)
 # Independently authenticated TL with two CA/QC identities and one TSA identity.
 T='http://uri.etsi.org/02231/v2#';D='http://www.w3.org/2000/09/xmldsig#';X='http://uri.etsi.org/01903/v1.3.2#';ns={'t':T,'d':D,'x':X}
 ET.register_namespace('',T);ET.register_namespace('ds',D);ET.register_namespace('xades',X)
 for filename,tsa_authorized in [('authorized',True),('no-tsa',False)]:
  root=ET.parse(ROOT/'Tests/SignumCertificateValidationTests/Fixtures/trusted.xml').getroot();info=root.find('t:SchemeInformation',ns)
  info.find('t:ListIssueDateTime',ns).text=(now-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ');info.find('t:NextUpdate/t:dateTime',ns).text=(now+timedelta(days=180)).strftime('%Y-%m-%dT%H:%M:%SZ')
  provider=root.find('t:TrustServiceProviderList/t:TrustServiceProvider',ns);services=provider.find('t:TSPServices',ns);template=copy.deepcopy(list(services)[0]);services.clear()
  for n,typ in [('issuer','CA/QC'),('other','CA/QC')]+([('tsa','TSA/QTST')] if tsa_authorized else []):
   service=copy.deepcopy(template);si=service.find('t:ServiceInformation',ns);si.find('t:ServiceName/t:Name',ns).text='SYNTHETIC '+n;si.find('t:ServiceTypeIdentifier',ns).text='http://uri.etsi.org/TrstSvc/Svctype/'+typ
   si.find('t:StatusStartingTime',ns).text=(now-timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ');identity=si.find('t:ServiceDigitalIdentity',ns);identity.clear();di=ET.SubElement(identity,'{'+T+'}DigitalId');ET.SubElement(di,'{'+T+'}X509Certificate').text=base64.b64encode(certs[n].public_bytes(der)).decode();services.append(service)
  sig=root.find('d:Signature',ns);sig.find('d:SignatureValue',ns).text=None
  for digest in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):digest.text=None
  signer=certs['issuer'].public_bytes(der);sc=sig.find('.//x:SigningCertificateV2/x:Cert',ns);sc.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(signer).digest()).decode()
  sig.find('d:KeyInfo',ns).clear();ET.ElementTree(root).write(tmp/'template.xml',encoding='utf-8',xml_declaration=True)
  run(prefix/'bin/xmlsec1','--sign','--lax-key-search','--insecure','--privkey-pem',str(tmp/'issuer.key')+','+str(tmp/'issuer.pem'),'--id-attr:Id','SignedProperties','--output',OUT/(filename+'.xml'),tmp/'template.xml')
  path=OUT/(filename+'.xml');path.write_text(path.read_text().replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(signer).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'))
(OUT/'clock.json').write_text(json.dumps({'evaluatedAt':(now+timedelta(minutes=2)).isoformat()},indent=2)+'\n')
(OUT/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.iterdir()) if p.name!='manifest.json'},indent=2)+'\n')
print('Multisigner evidence corpus generated. Temporary private keys removed.')
