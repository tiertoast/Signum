#!/usr/bin/env python3
"""Synthetic offline X.509/TL corpus. Ephemeral keys are deleted; never production credentials.
Requires openssl and xmlsec1 build tools. Regeneration changes random keys/serials.
"""
import pathlib, tempfile, subprocess, hashlib, json, base64, os, xml.etree.ElementTree as ET
os.environ["OPENSSL_CONF"]="/etc/ssl/openssl.cnf"
ROOT=pathlib.Path(__file__).resolve().parents[2];OUT=ROOT/'Tests/SignumCertificateValidationTests/Fixtures';OUT.mkdir(exist_ok=True)
T='http://uri.etsi.org/02231/v2#';D='http://www.w3.org/2000/09/xmldsig#';X='http://uri.etsi.org/01903/v1.3.2#'
ns={'t':T,'d':D,'x':X}
ET.register_namespace('',T);ET.register_namespace('ds',D);ET.register_namespace('xades',X)
def run(*args):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
with tempfile.TemporaryDirectory(prefix='signum-path-fixtures-') as tmp:
 tmp=pathlib.Path(tmp)
 def file(n):return str(tmp/n)
 def key(n):
  if not (tmp/(n+'.key')).exists():run('openssl','genrsa','-out',file(n+'.key'),'2048')
 def csr(n,k=None):
  k=k or n;key(k);run('openssl','req','-new','-key',file(k+'.key'),'-subj','/CN=SIGNUM SYNTHETIC '+('intermediate' if n=='wrong-intermediate' else n),'-out',file(n+'.csr'))
 def der(n):run('openssl','x509','-in',file(n+'.pem'),'-outform','DER','-out',str(OUT/(n+'.der')))
 for n in ['root-a','root-b','tl-signer']:
  key(n);(tmp/(n+'.cnf')).write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:3\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
  run('openssl','req','-new','-x509','-key',file(n+'.key'),'-subj','/CN=SIGNUM SYNTHETIC '+n,'-days','3650','-config',file(n+'.cnf'),'-out',file(n+'.pem'));der(n)
 def issue(n,issuer,extensions,k=None,start='20200101000000Z',end='20350101000000Z',md='sha256'):
  csr(n,k)
  db=tmp/(n+'.db');db.write_text('');serial=tmp/(n+'.serial');serial.write_text('01\n')
  cfg=tmp/(n+'.cnf');cfg.write_text(f'[ca]\ndefault_ca=CA\n[CA]\ndatabase={db}\nserial={serial}\nnew_certs_dir={tmp}\ncertificate={file(issuer+".pem")}\nprivate_key={file(issuer+".key")}\ndefault_md={md}\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'+extensions+'\n')
  run('openssl','ca','-batch','-notext','-config',str(cfg),'-startdate',start,'-enddate',end,'-in',file(n+'.csr'),'-out',file(n+'.pem'));der(n)
 ca='basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign'
 leaf='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation'
 issue('intermediate','root-a',ca)
 issue('leaf','intermediate',leaf)
 # Same intermediate subject/public key, signed by an alternative authorized root.
 run('openssl','x509','-req','-in',file('intermediate.csr'),'-CA',file('root-b.pem'),'-CAkey',file('root-b.key'),'-set_serial','42','-days','3000','-extfile',file('intermediate.cnf'),'-extensions','ext','-out',file('cross.pem'));der('cross')
 issue('wrong-intermediate','root-a',ca)
 for n,ext,start,end,md in [
  ('expired',leaf,'20200101000000Z','20250101000000Z','sha256'),
  ('future',leaf,'20270101000000Z','20350101000000Z','sha256'),
  ('critical',leaf+'\n1.2.3.4.5=critical,DER:05:00','20200101000000Z','20350101000000Z','sha256'),
  ('bad-ku','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment','20200101000000Z','20350101000000Z','sha256'),
  ('bad-eku',leaf+'\nextendedKeyUsage=serverAuth','20200101000000Z','20350101000000Z','sha256'),
  ('sha1',leaf,'20200101000000Z','20350101000000Z','sha1')]: issue(n,'intermediate',ext,start=start,end=end,md=md)
 issue('not-ca','root-a','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyCertSign')
 issue('bad-basic','not-ca',leaf)
 issue('path-zero','root-a','basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign')
 issue('subca','path-zero',ca);issue('bad-pathlen','subca',leaf)
 issue('name-ca','root-a',ca+'\nnameConstraints=critical,permitted;DNS:.allowed.example')
 issue('bad-name','name-ca',leaf+'\nsubjectAltName=DNS:forbidden.example')
 tampered=bytearray((OUT/'intermediate.der').read_bytes());tampered[-1]^=1;(OUT/'altered-intermediate.der').write_bytes(tampered)
 (tmp/'data').write_text('Signum synthetic certificate path validation fixture.\n')
 (tmp/'chain.pem').write_bytes((tmp/'intermediate.pem').read_bytes()+(tmp/'root-a.pem').read_bytes())
 run('openssl','cms','-sign','-binary','-nodetach','-md','sha256','-in',file('data'),'-signer',file('leaf.pem'),'-inkey',file('leaf.key'),'-certfile',file('chain.pem'),'-outform','DER','-out',str(OUT/'valid-untrusted.cms'))
 # Authenticated national TL fixtures with independent XML signer and actual CA identities.
 for fixture in ['trusted','withdrawn','history']:
  r=ET.parse(ROOT/'Tests/SignumTrustAuthenticationTests/Fixtures/it.xml').getroot();si=r.find('t:SchemeInformation',ns)
  si.find('t:ListIssueDateTime',ns).text='2026-10-20T10:00:00Z';si.find('t:NextUpdate/t:dateTime',ns).text='2027-04-01T00:00:00Z'
  providers=r.find('t:TrustServiceProviderList',ns);provider=list(providers)[0];providers.clear();providers.append(provider)
  provider.find('t:TSPInformation/t:TSPName/t:Name',ns).text='SIGNUM SYNTHETIC PROVIDER'
  services=provider.find('t:TSPServices',ns);service=list(services)[0];services.clear();services.append(service)
  for child in list(service):
   if child.tag!=f'{{{T}}}ServiceInformation':service.remove(child)
  info=service.find('t:ServiceInformation',ns)
  info.find('t:ServiceTypeIdentifier',ns).text='http://uri.etsi.org/TrstSvc/Svctype/CA/QC'
  info.find('t:ServiceName/t:Name',ns).text='SIGNUM SYNTHETIC CA SERVICE'
  info.find('t:ServiceStatus',ns).text='http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/'+('granted' if fixture=='trusted' else 'withdrawn')
  info.find('t:StatusStartingTime',ns).text='2020-01-01T00:00:00Z' if fixture=='trusted' else ('2026-10-20T00:00:00Z' if fixture=='withdrawn' else '2026-10-19T00:00:00Z')
  identity=info.find('t:ServiceDigitalIdentity',ns);identity.clear()
  di=ET.SubElement(identity,f'{{{T}}}DigitalId');ET.SubElement(di,f'{{{T}}}X509Certificate').text=base64.b64encode((OUT/('root-b.der' if fixture=='history' else 'root-a.der')).read_bytes()).decode()
  if fixture!='trusted':
   h=ET.SubElement(ET.SubElement(service,f'{{{T}}}ServiceHistory'),f'{{{T}}}ServiceHistoryInstance')
   ET.SubElement(h,f'{{{T}}}ServiceTypeIdentifier').text='http://uri.etsi.org/TrstSvc/Svctype/CA/QC'
   name=ET.SubElement(h,f'{{{T}}}ServiceName');ET.SubElement(name,f'{{{T}}}Name',{'{http://www.w3.org/XML/1998/namespace}lang':'en'}).text='SIGNUM SYNTHETIC HISTORICAL CA'
   di=ET.SubElement(ET.SubElement(h,f'{{{T}}}ServiceDigitalIdentity'),f'{{{T}}}DigitalId')
   ET.SubElement(di,f'{{{T}}}X509Certificate').text=base64.b64encode((OUT/'root-a.der').read_bytes()).decode()
   ET.SubElement(h,f'{{{T}}}ServiceStatus').text='http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted'
   ET.SubElement(h,f'{{{T}}}StatusStartingTime').text='2020-01-01T00:00:00Z'
  sig=r.find('d:Signature',ns);sig.find('d:SignatureValue',ns).text=None
  for digest in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):digest.text=None
  cert=(OUT/'tl-signer.der').read_bytes();sc=sig.find('.//x:SigningCertificateV2/x:Cert',ns)
  sc.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(cert).digest()).decode()
  serial=sc.find('x:IssuerSerialV2',ns)
  if serial is not None:sc.remove(serial)
  sig.find('d:KeyInfo',ns).clear()
  template=tmp/'template.xml';ET.ElementTree(r).write(template,encoding='utf-8',xml_declaration=True)
  output=OUT/(fixture+'.xml')
  run('xmlsec1','--sign','--lax-key-search','--insecure','--privkey-pem',file('tl-signer.key')+','+file('tl-signer.pem'),'--id-attr:Id','SignedProperties','--output',str(output),str(template))
  output.write_text(output.read_text().replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(cert).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'))
(OUT/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.iterdir()) if p.suffix in ['.der','.xml','.cms']},indent=2)+'\n')
print('Synthetic corpus generated; ephemeral private keys deleted.')
