#!/usr/bin/env python3
"""Minimal E2 TL/pointer variants only. Reuse E1R signed documents/evidence unchanged."""
from pathlib import Path
import os,copy,base64,hashlib,json,datetime,tempfile,subprocess
from lxml import etree as E
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
R=Path(__file__).resolve().parents[2];old=R/'Tests/SignumCertificateValidationTests/Fixtures';out=old/'E2';out.mkdir(exist_ok=True)
T='http://uri.etsi.org/02231/v2#';D='http://www.w3.org/2000/09/xmldsig#';X='http://uri.etsi.org/01903/v1.3.2#';S='http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';ns={'t':T,'d':D,'x':X}
at=datetime.datetime.fromisoformat(json.loads((old/'E1R/clock.json').read_text())['evaluatedAt'].replace('Z','+00:00'))
def time(delta):return (at+datetime.timedelta(seconds=delta)).isoformat().replace('+00:00','Z')
keys=[rsa.generate_private_key(public_exponent=65537,key_size=2048) for _ in range(2)];certs=[]
for i,key in enumerate(keys):
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'E2 synthetic TL signer '+str(i))]);cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(600+i).not_valid_before(at-datetime.timedelta(days=30)).not_valid_after(at+datetime.timedelta(days=365)).sign(key,hashes.SHA256());certs.append(cert);(out/('signer'+str(i)+'.der')).write_bytes(cert.public_bytes(serialization.Encoding.DER))
with tempfile.TemporaryDirectory(prefix='signum-e2-') as d:
 p=Path(d)
 def sign(name,root,signer=0):
  root=copy.deepcopy(root);der=certs[signer].public_bytes(serialization.Encoding.DER)
  (p/'key.pem').write_bytes(keys[signer].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(p/'cert.pem').write_bytes(certs[signer].public_bytes(serialization.Encoding.PEM))
  sig=root.find('d:Signature',ns);sig.find('d:SignatureValue',ns).text=None
  for v in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):v.text=None
  binding=sig.find('.//x:SigningCertificateV2/x:Cert',ns)
  for child in list(binding):
   if E.QName(child).localname=='IssuerSerialV2':binding.remove(child)
  binding.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(der).digest()).decode();sig.find('d:KeyInfo',ns).clear()
  (p/'template.xml').write_bytes(E.tostring(root,xml_declaration=True,encoding='UTF-8'))
  subprocess.run([os.environ['SIGNUM_FIXTURE_XMLSEC'],'--sign','--lax-key-search','--insecure','--privkey-pem',str(p/'key.pem')+','+str(p/'cert.pem'),'--id-attr:Id','SignedProperties','--output',str(out/(name+'.xml')),str(p/'template.xml')],check=True,capture_output=True)
  xml=out/(name+'.xml');xml.write_text(xml.read_text().replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(der).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'))
 base=E.parse(str(old/'E1R/authorized.xml')).getroot()
 for country in ['IT','AT','DE','BE','FR','ES','BG']:
  national=copy.deepcopy(base);national.find('t:SchemeInformation/t:SchemeTerritory',ns).text=country
  sign(country,national)
 newer=copy.deepcopy(base);newer.find('t:SchemeInformation/t:SchemeTerritory',ns).text='AT';seq=newer.find('t:SchemeInformation/t:TSLSequenceNumber',ns);seq.text=str(int(seq.text)+1);sign('AT-rotated',newer,1);seq.text=str(int(seq.text)-1);sign('AT-rotated-old',newer,1)
 eu=E.parse(str(old/'E1R/e1r-lotl.xml')).getroot();pointers=eu.find('t:SchemeInformation/t:PointersToOtherTSL',ns);template=copy.deepcopy(pointers.findall('t:OtherTSLPointer',ns)[-1]);pointers.clear()
 def pointer(country,signer=0):
  node=copy.deepcopy(template);node.find('t:TSLLocation',ns).text='https://ec.europa.eu/tools/lotl/eu-lotl.xml' if country=='EU' else ('https://eidas.agid.gov.it/TL/TSL-IT.xml' if country=='IT' else 'https://tl.example.test/'+country+'.xml')
  node.find('.//t:SchemeTerritory',ns).text=country
  for c in node.findall('.//t:X509Certificate',ns):c.text=base64.b64encode(certs[signer].public_bytes(serialization.Encoding.DER)).decode()
  return node
 for country in ['EU','IT','AT','DE','BE','FR','ES','BG']:pointers.append(pointer(country))
 eu.find('t:SchemeInformation/t:TSLSequenceNumber',ns).text='500';sign('europe',eu)
 eu2=copy.deepcopy(eu);eu2.find('t:SchemeInformation/t:TSLSequenceNumber',ns).text='501';ps=eu2.find('t:SchemeInformation/t:PointersToOtherTSL',ns)
 for node in list(ps):
  if node.findtext('.//t:SchemeTerritory',namespaces=ns)=='AT':ps.replace(node,pointer('AT',1))
 sign('europe-rotated-national',eu2)
 for variant,qualifier in [('transition-equivalent','QCQSCDStatusAsInCert'),('transition-negative','QCNoQSCD')]:
  root=E.parse(str(old/'E1S/historical-ski.xml')).getroot();service=root.findall('.//t:TSPService',ns)[0];history=service.find('t:ServiceHistory',ns);first=history[0];earliest=copy.deepcopy(first);history.append(earliest);first.find('t:StatusStartingTime',ns).text=time(-180)
  for info,q in [(first,qualifier),(earliest,'QCWithQSCD')]:
   ex=info.find('t:ServiceInformationExtensions',ns)
   if ex is None:ex=E.SubElement(info,'{'+T+'}ServiceInformationExtensions')
   rule=E.SubElement(E.SubElement(E.SubElement(ex,'{'+T+'}Extension',Critical='true'),'{'+S+'}Qualifications'),'{'+S+'}QualificationElement')
   E.SubElement(E.SubElement(rule,'{'+S+'}Qualifiers'),'{'+S+'}Qualifier',uri='http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/'+q)
   E.SubElement(E.SubElement(E.SubElement(rule,'{'+S+'}CriteriaList',{'assert':'all'}),'{'+S+'}KeyUsage'),'{'+S+'}KeyUsageBit',name='nonRepudiation').text='true'
  sign(variant,root)
(out/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.name!='manifest.json'},indent=2)+'\n')
