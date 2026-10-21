#!/usr/bin/env python3
"""Only new historical TL variants; reuse all E1R certs, CMS/PDF and evidence."""
from pathlib import Path
import os,tempfile,base64,hashlib,json,copy,subprocess,datetime
from lxml import etree as E
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
R=Path(__file__).resolve().parents[2];old=R/'Tests/SignumCertificateValidationTests/Fixtures/E1R';out=old.parent/'E1S';out.mkdir(exist_ok=True)
T='http://uri.etsi.org/02231/v2#';D='http://www.w3.org/2000/09/xmldsig#';X='http://uri.etsi.org/01903/v1.3.2#';S='http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';ns={'t':T,'d':D,'x':X}
at=datetime.datetime.fromisoformat(json.loads((old/'clock.json').read_text())['evaluatedAt'].replace('Z','+00:00'))
key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'E1S TL fixture signer')])
cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(501).not_valid_before(at-datetime.timedelta(days=30)).not_valid_after(at+datetime.timedelta(days=365)).sign(key,hashes.SHA256())
der=cert.public_bytes(serialization.Encoding.DER);(out/'tl-signer.der').write_bytes(der)
base=E.parse(str(old/'authorized.xml')).getroot()
with tempfile.TemporaryDirectory(prefix='signum-e1s-') as d:
 p=Path(d);(p/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(p/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 for variant in ['historical-ski','historical-negative','historical-ambiguous','historical-order']:
  root=copy.deepcopy(base)
  root.find('t:SchemeInformation/t:ListIssueDateTime',ns).text=(at-datetime.timedelta(seconds=30)).isoformat().replace('+00:00','Z')
  for index,service in enumerate(root.findall('.//t:TSPService',ns)):
   current=service.find('t:ServiceInformation',ns);h=E.SubElement(service,'{'+T+'}ServiceHistory');event=E.SubElement(h,'{'+T+'}ServiceHistoryInstance')
   for child in current:
    if E.QName(child).localname in ['ServiceTypeIdentifier','ServiceName','ServiceDigitalIdentity','ServiceStatus','StatusStartingTime','ServiceInformationExtensions']:event.append(copy.deepcopy(child))
   identity=event.find('t:ServiceDigitalIdentity',ns);certificate=x509.load_der_x509_certificate(base64.b64decode(identity.find('t:DigitalId/t:X509Certificate',ns).text));identity.clear()
   E.SubElement(E.SubElement(identity,'{'+T+'}DigitalId'),'{'+T+'}X509SubjectName').text=certificate.subject.rfc4514_string()
   ski=certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
   if variant=='historical-ambiguous' and index==0:ski=b'\x00'*20
   E.SubElement(E.SubElement(identity,'{'+T+'}DigitalId'),'{'+T+'}X509SKI').text=base64.b64encode(ski).decode()
   current.find('t:StatusStartingTime',ns).text=(at-datetime.timedelta(seconds=60)).isoformat().replace('+00:00','Z')
   if variant=='historical-negative' and index==0:
    ex=event.find('t:ServiceInformationExtensions',ns)
    if ex is None:ex=E.SubElement(event,'{'+T+'}ServiceInformationExtensions')
    rule=E.SubElement(E.SubElement(E.SubElement(ex,'{'+T+'}Extension',Critical='true'),'{'+S+'}Qualifications'),'{'+S+'}QualificationElement')
    E.SubElement(E.SubElement(rule,'{'+S+'}Qualifiers'),'{'+S+'}Qualifier',uri='http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD')
    E.SubElement(E.SubElement(E.SubElement(rule,'{'+S+'}CriteriaList',{'assert':'all'}),'{'+S+'}KeyUsage'),'{'+S+'}KeyUsageBit',name='nonRepudiation').text='true'
   if variant=='historical-order' and index==0:h.append(copy.deepcopy(event))
  sig=root.find('d:Signature',ns);sig.find('d:SignatureValue',ns).text=None
  for v in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):v.text=None
  binding=sig.find('.//x:SigningCertificateV2/x:Cert',ns)
  for child in list(binding):
   if E.QName(child).localname=='IssuerSerialV2':binding.remove(child)
  binding.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(der).digest()).decode()
  sig.find('d:KeyInfo',ns).clear();(p/'template.xml').write_bytes(E.tostring(root,xml_declaration=True,encoding='UTF-8'))
  subprocess.run([os.environ['SIGNUM_FIXTURE_XMLSEC'],'--sign','--lax-key-search','--insecure','--privkey-pem',str(p/'key.pem')+','+str(p/'cert.pem'),'--id-attr:Id','SignedProperties','--output',str(out/(variant+'.xml')),str(p/'template.xml')],check=True,capture_output=True)
  xml=out/(variant+'.xml');xml.write_text(xml.read_text().replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(der).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'))
(out/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.name!='manifest.json'},indent=2)+'\n')
