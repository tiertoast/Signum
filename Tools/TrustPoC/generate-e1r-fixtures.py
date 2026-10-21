#!/usr/bin/env python3
"""E1R corpus: reuse C/D generators and disposable keys; no production anchors.
Development-only lxml/cryptography already provided by the local diagnostic runtime.
"""
from pathlib import Path
import os,runpy,tempfile,base64,hashlib,json,copy,subprocess
from lxml import etree as E
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,ec
from cryptography import x509
from cryptography.x509.oid import NameOID
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'Tests/SignumCertificateValidationTests/Fixtures/E1R';OUT.mkdir(exist_ok=True)
os.environ['SIGNUM_QUALIFICATION_FIXTURES']='1';os.environ['SIGNUM_BINDING_FIXTURE_OUTPUT']=str(OUT)
g=runpy.run_path(str(ROOT/'Tools/TrustPoC/generate-evidence-binding-fixtures.py'))
key,cert=g['keys']['issuer'],g['certs']['issuer'];prefix=Path(os.environ['SIGNUM_FIXTURE_OPENSSL']).parents[1]
T='http://uri.etsi.org/02231/v2#';D='http://www.w3.org/2000/09/xmldsig#';S='http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';X='http://uri.etsi.org/01903/v1.3.2#'
ns={'t':T,'d':D,'s':S,'x':X}
base=E.parse(str(OUT/'authorized.xml')).getroot()
def extension(parent,kind='qualifier'):
 ex=E.SubElement(parent,'{'+T+'}Extension',Critical='true')
 if kind=='global':E.SubElement(ex,'{urn:signum:e1r:test}Unsupported')
 else:
  q=E.SubElement(E.SubElement(ex,'{'+S+'}Qualifications'),'{'+S+'}QualificationElement')
  E.SubElement(E.SubElement(q,'{'+S+'}Qualifiers'),'{'+S+'}Qualifier',uri='urn:signum:unsupported')
  c=E.SubElement(q,'{'+S+'}CriteriaList',assert_='all');c.attrib.clear();c.set('assert','all')
  E.SubElement(E.SubElement(c,'{'+S+'}KeyUsage'),'{'+S+'}KeyUsageBit',name='digitalSignature').text='true'
 return ex
with tempfile.TemporaryDirectory(prefix='signum-e1r-') as temporary:
 tmp=Path(temporary);(tmp/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(tmp/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 def sign(name,root,algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',identity=cert):
  root=copy.deepcopy(root);sig=root.find('d:Signature',ns);sig.find('d:SignedInfo/d:SignatureMethod',ns).set('Algorithm',algorithm)
  sig.find('d:SignatureValue',ns).text=None
  for v in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):v.text=None
  digest=sig.find('.//x:SigningCertificateV2/x:Cert/x:CertDigest/d:DigestValue',ns);digest.text=base64.b64encode(hashlib.sha512(identity.public_bytes(serialization.Encoding.DER)).digest()).decode()
  binding=sig.find('.//x:SigningCertificateV2/x:Cert',ns)
  for node in list(binding):
   if node.tag.endswith('IssuerSerialV2'):binding.remove(node)
  sig.find('d:KeyInfo',ns).clear();(tmp/'template.xml').write_bytes(E.tostring(root,xml_declaration=True,encoding='UTF-8'))
  subprocess.run([str(prefix/'bin/xmlsec1'),'--sign','--lax-key-search','--insecure','--privkey-pem',str(tmp/'key.pem')+','+str(tmp/'cert.pem'),'--id-attr:Id','SignedProperties','--output',str(OUT/(name+'.xml')),str(tmp/'template.xml')],check=True,capture_output=True)
  p=OUT/(name+'.xml');s=p.read_text();s=s.replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(identity.public_bytes(serialization.Encoding.DER)).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>');p.write_text(s)
 for bits in [256,384,512]:sign('pss-'+str(bits),base,'http://www.w3.org/2007/05/xmldsig-more#sha'+str(bits)+'-rsa-MGF1')
 ec_key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'E1R incompatible EC key')])
 ec_cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ec_key.public_key()).serial_number(99).not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc).sign(ec_key,hashes.SHA256())
 (OUT/'wrong-key.der').write_bytes(ec_cert.public_bytes(serialization.Encoding.DER))
 sign('pss-wrong-key',base,'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1',identity=ec_cert)
 for name,indices,global_scope in [('excluded-ca',[0],False),('excluded-tsa',[2],False),('global-critical',[],True)]:
  root=copy.deepcopy(base)
  if global_scope:
   tsp=root.find('t:TrustServiceProviderList/t:TrustServiceProvider/t:TSPInformation',ns);extension(E.SubElement(tsp,'{'+T+'}TSPInformationExtensions'),'global')
  else:
   services=root.findall('t:TrustServiceProviderList/t:TrustServiceProvider/t:TSPServices/t:TSPService',ns)
   for i in indices:
    info=services[i].find('t:ServiceInformation',ns);ex=info.find('t:ServiceInformationExtensions',ns)
    if ex is None:ex=E.SubElement(info,'{'+T+'}ServiceInformationExtensions')
    extension(ex)
  sign(name,root)
 root=E.parse(str(ROOT/'Tests/SignumTrustAuthenticationTests/Fixtures/eu-lotl.xml')).getroot()
 pointers=root.find('t:SchemeInformation/t:PointersToOtherTSL',ns)
 for pointer in list(pointers):
  country=pointer.find('.//t:SchemeTerritory',ns)
  if country is None or country.text not in ['EU','IT']:pointers.remove(pointer);continue
  for value in pointer.findall('.//t:X509Certificate',ns):value.text=base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
 sign('e1r-lotl',root)
 # Invalid encodings signed over otherwise correct SignedInfo: wrong salt, MGF and trailer.
 valid=E.parse(str(OUT/'pss-256.xml')).getroot();si=valid.find('d:Signature/d:SignedInfo',ns);canonical=E.tostring(si,method='c14n',exclusive=True)
 for name,salt,mgf in [('pss-wrong-salt',20,hashes.SHA256()),('pss-wrong-mgf',32,hashes.SHA384())]:
  root=copy.deepcopy(valid);root.find('d:Signature/d:SignatureValue',ns).text=base64.b64encode(key.sign(canonical,padding.PSS(mgf=padding.MGF1(mgf),salt_length=salt),hashes.SHA256())).decode();(OUT/(name+'.xml')).write_bytes(E.tostring(root,xml_declaration=True,encoding='UTF-8'))
 root=copy.deepcopy(valid);v=root.find('d:Signature/d:SignatureValue',ns);signature=int.from_bytes(base64.b64decode(v.text),'big');numbers=key.private_numbers();n=numbers.public_numbers.n;size=(n.bit_length()+7)//8
 em=bytearray(pow(signature,numbers.public_numbers.e,n).to_bytes(size,'big'));em[-1]=0xbd
 v.text=base64.b64encode(pow(int.from_bytes(em,'big'),numbers.d,n).to_bytes(size,'big')).decode();(OUT/'pss-wrong-trailer.xml').write_bytes(E.tostring(root,xml_declaration=True,encoding='UTF-8'))
manifest={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(OUT.iterdir()) if f.name!='manifest.json'};(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('E1R public fixture corpus complete; disposable private keys removed.')
