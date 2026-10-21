#!/usr/bin/env python3
"""Adversarial restricted RSA-PSS SPKI: MGF1 SHA384 under a SHA256 XML URI.
Temporary private key removed; only the public certificate and XML are retained.
"""
from pathlib import Path
import os,tempfile,subprocess,base64,hashlib,json
from lxml import etree as E
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'Tests/SignumCertificateValidationTests/Fixtures/E1R'
openssl=Path(os.environ['SIGNUM_FIXTURE_OPENSSL']);xmlsec=openssl.parent/'xmlsec1'
ns={'d':'http://www.w3.org/2000/09/xmldsig#','x':'http://uri.etsi.org/01903/v1.3.2#'}
def run(*a):subprocess.run(list(map(str,a)),check=True)
with tempfile.TemporaryDirectory(prefix='signum-e1r-pss-key-') as d:
 t=Path(d)
 run(openssl,'genpkey','-algorithm','RSA-PSS','-pkeyopt','rsa_keygen_bits:2048','-pkeyopt','rsa_pss_keygen_md:sha256','-pkeyopt','rsa_pss_keygen_mgf1_md:sha384','-pkeyopt','rsa_pss_keygen_saltlen:32','-out',t/'key.pem')
 run(openssl,'req','-new','-x509','-key',t/'key.pem','-sha256','-config','/dev/null','-subj','/CN=E1R constrained PSS fixture','-days','3650','-out',t/'cert.pem')
 run(openssl,'x509','-in',t/'cert.pem','-outform','DER','-out',OUT/'constrained-pss.der')
 cert=(OUT/'constrained-pss.der').read_bytes();r=E.parse(str(OUT/'pss-256.xml')).getroot();sig=r.find('d:Signature',ns)
 sig.find('.//x:SigningCertificateV2/x:Cert/x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(cert).digest()).decode()
 sig.find('d:SignatureValue',ns).text=None
 for v in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns):v.text=None
 sig.find('d:KeyInfo',ns).clear();(t/'template.xml').write_bytes(E.tostring(r,xml_declaration=True,encoding='UTF-8'))
 run(xmlsec,'--sign','--lax-key-search','--insecure','--privkey-pem',str(t/'key.pem')+','+str(t/'cert.pem'),'--id-attr:Id','SignedProperties','--output',OUT/'pss-constrained-key.xml',t/'template.xml')
 p=OUT/'pss-constrained-key.xml';p.write_text(p.read_text().replace('<ds:KeyInfo/>','<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(cert).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'))
manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.iterdir()) if p.name!='manifest.json'};(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
