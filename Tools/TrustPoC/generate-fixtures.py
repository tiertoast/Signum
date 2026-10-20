#!/usr/bin/env python3
"""Regenerate SYNTHETIC fixtures with throwaway keys, never production keys.
Committed XML/DER is the offline test corpus. Regeneration changes random keys.
Requires Python 3, openssl and xmlsec1; run from the repository root.
"""
import base64, hashlib, json, pathlib, subprocess, tempfile
import xml.etree.ElementTree as ET
ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'Tests/SignumTrustAuthenticationTests/Fixtures'
T='http://uri.etsi.org/02231/v2#'; D='http://www.w3.org/2000/09/xmldsig#'; X='http://uri.etsi.org/01903/v1.3.2#'
ns={'t':T,'d':D,'x':X}
ET.register_namespace('',T); ET.register_namespace('ds',D); ET.register_namespace('xades',X)
def run(*args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode: raise RuntimeError(result.stderr.decode()+result.stdout.decode())
with tempfile.TemporaryDirectory(prefix='signum-test-') as temp:
    temp=pathlib.Path(temp); certs={}
    for key in ['a','b']:
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj',f'/CN=SIGNUM SYNTHETIC TEST {key} ONLY','-days','3650','-keyout',str(temp/f'{key}.key'),'-out',str(temp/f'{key}.pem'))
        run('openssl','x509','-in',str(temp/f'{key}.pem'),'-outform','DER','-out',str(OUT/f'test-{key}.der'))
        certs[key]=(OUT/f'test-{key}.der').read_bytes()
    for name,key,seq,uris in [
        ('synthetic-a','a',400,[]),
        ('synthetic-pivot','a',401,[]),
        ('synthetic-wrong-cert-binding','a',400,[]),
        ('synthetic-wrong-format','a',400,[]),
        ('synthetic-b','b',402,['https://ec.europa.eu/tools/lotl/eu-lotl-pivot-401.xml'])]:
        r=ET.parse(OUT/'eu-lotl.xml').getroot(); si=r.find('t:SchemeInformation',ns)
        si.find('t:TSLSequenceNumber',ns).text=str(seq)
        si.find('t:ListIssueDateTime',ns).text=f'2026-10-{seq-390:02}T10:00:00Z'
        si.find('t:NextUpdate/t:dateTime',ns).text='2027-04-01T10:00:00Z'
        uri=si.find('t:SchemeInformationURI',ns);uri.clear()
        for u in uris+['https://eur-lex.europa.eu/eli/C/2026/1944/oj']:
            e=ET.SubElement(uri,f'{{{T}}}URI',{'{http://www.w3.org/XML/1998/namespace}lang':'en'});e.text=u
        pointers=si.find('t:PointersToOtherTSL',ns)
        eu=next(p for p in pointers if any(n.text=='EU' for n in p.iter(f'{{{T}}}SchemeTerritory')))
        pointers.clear(); pointers.append(eu)
        identities=eu.find('t:ServiceDigitalIdentities',ns);identities.clear()
        identity=ET.SubElement(identities,f'{{{T}}}ServiceDigitalIdentity');di=ET.SubElement(identity,f'{{{T}}}DigitalId')
        ET.SubElement(di,f'{{{T}}}X509Certificate').text=base64.b64encode(certs['b']).decode()
        if name=='synthetic-pivot': si.find('t:NextUpdate/t:dateTime',ns).text='2026-10-11T11:00:00Z'
        sig=r.find('d:Signature',ns)
        sig.find('d:SignatureValue',ns).text=None
        for dv in sig.findall('d:SignedInfo/d:Reference/d:DigestValue',ns): dv.text=None
        sig.find('d:KeyInfo/d:X509Data/d:X509Certificate',ns).text=base64.b64encode(certs[key]).decode()
        sc=sig.find('.//x:SigningCertificateV2/x:Cert',ns)
        sc.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(hashlib.sha512(certs[key]).digest()).decode()
        if name=='synthetic-wrong-cert-binding':
            sc.find('x:CertDigest/d:DigestValue',ns).text=base64.b64encode(bytes(64)).decode()
        if name=='synthetic-wrong-format':
            sig.find('.//x:DataObjectFormat',ns).set('ObjectReference','#nonexistent')
        issuer=sc.find('x:IssuerSerialV2',ns)
        if issuer is not None:sc.remove(issuer)
        ki=sig.find('d:KeyInfo',ns);ki.clear()
        template=temp/'template.xml';ET.ElementTree(r).write(template,encoding='utf-8',xml_declaration=True)
        run('xmlsec1','--sign','--verbose','--print-crypto-library-errors','--lax-key-search','--insecure','--privkey-pem',str(temp/f'{key}.key')+','+str(temp/f'{key}.pem'),'--id-attr:Id','SignedProperties','--output',str(OUT/f'{name}.xml'),str(template))
        output=OUT/f'{name}.xml'
        signed=output.read_text()
        signed=signed.replace('<ds:KeyInfo/>', '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(certs[key]).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>')
        output.write_text(signed)
manifest = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(OUT.iterdir()) if f.suffix in ['.xml', '.der']}
(OUT/'manifest.json').write_text(json.dumps({'captured':'2026-10-20', 'testClockUTC':'2026-10-20T12:00:00Z', 'sha256':manifest}, indent=2)+'\n')
print('Synthetic fixtures generated; throwaway private keys deleted.')
