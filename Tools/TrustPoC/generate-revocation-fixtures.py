#!/usr/bin/env python3
"""Public, synthetic OCSP/CRL corpus. cryptography 50.0.2 (build/test only).
No network. Private test keys live only in memory or a temporary directory and are deleted.
The checked-in evaluation clock is fixed in clock.json; regeneration records a new
clock and random keys, with the same expected dispositions.
"""
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib, json, tempfile, subprocess, os
import cryptography
if cryptography.__version__ != "50.0.2":
    raise SystemExit("Fixture generation requires cryptography 50.0.2 (development only)")
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
os.environ['OPENSSL_CONF']='/etc/ssl/openssl.cnf'
OUT = Path(os.environ.get('SIGNUM_FIXTURE_OUTPUT', str(Path(__file__).resolve().parents[2] / 'Tests/SignumCertificateValidationTests/Fixtures/Revocation')))
OUT.mkdir(parents=True, exist_ok=True)
NOW = datetime.now(timezone.utc).replace(microsecond=0)
DAY = timedelta(days=1)
DER = serialization.Encoding.DER
keys = {n:rsa.generate_private_key(public_exponent=65537,key_size=2048) for n in ['issuer','leaf','other','responder','wrong','unchecked','tsa']}
certs = {}
def cert(n, serial, issuer=None, ca=False, eku=None, nocheck=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SIGNUM SYNTHETIC REVOCATION '+n)])
    issuer_name = certs[issuer].subject if issuer else subject
    b = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).serial_number(serial).public_key(keys[n].public_key()).not_valid_before(NOW-365*DAY).not_valid_after(NOW+3650*DAY)
    b=b.add_extension(x509.BasicConstraints(ca=ca,path_length=2 if ca else None),critical=True).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=None,decipher_only=None),critical=True)
    b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[n].public_key()),critical=False)
    b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys[issuer or n].public_key()),critical=False)
    if eku:b=b.add_extension(x509.ExtendedKeyUsage([eku]),critical=True)
    if nocheck:b=b.add_extension(x509.OCSPNoCheck(),critical=False)
    certs[n]=b.sign(keys[issuer or n],hashes.SHA256())
    (OUT/(n+'.der')).write_bytes(certs[n].public_bytes(DER))
cert('issuer',1,ca=True);cert('leaf',2,issuer='issuer');cert('other',3,ca=True)
cert('responder',4,issuer='issuer',eku=ExtendedKeyUsageOID.OCSP_SIGNING,nocheck=True)
cert('wrong',5,issuer='issuer',eku=ExtendedKeyUsageOID.SERVER_AUTH,nocheck=True)
cert('unchecked',6,issuer='issuer',eku=ExtendedKeyUsageOID.OCSP_SIGNING)
cert('tsa',7,issuer='issuer',eku=ExtendedKeyUsageOID.TIME_STAMPING)
# cryptography sets producedAt to generation wall clock. The corpus's evaluation
# clock is read from generated metadata and all windows enclose that instant.
NOW = datetime.now(timezone.utc).replace(microsecond=0)
def response(name,status=ocsp.OCSPCertStatus.GOOD,signer='issuer',first=None,last=None,unknown=False):
    first=first or NOW-timedelta(hours=1)
    last=last if last is not None else NOW+DAY
    b=ocsp.OCSPResponseBuilder().add_response(cert=certs['responder'] if unknown else certs['leaf'],issuer=certs['issuer'],algorithm=hashes.SHA1(),cert_status=status,this_update=first,next_update=last,revocation_time=NOW-2*DAY if status==ocsp.OCSPCertStatus.REVOKED else None,revocation_reason=x509.ReasonFlags.key_compromise if status==ocsp.OCSPCertStatus.REVOKED else None)
    b=b.responder_id(ocsp.OCSPResponderEncoding.HASH,certs[signer])
    if signer!='issuer':b=b.certificates([certs[signer]])
    (OUT/(name+'.ocsp')).write_bytes(b.sign(keys[signer],hashes.SHA256()).public_bytes(DER))
response('good');response('revoked',ocsp.OCSPCertStatus.REVOKED);response('unknown',ocsp.OCSPCertStatus.UNKNOWN)
response('delegated',signer='responder');response('wrong-responder',signer='wrong');response('unchecked-responder',signer='unchecked')
response('unrelated',unknown=True);response('stale',first=NOW-4*DAY,last=NOW-DAY)
response('future',first=NOW+DAY,last=NOW+2*DAY)
response('unauthorized',signer='other')
# Missing nextUpdate deliberately remains unsupported by the verifier profile.
b=ocsp.OCSPResponseBuilder().add_response(cert=certs['leaf'],issuer=certs['issuer'],algorithm=hashes.SHA256(),cert_status=ocsp.OCSPCertStatus.GOOD,this_update=NOW-timedelta(hours=1),next_update=None,revocation_time=None,revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH,certs['issuer'])
(OUT/'no-next.ocsp').write_bytes(b.sign(keys['issuer'],hashes.SHA256()).public_bytes(DER))
def crl(name,revoked=False,first=None,last=None,signer='issuer',delta=False,idp=False,critical=False):
    b=x509.CertificateRevocationListBuilder().issuer_name(certs['issuer'].subject).last_update(first or NOW-timedelta(hours=1)).next_update(last or NOW+DAY)
    b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys['issuer'].public_key()),critical=False)
    if revoked:b=b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(2).revocation_date(NOW-2*DAY).add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise),critical=False).build())
    if delta:b=b.add_extension(x509.DeltaCRLIndicator(1),critical=True)
    if idp:b=b.add_extension(x509.IssuingDistributionPoint(full_name=None,relative_name=None,only_contains_user_certs=True,only_contains_ca_certs=False,only_some_reasons=None,indirect_crl=False,only_contains_attribute_certs=False),critical=True)
    if critical:b=b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'),b'\x05\x00'),critical=True)
    (OUT/(name+'.crl')).write_bytes(b.sign(keys[signer],hashes.SHA256()).public_bytes(DER))
crl('good');crl('revoked',True);crl('stale',first=NOW-4*DAY,last=NOW-DAY);crl('future',first=NOW+DAY,last=NOW+2*DAY)
crl('wrong-key',signer='other');crl('delta',delta=True);crl('restricted',idp=True);crl('critical',critical=True)
for kind in ['ocsp','crl']:
    raw=bytearray((OUT/('good.'+kind)).read_bytes());raw[-1]^=1;(OUT/('altered.'+kind)).write_bytes(raw)
# A genuine RFC 3161 token. The test-only TSA private key exists only in a
# temporary directory and is removed even if the OpenSSL command fails.
with tempfile.TemporaryDirectory(prefix='signum-timestamp-fixture-') as temporary:
    tmp=Path(temporary)
    (tmp/'tsa.key').write_bytes(keys['tsa'].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (tmp/'tsa.pem').write_bytes(certs['tsa'].public_bytes(serialization.Encoding.PEM))
    (tmp/'issuer.pem').write_bytes(certs['issuer'].public_bytes(serialization.Encoding.PEM))
    (tmp/'serial').write_text('01\n')
    (tmp/'signature.bin').write_bytes(b'SIGNUM SYNTHETIC SIGNATURE VALUE' * 8)
    config = f'''[tsa]
default_tsa=authority
[authority]
serial={tmp/'serial'}
signer_cert={tmp/'tsa.pem'}
certs={tmp/'issuer.pem'}
signer_key={tmp/'tsa.key'}
signer_digest=sha256
default_policy=1.2.3.4.5
digests=sha256,sha384,sha512
accuracy=secs:1
ordering=no
tsa_name=yes
ess_cert_id_chain=no
ess_cert_id_alg=sha256
'''
    (tmp/'tsa.cnf').write_text(config)
    openssl=os.environ.get('SIGNUM_FIXTURE_OPENSSL','openssl')
    def command(*args):
        r=subprocess.run([openssl,*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if r.returncode:raise RuntimeError(r.stderr.decode())
    command('ts','-query','-data',tmp/'signature.bin','-sha256','-cert','-out',tmp/'request.tsq')
    command('ts','-reply','-config',tmp/'tsa.cnf','-queryfile',tmp/'request.tsq','-token_out','-out',OUT/'valid.tst')
    # Extract TSTInfo, then produce correctly signed negative tokens. A generic
    # CMS signature is insufficient: RFC 3161 also requires TSA EKU and ESS.
    command('cms','-verify','-noverify','-inform','DER','-in',OUT/'valid.tst','-out',tmp/'tstinfo.bin')
    for name in ['tsa','wrong']:
        (tmp/(name+'.pem')).write_bytes(certs[name].public_bytes(serialization.Encoding.PEM))
        (tmp/(name+'.key')).write_bytes(keys[name].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    for fixture, signer, ess in [('wrong-eku','wrong',True),('missing-ess','tsa',False)]:
        command('cms','-sign','-binary','-nodetach','-md','sha256','-econtent_type','1.2.840.113549.1.9.16.1.4',
            '-in',tmp/'tstinfo.bin','-signer',tmp/(signer+'.pem'),'-inkey',tmp/(signer+'.key'),'-certfile',tmp/'issuer.pem',
            '-outform','DER','-out',OUT/(fixture+'.tst'),*(['-cades'] if ess else []))
    (OUT/'signature.bin').write_bytes((tmp/'signature.bin').read_bytes())
    bad=bytearray((OUT/'valid.tst').read_bytes());bad[-1]^=1;(OUT/'altered.tst').write_bytes(bad)
(OUT/'clock.json').write_text(json.dumps({'evaluatedAt':(NOW+timedelta(minutes=1)).isoformat(),'cryptography':'50.0.2'},indent=2)+'\n')
(OUT/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.iterdir()) if p.name!='manifest.json'},indent=2)+'\n')
print('Synthetic public revocation corpus generated; keys discarded.')
