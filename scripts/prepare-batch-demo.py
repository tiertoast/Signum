#!/usr/bin/env python3
"""Prepare an isolated synthetic GUI demo. Never accesses a token or signs files."""
import argparse
import json
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[1]


def prepare(output):
    output = output.resolve()
    if (REPO / ".build").resolve() not in output.parents:
        raise ValueError("Demo output must be a new directory inside this checkout's .build")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)

    def run(args):
        subprocess.run([str(x) for x in args], cwd=output, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    (output / "certificate.cnf").write_text("""[req]
distinguished_name=dn
x509_extensions=signer
[dn]
[signer]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
""")
    run(["/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "key.pem", "-out", "certificate.pem", "-days", "7",
         "-subj", "/CN=Signum Synthetic Batch Demo", "-config", "certificate.cnf"])
    run(["/usr/bin/openssl", "x509", "-in", "certificate.pem", "-outform", "DER", "-out", "certificate.der"])
    run(["/usr/bin/openssl", "rsa", "-in", "key.pem", "-outform", "DER", "-out", "key.der"])
    header = "#define SIGNUM_MOCK_BOOTSTRAP_CERTIFICATE 1\n#define SIGNUM_MOCK_SOFTWARE_KEY 1\n"
    header += "#define SIGNUM_MOCK_AUDIT_PATH " + json.dumps(str(output / "operations")) + "\n"
    for name, path in (("bootstrap_certificate", "certificate.der"), ("bootstrap_private_key", "key.der")):
        header += "static const unsigned char " + name + "[]={" + ",".join(map(str, (output / path).read_bytes())) + "};\n"
    (output / "fixture.h").write_text(header)
    module = output / "synthetic-provider.dylib"
    run(["/usr/bin/cc", "-dynamiclib", "-pthread", "-I", REPO / "Sources/CPKCS11",
         "-include", output / "fixture.h", REPO / "Tools/PKCS11Tests/mock_provider.c",
         "-framework", "Security", "-framework", "CoreFoundation", "-o", module])
    module.chmod(0o700)
    documents = output / "documents"
    documents.mkdir(mode=0o700)
    for number in range(1, 4):
        (documents / ("synthetic-" + str(number) + ".txt")).write_text("Signum synthetic batch document " + str(number) + "\n")
    (documents / "duplicate-of-1.txt").write_bytes((documents / "synthetic-1.txt").read_bytes())
    # Small, unencrypted, one-page PDF with exact xref offsets; no external fonts.
    content = b"BT /F1 16 Tf 40 420 Td (Signum synthetic batch demo) Tj ET\n"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 500] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"endstream"]
    pdf, offsets = b"%PDF-1.4\n", []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    pdf += b"".join(("%010d 00000 n \n" % offset).encode() for offset in offsets)
    pdf += b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"
    (documents / "synthetic.pdf").write_bytes(pdf)
    (output / "output").mkdir(mode=0o700)
    (output / "DEMO.txt").write_text("SYNTHETIC TEST ONLY. Public test key embedded in the mock. No real token.\n"
        "Use only documents in documents/. Select this exact synthetic-provider.dylib in Signum.\n"
        "The mock ignores any nonempty test string entered in the PIN field. Never enter a real PIN.\n"
        "No signing/authentication was performed by this preparation script.\n")
    print("Synthetic provider: " + str(module))
    print("Synthetic documents: " + str(documents))
    print("Output directory: " + str(output / "output"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory below .build; must not exist")
    prepare(parser.parse_args().output)
