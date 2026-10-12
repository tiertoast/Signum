# Signum PAdES Engine — Experimental

Optional native C++/PoDoFo prototype for PAdES-B with a PKCS#11 hardware key.
Not built by swift test. When the optional helper is compiled locally, the macOS app can launch it for experimental PAdES signing.

## Technical flow

- PoDoFo 1.1.x incrementally signs a new copy of the PDF using PdfSignerCms.
- An external SigningService supplies SHA-256 DigestInfo to PKCS#11 CKM_RSA_PKCS.
- The private key never leaves the DigitalDNA/CNS device.
- The optional rectangle creates a PDF signature field; graphic image/text appearance streams are NOT yet implemented.
- This does not verify trusted certificate chains, eIDAS status, timestamps or revocation.

## Build on your Mac only

Verify installed Homebrew packages first, then when ready:

```bash
brew install cmake podofo
cd ~/Signum
cmake -S Tools/PAdESPrototype -B .build/signum-pades -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build .build/signum-pades --config Release
```

If compilation fails or the PoDoFo API differs, STOP and send the compiler diagnostics.
Do not use a production PDF for this experiment.

## First PDF signature trial (after successful compilation)

Choose a small non-confidential test PDF and a NEW output path:

```bash
.build/signum-pades/signum-pades-local /absolute/path/to/test.pdf /absolute/path/to/test-signed.pdf /Library/bit4id/pkcs11/libbit4xpki.dylib 1 445333
```

The helper asks for the token PIN on the terminal, not via arguments.
To use a signature field rectangle, append optional PAGE_INDEX X Y WIDTH HEIGHT (PDF points, page zero-based):

```text
0 120 90 190 62
```

Verify the output independently with InfoCamere Sign, including its PAdES profile, integrity, ByteRange and intended signer. The file is not considered compatible until these tests succeed.

## License and safety

PoDoFo is LGPL-2.0-or-later OR MPL-2.0, installed independently, not vendored in Signum.
The helper does not perform a full driver security review; the PIN may remain in transient memory copies. An eventual GUI bridge must use isolated secure IPC rather than command-line or environment PINs.

## GUI prototype

Rebuild the helper locally, then run `bash scripts/build-app.sh` to include it in the app bundle. Until the helper is present, the PAdES signing button stays disabled. Verify every output PDF with an independent validator. The selected position creates a signature field; the custom image and text appearance is not yet embedded into signed PDFs.
