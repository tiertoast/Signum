#!/usr/bin/env python3
"""Offline dossier consistency; --require-ready checks recorded prerequisites, not legal compliance."""
import argparse
import hashlib
import json
from pathlib import Path


def check(dossier, coverage, native, source_root, ready=False):
    if dossier.get('schema') != 1:
        raise ValueError('Unsupported PoDoFo dossier schema')
    components = set(dossier.get('components', []))
    required = {'podofo', 'freetype', 'pdfium', 'numerics', 'liberalean', 'foxit'}
    if not required <= components or not components <= set(coverage['components']):
        raise ValueError('PoDoFo or embedded dependency absent from dossier/verified notices')
    source = native['sources']['podofo']
    if dossier.get('version') != source['version'] or dossier.get('upstreamArchiveSHA256') != source['sha256']:
        raise ValueError('PoDoFo source version/hash differs from native metadata')
    if dossier.get('linkage') != 'dynamic':
        raise ValueError('Dossier linkage must describe the observed dynamic PoDoFo build')
    if dossier.get('patchStatus') not in ('unknown', 'verified') or dossier.get('sourceCorrespondence') not in ('unattested', 'attested'):
        raise ValueError('Missing explicit patch/source correspondence status')
    if dossier.get('selectedLicense') not in (None, 'MPL-2.0', 'LGPL-2.0-or-later'):
        raise ValueError('Unsupported author license decision')
    if dossier.get('distributionRoute') not in (None, 'source-with-artifact', 'written-offer', 'public-source-repository'):
        raise ValueError('Unsupported author distribution decision')
    relative = dossier.get('sourceArchive')
    archive_present = False
    if relative is not None:
        root = Path(source_root).resolve(); archive = (root / relative).resolve()
        if Path(relative).is_absolute() or root not in archive.parents or not archive.is_file():
            raise ValueError('Missing or unsafe source archive')
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Source archive hash mismatch')
        archive_present = True
    pending = []
    if not archive_present: pending.append('verified source archive unavailable')
    if dossier['patchStatus'] != 'verified': pending.append('patch inventory unverified')
    if dossier['sourceCorrespondence'] != 'attested': pending.append('binary/source correspondence unattested')
    if not dossier.get('selectedLicense'): pending.append('author license decision pending')
    if not dossier.get('distributionRoute'): pending.append('author source delivery decision pending')
    if not dossier.get('recipientInstructions'): pending.append('recipient source access instructions unavailable')
    if ready and pending:
        raise ValueError('Distribution prerequisites incomplete: ' + '; '.join(pending))
    return dict(structuralConsistency=True, distributionPrerequisitesRecorded=not pending,
                pending=pending, components=sorted(components),
                scope='Recorded technical prerequisites only; not a legal verdict or independent source attestation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dossier', type=Path, required=True)
    parser.add_argument('--coverage-proof', type=Path, required=True)
    parser.add_argument('--native-metadata', type=Path, required=True)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--require-ready', action='store_true')
    args = parser.parse_args()
    try:
        result = check(json.loads(args.dossier.read_text()), json.loads(args.coverage_proof.read_text()),
                       json.loads(args.native_metadata.read_text()), args.source_root or args.dossier.parent,
                       args.require_ready)
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('PODOFO DOSSIER ERROR: ' + str(error)); raise SystemExit(1)
