#!/usr/bin/env python3
"""Package an audited local Beta app without rebuilding, modifying or publishing it."""
import argparse
import hashlib
import json
import os
import plistlib
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(args):
    subprocess.run([str(arg) for arg in args], check=True, timeout=300)


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def build(app, notes, output, allow_unsigned_staging=False):
    app, notes, output = app.absolute(), notes.absolute(), output.absolute()
    checksum = output.with_name(output.name + '.sha256')
    if output.suffix != '.dmg' or os.path.lexists(output) or os.path.lexists(checksum):
        raise ValueError('DMG and checksum must be NEW paths; existing artifacts are preserved')
    if app.suffix != '.app' or not app.is_dir() or not notes.is_file():
        raise ValueError('An existing complete app and release notes are required')
    manifest_path = app / 'Contents/Resources/BuildManifest.json'
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get('configuration') != 'release' or manifest.get('architecture') != 'arm64'
            or manifest.get('sourceTrackedDirty') is not False):
        raise ValueError('A clean Release arm64 build is required')
    version, number = manifest['version'], manifest['build']
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    preview_name = info.get('CFBundleDisplayName', '')
    volume_name = preview_name if 'Development Preview' in preview_name else 'Signum ' + version + ' Beta b' + number
    unsigned = manifest.get('signingMode') == 'none'
    if unsigned:
        if not allow_unsigned_staging or manifest.get('distributionChannel') != 'public-beta-staging' or manifest.get('publicationQualified') is not False:
            raise ValueError('Unsigned app requires explicit staging mode; never publication approval')
        if sha256(app / 'Contents/MacOS/Signum') != manifest.get('mainExecutableSHA256'):
            raise ValueError('Unsigned main executable hash mismatch')
    else:
        run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    if info.get('CFBundleShortVersionString') != version or info.get('CFBundleVersion') != number:
        raise ValueError('App metadata differs from its manifest')
    for relative, digest in manifest['nestedCodeSHA256'].items():
        component = (app / relative).resolve(strict=True)
        if app.resolve() not in component.parents or sha256(component) != digest:
            raise ValueError('Invalid nested component: ' + relative)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.signum-dmg-', dir=output.parent) as folder:
        temporary = Path(folder)
        stage = temporary / 'contents'
        stage.mkdir()
        shutil.copytree(app, stage / app.name, symlinks=True)
        shutil.copyfile(manifest_path, stage / 'BuildManifest.json')
        shutil.copyfile(notes, stage / 'ReleaseNotes.md')
        if unsigned:
            (stage / 'UNSIGNED-STAGING.txt').write_text('Unsigned staging artifact; no Developer ID or notarization. Not execution-qualified on Apple Silicon and not approved for public distribution.\n')
        (stage / 'Applications').symlink_to('/Applications', target_is_directory=True)
        checks = []
        for path in sorted(stage.rglob('*')):
            if path.is_file() and not path.is_symlink():
                checks.append(sha256(path) + '  ' + str(path.relative_to(stage)))
        (stage / 'SHA256SUMS').write_text('\n'.join(checks) + '\n')
        image = temporary / 'image.dmg'
        run(['/usr/bin/hdiutil', 'create', '-volname', volume_name,
             '-srcfolder', stage, '-fs', 'HFS+', '-format', 'UDZO', image])
        run(['/usr/bin/hdiutil', 'verify', image])
        digest = sha256(image)
        # Atomic exclusive publication; no existing DMG is replaced.
        os.link(image, output)
        with checksum.open('x') as stream:
            stream.write(digest + '  ' + output.name + '\n')
    print(json.dumps({'dmg': str(output), 'bytes': output.stat().st_size,
                      'sha256': digest, 'sourceCommit': manifest['sourceCommit']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path)
    parser.add_argument('--release-notes', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New .dmg path; must not exist')
    parser.add_argument('--allow-unsigned-staging', action='store_true')
    args = parser.parse_args()
    build(args.app, args.release_notes, args.output, args.allow_unsigned_staging)
