"""S09 synthetic prerequisites; never claim the installed library was reproduced."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('podofo_contract', Path(__file__).resolve().parents[1] / 'podofo_source_contract.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class PoDoFoSourceContractTests(unittest.TestCase):
    def fixture(self, body):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / 'synthetic.tar'; archive.write_bytes(b'SYNTHETIC SOURCE')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            components = ['podofo', 'freetype', 'pdfium', 'numerics', 'liberalean', 'foxit']
            dossier = dict(schema=1, components=components, version='podofo-fixture', upstreamArchiveSHA256=digest,
                           linkage='dynamic', patchStatus='verified', sourceCorrespondence='attested',
                           selectedLicense='MPL-2.0', distributionRoute='source-with-artifact',
                           recipientInstructions='Synthetic fixture only', sourceArchive='synthetic.tar')
            native = {'sources': {'podofo': {'version': 'podofo-fixture', 'sha256': digest}}}
            body(dossier, {'components': components.copy()}, native, root)

    def test_complete_synthetic_case_passes(self):
        self.fixture(lambda d, p, n, r: self.assertTrue(c.check(d, p, n, r, True)['distributionPrerequisitesRecorded']))

    def test_pending_case_is_structurally_valid_but_never_ready(self):
        def body(d, p, n, r):
            d.update(sourceArchive=None, patchStatus='unknown', sourceCorrespondence='unattested', selectedLicense=None, distributionRoute=None, recipientInstructions=None)
            self.assertFalse(c.check(d, p, n, r)['distributionPrerequisitesRecorded'])
            with self.assertRaisesRegex(ValueError, 'incomplete'): c.check(d, p, n, r, True)
        self.fixture(body)

    def test_missing_changed_or_escaping_archive_fails(self):
        def body(d, p, n, r):
            for relative in ['missing.tar', '../outside.tar', str(r / 'synthetic.tar')]:
                d['sourceArchive'] = relative
                with self.assertRaisesRegex(ValueError, 'archive'): c.check(d, p, n, r)
            d['sourceArchive'] = 'synthetic.tar'; (r / 'synthetic.tar').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'hash'): c.check(d, p, n, r)
        self.fixture(body)

    def test_missing_component_or_wrong_version_fails(self):
        def body(d, p, n, r):
            p['components'].remove('freetype')
            with self.assertRaisesRegex(ValueError, 'dependency'): c.check(d, p, n, r)
            p['components'].append('freetype'); d['version'] = 'wrong'
            with self.assertRaisesRegex(ValueError, 'version/hash'): c.check(d, p, n, r)
        self.fixture(body)

    def test_unknown_author_decision_fails(self):
        def body(d, p, n, r):
            for key in ['selectedLicense', 'distributionRoute']:
                original = d[key]; d[key] = 'automatic'
                with self.assertRaisesRegex(ValueError, 'author'): c.check(d, p, n, r)
                d[key] = original
        self.fixture(body)


if __name__ == '__main__': unittest.main()
