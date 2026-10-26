import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("packager", root/"scripts/build-beta-app.py")
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)

class PINBuildMetadataTests(unittest.TestCase):
    def test_distinct_identity_and_name(self):
        identifier, name = packager.preview_metadata("0.7.0", 14)
        self.assertEqual(identifier, "io.github.tiertoast.Signum.DevelopmentPreview.V07.B14")
        self.assertEqual(name, "Signum 0.7 Development Preview — Build 12A")
        self.assertNotEqual(identifier, packager.preview_metadata("0.7.0", 13)[0])
    def test_previous_build_identity_unchanged(self):
        self.assertEqual(packager.preview_metadata("0.7.0", 13), ("io.github.tiertoast.Signum.DevelopmentPreview.V07.B13", "Signum 0.7 Development Preview — Build 11"))
    def test_undeclared_build_rejected(self):
        with self.assertRaises(ValueError):
            packager.preview_metadata("0.7.0", 15)

if __name__ == "__main__":
    unittest.main()
