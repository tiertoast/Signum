"""Offline packaging guards. No installed provider, credentials, or hardware."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "build-beta-app.py"
spec = importlib.util.spec_from_file_location("beta_package", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_macho_parsing_handles_spaces_and_system_libraries(self):
        self.assertEqual(package.dependencies("image:\n\t@loader_path/../Frameworks/A B.dylib (compatibility version 1.0.0, current version 1.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n"),
                         ["@loader_path/../Frameworks/A B.dylib", "/usr/lib/libSystem.B.dylib"])
        self.assertTrue(package.system("/usr/lib/libSystem.B.dylib"))
        self.assertFalse(package.system("/usr/local/lib/libcrypto.dylib"))

    def test_rpaths_and_minimum_os(self):
        text = "cmd LC_RPATH\n cmdsize 80\n path /private/build with spaces/lib (offset 12)\ncmd LC_BUILD_VERSION\n platform 1\n minos 14.0\n sdk 27.0\n"
        self.assertEqual(package.rpaths(text), ["/private/build with spaces/lib"])
        self.assertEqual(package.minimum(text), (14, 0))
        self.assertEqual(package.minimum("cmd LC_VERSION_MIN_MACOSX\n cmdsize 16\n version 13.5\n sdk 14.0"), (13, 5))
        with self.assertRaises(ValueError):
            package.minimum("sdk 27.0")

    def test_compiled_development_paths_are_rejected(self):
        for data in (b"\x00/Users/another/Developer/Signum/foo.cpp\x00", b"/opt/homebrew/lib/libx.dylib",
                     b"/usr/local/lib/libx.dylib", str(package.REPO).encode()):
            with self.assertRaises(ValueError):
                package.portable(data)
        package.portable(b"@loader_path/../Frameworks/libpodofo.4.dylib\x00/etc/ssl\x00/usr/lib/libSystem.B.dylib")

    def test_loader_audit_requires_evidence_and_bundle_containment(self):
        root = Path("/tmp/Signum.app")
        good = "dyld[12]: <UUID> /tmp/Signum.app/Contents/Frameworks/libpodofo.4.dylib\ndyld[12]: <UUID> /usr/lib/libSystem.B.dylib\n"
        package.audit_loaded(good, root, True)
        for text in ("", good.replace("Signum.app/", "Signum.app.evil/"),
                     "dyld[12]: <UUID> /usr/lib/libSystem.B.dylib\n"):
            with self.assertRaises(ValueError):
                package.audit_loaded(text, root, True)

    def test_existing_output_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as root:
            app = Path(root) / "Signum.app"
            app.mkdir()
            marker = app / "preserve"
            marker.write_bytes(b"working Alpha")
            with self.assertRaises(ValueError):
                package.build(app, "debug", Path(root) / "missing-prefix", Path("/missing/cmake"))
            self.assertEqual(marker.read_bytes(), b"working Alpha")

    def test_broken_symlink_output_is_also_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            app = Path(root) / "Signum.app"
            app.symlink_to(Path(root) / "missing")
            with self.assertRaises(ValueError):
                package.build(app, "release", Path(root) / "missing-prefix", Path("/missing/cmake"))
            self.assertTrue(app.is_symlink())

    def test_exclusive_publication_preserves_racing_destination(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "staged.app"
            dest = Path(root) / "existing.app"
            source.mkdir()
            dest.mkdir()
            with self.assertRaises(OSError):
                package.replace_exclusive(source, dest)
            self.assertTrue(source.is_dir())
            dest.rmdir()
            package.replace_exclusive(source, dest)
            self.assertTrue(dest.is_dir())
            self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
