"""Offline packaging guards. No installed provider, credentials, or hardware."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import plistlib
import json
import subprocess

SCRIPT = Path(__file__).resolve().parents[1] / "build-beta-app.py"
spec = importlib.util.spec_from_file_location("beta_package", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_07_preview_coexists_with_06(self):
        identity, name = package.preview_metadata("0.7.0", 1)
        self.assertEqual(identity, "io.github.tiertoast.Signum.DevelopmentPreview.V07.B1")
        self.assertIn("0.7 Development Preview", name)
        self.assertNotEqual(identity, package.preview_metadata("0.6.0", 3)[0])
        with self.assertRaises(ValueError):
            package.preview_metadata("0.7.0", 2)

    def test_layered_document_compiles_for_macos13_with_native_and_fallback_icons(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "Resources"
            destination.mkdir()
            metadata = package.compile_app_icon(destination, "13.0")
            self.assertEqual(metadata["CFBundleIconName"], "AppIcon")
            self.assertEqual(metadata["CFBundleIconFile"], "AppIcon")
            data = (destination / "AppIcon.icns").read_bytes()
            self.assertEqual(data[:4], b"icns")
            self.assertEqual(int.from_bytes(data[4:8], "big"), len(data))
            self.assertGreater((destination / "Assets.car").stat().st_size, 0)

    def test_06_preview_is_isolated_and_05_identity_is_preserved(self):
        identity, name = package.preview_metadata("0.6.0", 1)
        self.assertEqual(identity, "io.github.tiertoast.Signum.DevelopmentPreview.V06.B1")
        self.assertEqual(name, "Signum 0.6 Development Preview — Build 1")
        self.assertTrue(identity.startswith("io.github.tiertoast.Signum.DevelopmentPreview"))
        build2_identity, build2_name = package.preview_metadata("0.6.0", 2)
        self.assertEqual(build2_identity, "io.github.tiertoast.Signum.DevelopmentPreview.V06.B2")
        self.assertEqual(build2_name, "Signum 0.6 Development Preview — Build 2")
        self.assertNotEqual(identity, build2_identity)
        self.assertEqual(package.preview_metadata("0.6.0",3),
                         ("io.github.tiertoast.Signum.DevelopmentPreview.V06.B3", "Signum 0.6 Development Preview — Build 3"))

        self.assertEqual(package.preview_metadata("0.5.0", 7),
                         ("io.github.tiertoast.Signum.Beta.B7", "Signum 0.5 Beta — Build 7"))
        self.assertEqual(package.preview_metadata("0.5.0", 6)[0],
                         "io.github.tiertoast.Signum.DevelopmentPreview.B6")
        for version, build in [("0.6.0", 7), ("0.5.0", 1), ("0.7.0", 2)]:
            with self.assertRaises(ValueError):
                package.preview_metadata(version, build)

    def test_legacy_script_fails_clearly_without_creating_any_bundle(self):
        with tempfile.TemporaryDirectory() as root:
            for args in ([], ["--help"], ["--output", "Signum.app"]):
                result = subprocess.run(["/bin/bash", str(SCRIPT.with_name("build-app.sh")), *args], cwd=root, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn("retired", result.stderr)
                self.assertIn("build-beta-app.py", result.stderr)
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_missing_worker_or_helper_prevents_complete_product_set(self):
        with tempfile.TemporaryDirectory() as root:
            bins = Path(root) / "bins"; native = Path(root) / "native"
            bins.mkdir(); native.mkdir()
            products = [bins / "SignumApp", bins / "SignumCLI", bins / "SignumPKCS11Worker", native / "signum-pades-local"]
            for product in products:
                product.write_bytes(b"synthetic executable"); product.chmod(0o700)
            self.assertEqual(len(package.required_products(bins, native)), 4)
            for missing in products:
                missing.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "mandatory executable"):
                    package.required_products(bins, native)
                missing.chmod(0o700)
                data = missing.read_bytes(); missing.unlink()
                with self.assertRaisesRegex(ValueError, "mandatory executable"):
                    package.required_products(bins, native)
                missing.write_bytes(data); missing.chmod(0o700)

    def test_missing_dependency_is_refused_without_external_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            prefix = Path(root).resolve(); (prefix / "lib").mkdir()
            with self.assertRaisesRegex(ValueError, "Missing mandatory native dependency"):
                package.private_dependency("@rpath/libmissing.dylib", prefix)
            dependency = prefix / "lib/liblocal.dylib"; dependency.write_bytes(b"fixture")
            self.assertEqual(package.private_dependency("@rpath/liblocal.dylib", prefix), dependency)
            with self.assertRaisesRegex(ValueError, "Unsupported dependency"):
                package.private_dependency("@loader_path/outside.dylib", prefix)
            dependency.unlink(); dependency.symlink_to(SCRIPT)
            with self.assertRaisesRegex(ValueError, "outside the private"):
                package.private_dependency("@rpath/liblocal.dylib", prefix)

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

    def test_macos13_requires_every_binary_to_fit_declared_minimum(self):
        self.assertEqual(package.enforce_minimum([(13, 0), (12, 0, 1)], "13.0"), "13.0")
        for versions in ([(13, 0), (14, 0)], [(13, 0, 1)], [(27, 0)]):
            with self.assertRaises(ValueError):
                package.enforce_minimum(versions, "13.0")
        with self.assertRaises(ValueError):
            package.version_key("13.0 extra flags")

    def test_native_and_swift_policy_agree_with_resource_metadata(self):
        spec = importlib.util.spec_from_file_location("beta_native", SCRIPT.with_name("build-beta-native.py"))
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        info = plistlib.loads((package.REPO / "Resources/Info.plist").read_bytes())
        self.assertEqual(native.deployment_target(), info["LSMinimumSystemVersion"])
        self.assertIn(".macOS(.v" + info["LSMinimumSystemVersion"].split(".")[0] + ")", (package.REPO / "Package.swift").read_text())
        self.assertEqual(info["CFBundleShortVersionString"], "0.4.0")

    def test_newer_native_prefix_is_rejected_before_build_or_publication(self):
        with tempfile.TemporaryDirectory() as root:
            prefix = Path(root) / "prefix"
            prefix.mkdir()
            (prefix / "signum-native-build.json").write_text(json.dumps({
                "recipe": 1, "architecture": "arm64", "deploymentTarget": "99.0"}))
            output = Path(root) / "Signum.app"
            with self.assertRaisesRegex(ValueError, "newer OS"):
                package.build(output, "release", prefix, Path("/missing/cmake"))
            self.assertFalse(output.exists())

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
