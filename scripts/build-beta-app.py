#!/usr/bin/env python3
"""Build and audit a new local ad-hoc .app. Not a Developer ID release."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]


def run(args, capture=False, **kwargs):
    result = subprocess.run([str(x) for x in args], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None, **kwargs)
    return result.stdout if capture else None


def dependencies(text):
    return re.findall(r"^\s+(.+?) \(compatibility version ", text, re.MULTILINE)


def rpaths(text):
    return re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset", text)


def minimum(text):
    versions = re.findall(r"\bminos (\d+(?:\.\d+){0,2})", text)
    versions += re.findall(r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version (\d+(?:\.\d+){0,2})", text)
    if not versions:
        raise ValueError("Missing macOS deployment target")
    return max(tuple(int(x) for x in value.split(".")) for value in versions)


def version_key(value):
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", value):
        raise ValueError("Invalid macOS version")
    parts = tuple(int(x) for x in value.split("."))
    return parts + (0,) * (3 - len(parts))


def enforce_minimum(versions, declared):
    measured = max(v + (0,) * (3 - len(v)) for v in versions)
    if measured > version_key(declared):
        raise ValueError("Mach-O deployment target exceeds the declared macOS minimum; rebuild all dependencies")
    return declared


def system(path):
    return path.startswith(("/System/Library/", "/usr/lib/"))


def portable(data):
    if (str(REPO).encode() in data or b"/opt/homebrew/" in data or
            b"/usr/local/" in data or re.search(rb"/Users/[^\x00\n]+?/Developer/", data)):
        raise ValueError("Bundle contains an absolute development or Homebrew path")


def audit_loaded(text, app, needs_podofo=False):
    paths = re.findall(r"^dyld\[\d+\]: <[^>]+> (/.+)$", text, re.MULTILINE)
    if not paths:
        raise ValueError("No dynamic loader evidence available")
    root = app.resolve()
    for path in paths:
        if not system(path) and root not in Path(path).resolve().parents:
            raise ValueError("Startup loaded an external non-system library: " + path)
    if needs_podofo and not any(Path(p).name == "libpodofo.4.dylib" for p in paths):
        raise ValueError("No evidence of the bundled PoDoFo library loading")


def replace_exclusive(source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(destination), 4):  # RENAME_EXCL
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def required_products(bins, native_build):
    products = {bins / "SignumApp": "Contents/MacOS/Signum",
                bins / "SignumCLI": "Contents/Helpers/SignumCLI",
                bins / "SignumPKCS11Worker": "Contents/Helpers/SignumPKCS11Worker",
                native_build / "signum-pades-local": "Contents/Helpers/signum-pades-local"}
    for source in products:
        if not source.is_file() or not os.access(source, os.X_OK):
            raise ValueError("Missing mandatory executable: " + str(source))
    return products


def private_dependency(ref, prefix):
    if ref.startswith("@rpath/"):
        path = prefix / "lib" / ref[len("@rpath/"):]
    elif ref.startswith("/"):
        path = Path(ref)
    else:
        raise ValueError("Unsupported dependency: " + ref)
    if not path.is_file():
        raise ValueError("Missing mandatory native dependency: " + ref)
    path = path.resolve(strict=True)
    if prefix not in path.parents:
        raise ValueError("Dependency outside the private native prefix: " + ref)
    return path


def compile_app_icon(destination, minimum_os):
    """Compile the original layered document and merge Apple's bundle metadata."""
    partial = destination.parent / "icon-partial.plist"
    actool = run(["/usr/bin/xcrun", "--find", "actool"], capture=True).strip()
    run([actool, REPO / "Resources/AppIcon.icon",
         "--compile", destination, "--platform", "macosx", "--target-device", "mac",
         "--minimum-deployment-target", minimum_os, "--app-icon", "AppIcon",
         "--output-partial-info-plist", partial])
    metadata = plistlib.loads(partial.read_bytes())
    partial.unlink()  # Compiler metadata is not a bundle resource.
    if metadata.get("CFBundleIconName") != "AppIcon":
        raise ValueError("Missing compiled Icon Composer metadata")
    for name in ("AppIcon.icns", "Assets.car"):
        if not (destination / name).is_file():
            raise ValueError("Missing compiled Icon Composer output: " + name)
    return metadata


def preview_metadata(version, build):
    if version == "0.7.0":
        if build not in (1, 2, 3, 4):
            raise ValueError("Only 0.7 Development Preview Builds 1, 2, 3 and 4 are declared")
        return (f"io.github.tiertoast.Signum.DevelopmentPreview.V07.B{build}",
                f"Signum 0.7 Development Preview — Build {build}")
    if version == "0.6.0":
        if build not in (1, 2, 3):
            raise ValueError("Only 0.6 Development Preview Builds 1, 2 and 3 are declared")
        return (f"io.github.tiertoast.Signum.DevelopmentPreview.V06.B{build}",
                f"Signum 0.6 Development Preview — Build {build}")
    if version != "0.5.0" or build not in (3, 4, 5, 6, 7):
        raise ValueError("Unsupported preview version/build")
    identity = "io.github.tiertoast.Signum.DevelopmentPreview" + (".B" + str(build) if build >= 4 else "")
    if build == 7:
        identity = "io.github.tiertoast.Signum.Beta.B7"
    name = "Signum 0.5 Beta — Build 7" if build == 7 else (f"Signum 0.5 Development Preview — Build {build}" if build >= 4 else "Signum 0.5 Development Preview")
    return identity, name


def build(output, configuration, native_prefix, cmake, preview=False, preview_build=3, preview_version="0.5.0"):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("This local recipe currently requires macOS arm64")
    output = output.absolute()
    if output.suffix != ".app" or os.path.lexists(output):
        raise ValueError("Output must be a NEW .app path; existing builds are preserved")
    prefix = native_prefix.resolve(strict=True)
    native_metadata = json.loads((prefix / "signum-native-build.json").read_text())
    if native_metadata.get("recipe") != 1 or native_metadata.get("architecture") != "arm64":
        raise ValueError("Expected the private beta native recipe")
    info = plistlib.loads((REPO / "Resources/Info.plist").read_bytes())
    preview_id, preview_name = preview_metadata(preview_version, preview_build)
    # Regular regressions run once through test-local.py, before packaging.
    tested_preview = preview and (preview_version in ("0.6.0", "0.7.0") or preview_build >= 5)
    if preview:
        info.update(CFBundleIdentifier=preview_id, CFBundleName=preview_name,
                    CFBundleDisplayName=preview_name, CFBundleShortVersionString=preview_version,
                    CFBundleVersion=str(preview_build))
    declared_target = info["LSMinimumSystemVersion"]
    if version_key(native_metadata["deploymentTarget"]) > version_key(declared_target):
        raise ValueError("Native prefix requires a newer OS; rebuild it for " + declared_target)
    sdk = run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], capture=True).strip()
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"],
           "SDKROOT": sdk, "LC_ALL": "C", "PKG_CONFIG_LIBDIR": "/nonexistent"}
    if preview:
        env.update(PKG_CONFIG_PATH=str(prefix / "lib/pkgconfig"), PKG_CONFIG_LIBDIR=str(prefix / "lib/pkgconfig"), PATH="/opt/homebrew/bin:" + env["PATH"], MACOSX_DEPLOYMENT_TARGET="13.0")
    scratch = REPO / ((".build/preview-package13-" if preview else ".build/beta-package-") + configuration)
    # Use an absolute logical root: Xcode 27 resolves a relative replacement
    # against the checkout's parent in Debug module metadata.
    mapping = str(REPO) + "=/Signum"
    swift = ["/usr/bin/swift", "build", "-c", configuration, "--scratch-path", scratch,
             "-Xswiftc", "-file-prefix-map", "-Xswiftc", mapping,
             "-Xswiftc", "-debug-prefix-map", "-Xswiftc", mapping,
             "-Xcc", "-ffile-prefix-map=" + mapping]
    if preview:
        swift += ["--triple", "arm64-apple-macosx13.0"]
    run(swift, cwd=REPO, env=env)
    bins = Path(run(swift + ["--show-bin-path"], capture=True, cwd=REPO, env=env).strip())
    native_build = REPO / ((".build/preview-pades-" if preview else ".build/beta-pades-") + configuration)
    run([cmake, "-S", REPO / "Tools/PAdESPrototype", "-B", native_build,
         "-DCMAKE_BUILD_TYPE=" + configuration.capitalize(), "-DCMAKE_PREFIX_PATH=" + str(prefix),
         "-DOPENSSL_ROOT_DIR=" + str(prefix), "-DOPENSSL_USE_STATIC_LIBS=" + ("FALSE" if preview else "TRUE"),
         "-DCMAKE_OSX_DEPLOYMENT_TARGET=" + declared_target, "-DCMAKE_OSX_ARCHITECTURES=arm64",
         "-DCMAKE_C_FLAGS=-ffile-prefix-map=" + mapping,
         "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=" + mapping,
         "-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local",
         "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF", "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF",
         "-DSIGNUM_BUILD_OFFLINE_TESTS=ON"], cwd=REPO, env=env)
    run([cmake, "--build", native_build, "--parallel", "6"], env=env)
    if not tested_preview:
        run([cmake.with_name("ctest"), "--test-dir", native_build, "--output-on-failure", "--verbose"], env=env)

    products = required_products(bins, native_build)
    if preview:
        products[bins / "SignumTrustProbe"] = "Contents/Helpers/SignumTrustProbe"
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".signum-bundle-", dir=output.parent))
    app = stage / "Signum.app"
    try:
        for folder in ("MacOS", "Helpers", "Frameworks", "Resources"):
            (app / "Contents" / folder).mkdir(parents=True, exist_ok=True)
        files = {source: app / target for source, target in products.items()}
        pending = list(files)
        ids = {}
        while pending:
            source = pending.pop(0)
            dest = files[source]
            shutil.copyfile(source, dest)
            dest.chmod(0o755)
            own_id = run(["/usr/bin/otool", "-D", source], capture=True).splitlines()[1:]
            ids[source] = own_id[0] if own_id else None
            for ref in dependencies(run(["/usr/bin/otool", "-L", source], capture=True)):
                if system(ref) or ref == ids[source]:
                    continue
                # This pinned dependency closure has @rpath libraries in prefix/lib.
                # Reject arbitrary external refs instead of silently copying a local brew install.
                dependency = private_dependency(ref, prefix)
                name = Path(ref).name
                target = app / "Contents/Frameworks" / name
                if dependency in files:
                    if files[dependency] != target:
                        raise ValueError("Ambiguous dependency alias")
                else:
                    if target in files.values():
                        raise ValueError("Dependency basename collision")
                    files[dependency] = target
                    pending.append(dependency)
        versions = []
        for source, dest in files.items():
            args = ["/usr/bin/install_name_tool"]
            if ids[source]:
                args += ["-id", "@rpath/" + dest.name]
            for ref in dependencies(run(["/usr/bin/otool", "-L", dest], capture=True)):
                if system(ref) or ref == ids[source]:
                    continue
                target = app / "Contents/Frameworks" / Path(ref).name
                if not target.is_file():
                    raise ValueError("Unresolved bundle dependency")
                args += ["-change", ref, "@loader_path/" + os.path.relpath(target, dest.parent)]
            for path in rpaths(run(["/usr/bin/otool", "-l", dest], capture=True)):
                if not system(path):
                    args += ["-delete_rpath", path]
            if len(args) > 1:
                run(args + [dest])
            run(["/usr/bin/strip", "-S", dest])
            load = run(["/usr/bin/otool", "-l", dest], capture=True)
            versions.append(minimum(load))
            arch = run(["/usr/bin/lipo", "-archs", dest], capture=True).strip()
            if arch != "arm64":
                raise ValueError("Unexpected architecture: " + arch)
            for ref in dependencies(run(["/usr/bin/otool", "-L", dest], capture=True)):
                if system(ref) or (ids[source] and ref == "@rpath/" + dest.name):
                    continue
                if not ref.startswith("@loader_path/"):
                    raise ValueError("Non-portable load command: " + ref)
                resolved = (dest.parent / ref[len("@loader_path/"):]).resolve(strict=True)
                if app not in resolved.parents:
                    raise ValueError("Load command escapes the bundle")
            portable(dest.read_bytes())

        if preview:
            resources = [bins / "Signum_SignumTrustAuthentication.bundle"]
            resources = [p for p in resources if p.is_dir()]
            if len(resources) != 1: raise ValueError("Missing or ambiguous Trusted Lists schema bundle")
            shutil.copytree(resources[0], app / "Contents/Resources" / resources[0].name)
            os.symlink("../Resources/" + resources[0].name, app / "Contents/Helpers" / resources[0].name, target_is_directory=True)
        info.update(CFBundleIdentifier=(preview_id if preview else "io.github.tiertoast.Signum.BetaFoundation"),
                    CFBundleName=(preview_name if preview else "Signum Beta Foundation"), LSMinimumSystemVersion=enforce_minimum(versions, declared_target))
        info.update(compile_app_icon(app / "Contents/Resources", declared_target))
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        icon = app / "Contents/Resources/AppIcon.icns"
        shutil.copytree(prefix / "share/signum-notices", app / "Contents/Resources/Notices")
        manifest = {"configuration": configuration, "architecture": "arm64",
                    "sourceCommit": run(["/usr/bin/git", "rev-parse", "HEAD"], capture=True, cwd=REPO).strip(),
                    "sourceTrackedDirty": bool(run(["/usr/bin/git", "diff", "--name-only", "HEAD"], capture=True, cwd=REPO).strip()),
                    "minimumOSFromMachO": ".".join(map(str, max(versions))), "declaredMinimumOS": declared_target, "native": native_metadata,
                    "version": info["CFBundleShortVersionString"], "build": info["CFBundleVersion"],
                    "appIconSHA256": hashlib.sha256(icon.read_bytes()).hexdigest(),
                    "appIconAssetsSHA256": hashlib.sha256((app / "Contents/Resources/Assets.car").read_bytes()).hexdigest(),
                    "signing": "ad-hoc only; no Developer ID, hardened runtime or notarization",
                    "external": "User-installed PKCS#11 middleware for signing/discovery; bundled OpenSSL for unified verification; system /usr/bin/openssl for legacy verify-cades"}
        # Inner dylibs, helpers, main executable, then the enclosing bundle.
        ordered = sorted(files.values(), key=lambda p: (p.parent.name != "Frameworks", p.parent.name == "MacOS", str(p)))
        for dest in ordered:
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", dest])
        # Signing the enclosing app changes its main executable's signature.
        # A sealed manifest cannot self-hash that signature without a cycle.
        manifest["nestedCodeSHA256"] = {str(p.relative_to(app)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in ordered if p.parent.name != "MacOS"}
        manifest["mainExecutableIntegrity"] = "Covered by the enclosing app code signature"
        (app / "Contents/Resources/BuildManifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for path in app.rglob("*"):
            if path.is_file():
                portable(path.read_bytes())
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", app])
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app])
        for relative, digest in manifest["nestedCodeSHA256"].items():
            if hashlib.sha256((app / relative).read_bytes()).hexdigest() != digest:
                raise ValueError("Nested code changed during enclosing bundle signing")
        for path in app.rglob("*"):
            if path.is_file():
                portable(path.read_bytes())
        mock = native_build / "libsignum-pades-policy-mock.so"
        smoke(app, mock)
        if not tested_preview:
            run([native_build / "signum-pades-tests", "--helper-integration",
             app / "Contents/Helpers/signum-pades-local", mock], cwd=REPO, env=env)
        # Relocation checks resolve dependencies from the bundle, not the source prefix.
        relocated = stage / "Relocated" / "Signum.app"
        shutil.copytree(app, relocated, symlinks=True)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", relocated])
        smoke(relocated, mock)
        if not tested_preview:
            run([native_build / "signum-pades-tests", "--helper-integration",
             relocated / "Contents/Helpers/signum-pades-local", mock], cwd=REPO, env=env)
        replace_exclusive(app, output)
        print("Verified local ad-hoc bundle: " + str(output), flush=True)
    finally:
        shutil.rmtree(stage)


def smoke(app, mock):
    helper = app / "Contents/Helpers"
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "LC_ALL": "C",
           "DYLD_PRINT_LIBRARIES": "1"}
    for name, args, code in (("SignumPKCS11Worker", [], 2), ("SignumCLI", ["help"], 0),
                             ("signum-pades-local", [], 2)):
        child = subprocess.run([str(helper / name)] + args, input=b"", stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, timeout=10)
        if child.returncode != code:
            raise ValueError("Packaged startup failed: " + name + " (" + str(child.returncode) + ")")
        audit_loaded(child.stderr.decode(errors="replace"), app, name == "signum-pades-local")
    # Real IPC from the packaged CLI to its sibling worker. Public synthetic
    # discovery only: never reads an installed provider or requests a PIN.
    result = subprocess.run([str(helper / "SignumCLI"), "list", str(mock)],
                            input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={k: v for k, v in env.items() if k != "DYLD_PRINT_LIBRARIES"}, timeout=15)
    if result.returncode != 0 or b"Slot 7:" not in result.stdout:
        raise ValueError("Packaged CLI/worker synthetic discovery failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New .app path; must not exist")
    parser.add_argument("--configuration", choices=("debug", "release"), default="release")
    parser.add_argument("--native-prefix", required=True, type=Path)
    parser.add_argument("--cmake", type=Path, default=REPO / ".build/native-tools/cmake/data/bin/cmake")
    options = parser.parse_args()
    build(options.output, options.configuration, options.native_prefix, options.cmake.absolute())
