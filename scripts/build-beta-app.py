#!/usr/bin/env python3
"""Build and audit a new local ad-hoc .app. Not a Developer ID release."""
import argparse
import ctypes
import hashlib
import importlib.util
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


def linked_sdk(text):
    values = re.findall(r"\bsdk (\d+(?:\.\d+){0,2})", text)
    if len(values) != 1:
        raise ValueError("Missing or ambiguous linked SDK")
    return version_key(values[0])


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


def source_materials(prefix):
    native = json.loads((Path(prefix) / 'signum-native-build.json').read_text())
    if 'phase7Controlled' in native:
        spec = importlib.util.spec_from_file_location('native_profile_contract', REPO/'scripts/native_profile_contract.py')
        contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
        return contract.validate(prefix, REPO)
    return REPO/'Resources/ThirdPartySources', None


def install_notices(resources, prefix, binaries):
    """Use the same checked notice material for existing and rebuilt prefixes."""
    spec = importlib.util.spec_from_file_location("notices_contract", REPO/"scripts/notices_contract.py")
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    catalog = json.loads((REPO/"scripts/third-party-notices.json").read_text())
    native = json.loads((prefix/"signum-native-build.json").read_text())
    proof = contract.audit(binaries, prefix, REPO/"Resources/Notices", native, catalog)
    shutil.copytree(REPO/"Resources/Notices", resources/"Notices")
    shutil.copyfile(REPO/"scripts/third-party-notices.json", resources/"ThirdPartyNotices.json")
    contract.check_notices(resources/"Notices",catalog,set(proof['components']),native)
    source_spec = importlib.util.spec_from_file_location("podofo_source_contract", REPO/"scripts/podofo_source_contract.py")
    source_contract = importlib.util.module_from_spec(source_spec); source_spec.loader.exec_module(source_contract)
    source_root, provenance = source_materials(prefix)
    dossier = json.loads((source_root/"podofo.json").read_text())
    source_status = source_contract.check(dossier, proof, native, source_root)
    shutil.copytree(source_root, resources/"ThirdPartySources")
    shutil.copyfile(REPO/"docs/PODOFO_SOURCE_DOSSIER.md", resources/"ThirdPartySources/DOSSIER.md")
    (resources/"ThirdPartySources/STATUS.json").write_text(json.dumps(source_status, indent=2)+"\n")
    return proof


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
        if build not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14):
            raise ValueError("Only 0.7 Development Preview Builds 1 through 14 are declared")
        return (f"io.github.tiertoast.Signum.DevelopmentPreview.V07.B{build}",
                ("Signum 0.7 Development Preview — Build 12A" if build == 14 else "Signum 0.7 Development Preview — Build 11" if build == 13 else "Signum 0.7 Development Preview — Build 10" if build == 12 else "Signum 0.7 Development Preview — Build 9 Verification — Hotfix 1" if build == 11 else "Signum 0.7 Development Preview — Build 9 Verification" if build == 10 else "Signum 0.7 Development Preview — Build 8 DSS" if build == 9 else f"Signum 0.7 Development Preview — Build {build}"))
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


def external_workspace(path):
    path = Path(path).resolve()
    protected = [REPO, REPO.parent / 'repository.git', REPO.parent / 'logs',
                 REPO.parent / 'manual', REPO.parent.parent / 'Signum-Reviews',
                 REPO.parent.parent / 'Signum-0.7']
    if any(path == root or root in path.parents for root in protected) or os.path.lexists(path):
        raise ValueError('Workspace must be NEW, external and outside preserved trees')
    return path


def public_beta_metadata(build_number, bundle_id):
    if (not isinstance(build_number, int) or build_number < 1 or not bundle_id or
            not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+', bundle_id)):
        raise ValueError('Explicit positive Beta build and reverse-DNS bundle identifier required')
    return dict(CFBundleIdentifier=bundle_id, CFBundleName='Signum',
                CFBundleDisplayName='Signum 0.7.0 Beta',
                CFBundleShortVersionString='0.7.0', CFBundleVersion=str(build_number))


def distribution_prerequisites(prefix):
    """Recorded prerequisites only; never substitutes for an artifact/legal audit."""
    blockers = []
    result = dict(ready=False, blockers=blockers)
    try:
        native = json.loads((Path(prefix) / 'signum-native-build.json').read_text())
        catalog = json.loads((REPO / 'scripts/third-party-notices.json').read_text())
        def load(name):
            spec = importlib.util.spec_from_file_location(name, REPO / 'scripts' / (name + '.py'))
            value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
            return value
        load('notices_contract').check_notices(REPO / 'Resources/Notices', catalog, set(catalog['components']), native)
        if catalog['components']['freetype'].get('licenseSelection') not in ('FTL', 'GPL-2.0-or-later'):
            blockers.append('Author FreeType license selection pending')
        elif catalog['components']['freetype'].get('licenseSelection') == 'GPL-2.0-or-later':
            blockers.append('FreeType GPL route requires full GPL text and module/combined-work review')
        schemas = load('schema_license_contract').check(REPO, json.loads((REPO / 'scripts/schema-license-catalog.json').read_text()))
        blockers.extend('Original schema license missing: ' + x for x in schemas['unresolvedLicenses'])
        result['schemas'] = schemas
        root, provenance = source_materials(prefix)
        if provenance: result['nativeProvenance'] = provenance
        dossier = load('podofo_source_contract').check(json.loads((root / 'podofo.json').read_text()),
                    {'components': list(catalog['components'])}, native, root)
        result['podofo'] = dossier; blockers.extend(dossier['pending'])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        blockers.append(str(error))
    result['ready'] = not blockers
    return result


def seal_code(ordered, app, mode):
    if mode not in ('adhoc', 'none'):
        raise ValueError('Only local ad-hoc or unsigned staging is supported')
    for dest in ordered:
        if mode == 'adhoc':
            run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', dest])
        else:
            # install_name_tool/strip invalidate inherited linker signatures.
            run(['/usr/bin/codesign', '--remove-signature', dest])
    return mode == 'adhoc'


def build(output, configuration, native_prefix, cmake, preview=False, preview_build=3, preview_version="0.5.0",
          scratch_root=None, signing_mode='adhoc', public_beta_build=None, bundle_id=None, trust_probe=None):
    if signing_mode not in ('adhoc', 'none'):
        raise ValueError('Only local ad-hoc or unsigned staging is supported')
    public_beta = public_beta_build is not None
    if signing_mode == 'none' and not public_beta:
        raise ValueError('Unsigned staging requires the public Beta prerequisite gate and metadata')
    if public_beta and configuration != 'release':
        raise ValueError('Public Beta staging requires Release configuration')
    beta_info = public_beta_metadata(public_beta_build, bundle_id) if public_beta else None
    if (public_beta or signing_mode == 'none') and scratch_root is None:
        raise ValueError('An external workspace is required')
    if public_beta and trust_probe not in ('include', 'exclude'):
        raise ValueError('Explicit TrustProbe inclusion/exclusion required')
    if public_beta:
        preview = True; preview_version = '0.7.0'; preview_build = 14
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("This local recipe currently requires macOS arm64")
    output = output.absolute()
    if output.suffix != ".app" or os.path.lexists(output):
        raise ValueError("Output must be a NEW .app path; existing builds are preserved")
    if public_beta or signing_mode == 'none':
        external_workspace(output)
    frozen_commit = None
    if public_beta:
        if run(['/usr/bin/git', 'status', '--short', '--ignored'], capture=True, cwd=REPO).strip():
            raise ValueError('Public Beta staging requires a clean repository including ignored files')
        frozen_commit = run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True, cwd=REPO).strip()
    prefix = native_prefix.resolve(strict=True)
    native_metadata = json.loads((prefix / "signum-native-build.json").read_text())
    if native_metadata.get("recipe") != 1 or native_metadata.get("architecture") != "arm64":
        raise ValueError("Expected the private beta native recipe")
    if public_beta:
        readiness = distribution_prerequisites(prefix)
        if not readiness['ready']:
            raise ValueError('Distribution prerequisites incomplete: ' + '; '.join(readiness['blockers']))
    info = plistlib.loads((REPO / "Resources/Info.plist").read_bytes())
    preview_id, preview_name = preview_metadata(preview_version, preview_build)
    # Regular regressions run once through test-local.py, before packaging.
    tested_preview = preview and (preview_version in ("0.6.0", "0.7.0") or preview_build >= 5)
    if preview:
        info.update(CFBundleIdentifier=preview_id, CFBundleName=preview_name,
                    CFBundleDisplayName=preview_name, CFBundleShortVersionString=preview_version,
                    CFBundleVersion=str(preview_build))
    if public_beta:
        info.update(beta_info); preview_id = info['CFBundleIdentifier']; preview_name = info['CFBundleDisplayName']
    declared_target = info["LSMinimumSystemVersion"]
    if version_key(native_metadata["deploymentTarget"]) > version_key(declared_target):
        raise ValueError("Native prefix requires a newer OS; rebuild it for " + declared_target)
    sdk = run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], capture=True).strip()
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"],
           "SDKROOT": sdk, "LC_ALL": "C", "PKG_CONFIG_LIBDIR": "/nonexistent"}
    if preview:
        env.update(PKG_CONFIG_PATH=str(prefix / "lib/pkgconfig"), PKG_CONFIG_LIBDIR=str(prefix / "lib/pkgconfig"), PATH="/opt/homebrew/bin:" + env["PATH"], MACOSX_DEPLOYMENT_TARGET="13.0")
    workspace = external_workspace(scratch_root) if scratch_root is not None else None
    if workspace is not None:
        if prefix == workspace or prefix in workspace.parents or workspace in prefix.parents:
            raise ValueError('Workspace cannot contain or modify the read-only native prefix')
        workspace.mkdir(parents=True, exist_ok=False); (workspace / 'tmp').mkdir()
        env['TMPDIR'] = str(workspace / 'tmp') + '/'
        env.update(CLANG_MODULE_CACHE_PATH=str(workspace / 'clang-cache'),
                   SWIFT_MODULECACHE_PATH=str(workspace / 'swift-cache'),
                   XDG_CACHE_HOME=str(workspace / 'cache'))
    scratch = workspace / 'swift' if workspace else REPO / ((".build/preview-package13-" if preview else ".build/beta-package-") + configuration)
    # Use an absolute logical root: Xcode 27 resolves a relative replacement
    # against the checkout's parent in Debug module metadata.
    mapping = str(REPO) + "=/Signum"
    swift = ["/usr/bin/swift", "build", "-c", configuration, "--scratch-path", scratch,
             "-Xswiftc", "-file-prefix-map", "-Xswiftc", mapping,
             "-Xswiftc", "-debug-prefix-map", "-Xswiftc", mapping,
             "-Xcc", "-ffile-prefix-map=" + mapping]
    if workspace is not None:
        swift += ['--cache-path', workspace / 'package-cache', '--config-path', workspace / 'package-config',
                  '--security-path', workspace / 'package-security', '--disable-dependency-cache']
    if preview:
        swift += ["--triple", "arm64-apple-macosx13.0"]
    if preview and preview_version == "0.7.0" and preview_build >= 5:
        # swiftbuild currently links the explicit deployment triple with sdk=13.0.
        # Record the actual SDK used to compile, so AppKit enables native modern
        # chrome; keep the independently declared macOS 13 deployment minimum.
        sdk_version = run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"], capture=True).strip()
        swift += ["-Xlinker", "-platform_version", "-Xlinker", "macos",
                  "-Xlinker", declared_target, "-Xlinker", sdk_version]
    run(swift, cwd=REPO, env=env)
    bins = Path(run(swift + ["--show-bin-path"], capture=True, cwd=REPO, env=env).strip())
    native_build = workspace / 'pades' if workspace else REPO / ((".build/preview-pades-" if preview else ".build/beta-pades-") + configuration)
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
    if preview and (not public_beta or trust_probe == 'include'):
        products[bins / "SignumTrustProbe"] = "Contents/Helpers/SignumTrustProbe"
    if public_beta:
        # Refuse unknown/unlicensed dependencies before copying any native code.
        if (run(['/usr/bin/git', 'status', '--short', '--ignored'], capture=True, cwd=REPO).strip() or
                run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True, cwd=REPO).strip() != frozen_commit):
            raise ValueError('Source changed during the build')
        spec = importlib.util.spec_from_file_location('notices_contract', REPO / 'scripts/notices_contract.py')
        contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
        contract.audit(list(products), prefix, REPO / 'Resources/Notices', native_metadata)
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
            if preview and preview_version == "0.7.0" and preview_build >= 5 and source == bins / "SignumApp":
                if linked_sdk(load) != version_key(sdk_version):
                    raise ValueError("App linked SDK does not match the compiler SDK; native chrome would use compatibility mode")
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
        for service in info.get("NSServices", []): service["NSPortName"] = info["CFBundleName"]
        shutil.copy2(REPO / "Resources/DocumentIcons/SignedDocument.icns", app / "Contents/Resources/SignedDocument.icns")
        info.update(compile_app_icon(app / "Contents/Resources", declared_target))
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        icon = app / "Contents/Resources/AppIcon.icns"
        notice_proof = install_notices(app / "Contents/Resources", prefix, list(products))
        if public_beta:
            shutil.copyfile(REPO / 'LICENSE', app / 'Contents/Resources/Signum-LICENSE.txt')
            shutil.copyfile(REPO / 'scripts/schema-license-catalog.json', app / 'Contents/Resources/SchemaLicenseCatalog.json')
            shutil.copyfile(REPO / 'Sources/SignumTrustAuthentication/Schemas/PROVENANCE.md', app / 'Contents/Resources/SchemaProvenance.md')
        manifest = {"configuration": configuration, "architecture": "arm64",
                    "sourceCommit": run(["/usr/bin/git", "rev-parse", "HEAD"], capture=True, cwd=REPO).strip(),
                    "sourceTrackedDirty": bool(run(["/usr/bin/git", "diff", "--name-only", "HEAD"], capture=True, cwd=REPO).strip()),
                    "minimumOSFromMachO": ".".join(map(str, max(versions))), "declaredMinimumOS": declared_target, "native": native_metadata,
                    "version": info["CFBundleShortVersionString"], "build": info["CFBundleVersion"],
                    "appIconSHA256": hashlib.sha256(icon.read_bytes()).hexdigest(),
                    "appIconAssetsSHA256": hashlib.sha256((app / "Contents/Resources/Assets.car").read_bytes()).hexdigest(),
                    "signing": ("ad-hoc only; no Developer ID, hardened runtime or notarization" if signing_mode == 'adhoc' else "unsigned staging; not runtime or distribution qualified"),
                    "external": "User-installed PKCS#11 middleware for signing/discovery; bundled OpenSSL for unified verification; system /usr/bin/openssl for legacy verify-cades"}
        # Inner dylibs, helpers, main executable, then the enclosing bundle.
        ordered = sorted(files.values(), key=lambda p: (p.parent.name != "Frameworks", p.parent.name == "MacOS", str(p)))
        sealed = seal_code(ordered, app, signing_mode)
        if public_beta:
            manifest.update(distributionChannel='public-beta-staging', publicationQualified=False,
                            trustProbe=trust_probe, distributionPrerequisites=readiness)
        manifest['signingMode'] = signing_mode
        # Signing the enclosing app changes its main executable's signature.
        # A sealed manifest cannot self-hash that signature without a cycle.
        manifest["nestedCodeSHA256"] = {str(p.relative_to(app)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in ordered if p.parent.name != "MacOS"}
        manifest["mainExecutableIntegrity"] = ("Covered by the enclosing app code signature" if sealed else "Unsigned; content hash only, no authenticity assertion")
        if not sealed:
            manifest['mainExecutableSHA256'] = hashlib.sha256((app / 'Contents/MacOS/Signum').read_bytes()).hexdigest()
        (app / "Contents/Resources/BuildManifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for path in app.rglob("*"):
            if path.is_file():
                portable(path.read_bytes())
        if sealed:
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", app])
            run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app])
        for relative, digest in manifest["nestedCodeSHA256"].items():
            if hashlib.sha256((app / relative).read_bytes()).hexdigest() != digest:
                raise ValueError("Nested code changed during enclosing bundle signing")
        for path in app.rglob("*"):
            if path.is_file():
                portable(path.read_bytes())
        mock = native_build / "libsignum-pades-policy-mock.so"
        if sealed:
            smoke(app, mock)
        if sealed and not tested_preview:
            run([native_build / "signum-pades-tests", "--helper-integration",
             app / "Contents/Helpers/signum-pades-local", mock], cwd=REPO, env=env)
        # Relocation checks resolve dependencies from the bundle, not the source prefix.
        relocated = stage / "Relocated" / "Signum.app"
        shutil.copytree(app, relocated, symlinks=True)
        if sealed:
            run(["/usr/bin/codesign", "--verify", "--deep", "--strict", relocated])
            smoke(relocated, mock)
        if sealed and not tested_preview:
            run([native_build / "signum-pades-tests", "--helper-integration",
             relocated / "Contents/Helpers/signum-pades-local", mock], cwd=REPO, env=env)
        if public_beta and (run(['/usr/bin/git', 'status', '--short', '--ignored'], capture=True, cwd=REPO).strip() or
                            run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True, cwd=REPO).strip() != frozen_commit):
            raise ValueError('Source changed before staging publication')
        replace_exclusive(app, output)
        print(("Verified local ad-hoc bundle: " if sealed else "Unsigned staging bundle; not execution-qualified: ") + str(output), flush=True)
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
    parser.add_argument('--scratch-root', type=Path)
    parser.add_argument('--signing-mode', choices=('adhoc', 'none'), default='adhoc')
    parser.add_argument('--public-beta-build', type=int)
    parser.add_argument('--bundle-id')
    parser.add_argument('--trust-probe', choices=('include', 'exclude'))
    options = parser.parse_args()
    build(options.output, options.configuration, options.native_prefix, options.cmake.absolute(),
          scratch_root=options.scratch_root, signing_mode=options.signing_mode,
          public_beta_build=options.public_beta_build, bundle_id=options.bundle_id, trust_probe=options.trust_probe)
