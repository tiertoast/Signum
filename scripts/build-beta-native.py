#!/usr/bin/env python3
"""Offline, private native prefix. Never installs globally or reuses Alpha builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[1]


def deployment_target():
    target = plistlib.loads((REPO / "Resources/Info.plist").read_bytes())["LSMinimumSystemVersion"]
    if target not in ("13.0", "14.0"):
        raise ValueError("Unreviewed macOS deployment target")
    return target


ARCHIVES = {
    "openssl": ("openssl.tar.gz", "openssl-3.5.4", "967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99"),
    "freetype": ("freetype.tar.xz", "freetype-2.13.3", "0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289"),
    "podofo": ("podofo.tar.gz", "podofo-1.1.2", "d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a"),
}


def run(args, cwd, env):
    subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True)


def build(output, cmake):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("This local recipe currently requires macOS arm64")
    target = deployment_target()
    # Check all inputs before reserving an exclusively new output tree.
    for archive, _, digest in ARCHIVES.values():
        path = REPO / ".build/native-src" / archive
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Missing or unexpected pinned source archive: " + archive)
    output = output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = output / "sources"
    sources.mkdir()
    for archive, dirname, _ in ARCHIVES.values():
        with tarfile.open(REPO / ".build/native-src" / archive) as source:
            for entry in source.getmembers():
                # Hash-pinned inputs, with traversal/device protection as well.
                dest = (sources / entry.name).resolve()
                if sources not in dest.parents or entry.isdev():
                    raise ValueError("Unsafe archive entry")
                if entry.issym() or entry.islnk():
                    link = (dest.parent / entry.linkname).resolve() if entry.issym() else (sources / entry.linkname).resolve()
                    if sources not in link.parents:
                        raise ValueError("Unsafe archive link")
            source.extractall(sources)
        if not (sources / dirname).is_dir():
            raise ValueError("Unexpected source layout")
    prefix = output / "prefix"
    sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    # No Homebrew search paths, inherited compiler flags, or runtime DYLD overrides.
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"],
           "SDKROOT": sdk, "MACOSX_DEPLOYMENT_TARGET": target,
           "PKG_CONFIG_LIBDIR": "/nonexistent", "LC_ALL": "C"}
    sslbuild = output / "openssl-build"
    sslbuild.mkdir()
    # Relative source path keeps __FILE__ and OpenSSL compiler metadata portable.
    # Configure's prefix is a logical staging prefix, never installed at root.
    run(["/usr/bin/perl", "../sources/openssl-3.5.4/Configure", "darwin64-arm64-cc",
         "--prefix=/signum-native", "--openssldir=/etc/ssl", "no-shared", "no-tests",
         "no-module", "no-engine", "-mmacosx-version-min=" + target], sslbuild, env)
    run(["/usr/bin/make", "-j6"], sslbuild, env)
    stage = output / "openssl-install"
    run(["/usr/bin/make", "install_sw", "DESTDIR=" + str(stage)], sslbuild, env)
    (stage / "signum-native").rename(prefix)

    flags = "-ffile-prefix-map=" + str(REPO) + "=."
    common = ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
              "-DCMAKE_PREFIX_PATH=" + str(prefix), "-DCMAKE_OSX_DEPLOYMENT_TARGET=" + target,
              "-DCMAKE_OSX_ARCHITECTURES=arm64", "-DCMAKE_C_FLAGS=" + flags,
              "-DCMAKE_CXX_FLAGS=" + flags, "-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local",
              "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF", "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF",
              "-DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=TRUE", "-DCMAKE_OSX_SYSROOT=" + sdk]

    def library(name, options):
        folder = output / (name + "-build")
        run([cmake, "-S", sources / ARCHIVES[name][1], "-B", folder] + common + options, REPO, env)
        run([cmake, "--build", folder, "--parallel", "6"], REPO, env)
        run([cmake, "--install", folder], REPO, env)

    library("freetype", ["-DBUILD_SHARED_LIBS=OFF", "-DFT_DISABLE_HARFBUZZ=ON",
                        "-DFT_DISABLE_BROTLI=ON", "-DFT_DISABLE_BZIP2=ON", "-DFT_DISABLE_PNG=ON"])
    library("podofo", ["-DPODOFO_BUILD_LIB_ONLY=ON", "-DPODOFO_BUILD_STATIC=OFF",
                       "-DPODOFO_WITH_FONTMANAGER=OFF", "-DPODOFO_WITH_AFDKO=OFF",
                       "-DOPENSSL_ROOT_DIR=" + str(prefix), "-DOPENSSL_USE_STATIC_LIBS=TRUE",
                       "-DFREETYPE_LIBRARY_RELEASE=" + str(prefix / "lib/libfreetype.a"),
                       "-DFREETYPE_INCLUDE_DIRS=" + str(prefix / "include/freetype2"),
                       "-DCMAKE_DISABLE_FIND_PACKAGE_JPEG=TRUE", "-DCMAKE_DISABLE_FIND_PACKAGE_PNG=TRUE",
                       "-DCMAKE_DISABLE_FIND_PACKAGE_TIFF=TRUE", "-DCMAKE_DISABLE_FIND_PACKAGE_LCMS2=TRUE",
                       "-DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=TRUE"])
    notices = prefix / "share/signum-notices"
    notices.mkdir(parents=True)
    licenses = {"OpenSSL.txt": "openssl-3.5.4/LICENSE.txt",
                "PoDoFo-LGPL.txt": "podofo-1.1.2/COPYING.LGPL",
                "PoDoFo-MPL.txt": "podofo-1.1.2/COPYING.MPL",
                "FreeType-license.txt": "freetype-2.13.3/LICENSE.TXT",
                "FreeType-FTL.txt": "freetype-2.13.3/docs/FTL.TXT",
                "PoDoFo-PDFium.txt": "podofo-1.1.2/3rdparty/chromium/pdfium/LICENSE",
                "PoDoFo-numerics.txt": "podofo-1.1.2/3rdparty/chromium/numerics/LICENSE",
                "PoDoFo-LiberaLean.txt": "podofo-1.1.2/src/podofo/private/LiberaLean/LICENSE.txt",
                "PoDoFo-Foxit.txt": "podofo-1.1.2/src/podofo/private/FoxitFonts/COPYING.txt"}
    for name, source in licenses.items():
        (notices / name).write_bytes((sources / source).read_bytes())
    (prefix / "signum-native-build.json").write_text(json.dumps({
        "recipe": 1, "architecture": "arm64", "deploymentTarget": target,
        "sources": {name: {"version": value[1], "sha256": value[2]} for name, value in ARCHIVES.items()},
        "openssl": "static; no-module; no-engine; default provider built in; config /etc/ssl",
    }, indent=2) + "\n")
    print("Native prefix ready: " + str(prefix), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New private build directory; must not exist")
    parser.add_argument("--cmake", type=Path, default=REPO / ".build/native-tools/cmake/data/bin/cmake")
    options = parser.parse_args()
    build(options.output, options.cmake.absolute())
