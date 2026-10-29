#!/usr/bin/env python3
"""Local Build 12A validation/package driver. Never runs a mutating token test."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--native-prefix", type=Path, required=True)
parser.add_argument("--cmake", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--collect-public-inventory", action="store_true")
args = parser.parse_args()
if platform.system() != "Darwin" or platform.machine() != "arm64":
    raise SystemExit("Richiede il Mac Apple Silicon di sviluppo, Xcode e le dipendenze native della Build 11.")
prefix, cmake, output = args.native_prefix.resolve(), args.cmake.resolve(), args.output.resolve()
if not prefix.is_dir() or not cmake.is_file():
    raise SystemExit("Dipendenze native o CMake non disponibili.")
output.mkdir(mode=0o700, parents=True, exist_ok=False)
env = {"PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"], "LC_ALL": "C",
       "PKG_CONFIG_PATH": str(prefix/"lib/pkgconfig"), "PKG_CONFIG_LIBDIR": str(prefix/"lib/pkgconfig"),
       "MACOSX_DEPLOYMENT_TARGET": "13.0"}

# Xcode may use an already installed private-framework runtime for actool.
# Inherit it only for the build subprocess; never for hardware/preflight tools.
build_env = dict(env)
if os.environ.get("DYLD_FRAMEWORK_PATH"):
    build_env["DYLD_FRAMEWORK_PATH"] = os.environ["DYLD_FRAMEWORK_PATH"]

def run(label, command, environment=None):
    print(label, flush=True)
    with (output/(label+".log")).open("wb") as log:
        subprocess.run([str(x) for x in command], cwd=root, env=environment or env, stdout=log, stderr=subprocess.STDOUT, check=True)

for configuration in ["debug", "release"]:
    run("synthetic-"+configuration, [sys.executable, root/"Tools/PINManagementTests/run.py", "--configuration", configuration])
    run("bundle-"+configuration, [sys.executable, root/"scripts/build-preview-app.py",
        "--version", "0.7.0", "--build-number", "14", "--configuration", configuration,
        "--native-prefix", prefix, "--cmake", cmake, "--output", output/("Signum-Build-12A-"+configuration+".app")], environment=build_env)
    # Same sources/dependency environment; assert eight new Swift contracts.
    run("swift-pin-tests-"+configuration, ["/usr/bin/swift", "test", "-c", configuration,
        "--scratch-path", root/(".build/preview-package13-"+configuration),
        "--triple", "arm64-apple-macosx13.0", "-Xlinker", "-rpath", "-Xlinker", prefix/"lib",
        "--filter", "PINManagementFoundationTests"])
run("build-metadata", [sys.executable, root/"Tools/PINManagementTests/test_metadata.py"])
if args.collect_public_inventory:
    bins = subprocess.check_output(["/usr/bin/swift", "build", "-c", "release", "--scratch-path",
        root/".build/preview-package13-release", "--triple", "arm64-apple-macosx13.0", "--show-bin-path"],cwd=root,env=env,text=True).strip()
    # The packager builds the package's executable products, including this
    # public-only tool and its sibling supervised PKCS#11 worker.
    with (output/"PIN-public-inventory.json").open("wb") as report:
        subprocess.run([str(Path(bins)/"SignumPINPreflight")],cwd=root,env=env,stdout=report,check=True,timeout=300)
    with (output/"PIN-installation-inventory.json").open("wb") as report:
        subprocess.run([sys.executable,str(root/"Tools/PINManagementTests/macos_inventory.py"),str(output/"PIN-public-inventory.json")],
                       cwd=root,env=env,stdout=report,check=True,timeout=300)
(output/"validation-status.json").write_text(json.dumps({"schema":1,"nativeDebugRelease":"passed",
    "swiftPINContracts":"passed", "packagedDebugRelease":"passed", "publicInventory":args.collect_public_inventory,
    "screenshots":"manual-pending", "uiRegression":"manual-pending", "hardwareMutation":"prohibited"},indent=2)+"\n")
print("Compilazioni e contratti completati. Restano screenshot e regressioni GUI; nessuna prova mutante hardware.")
