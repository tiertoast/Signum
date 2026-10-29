#!/usr/bin/env python3
"""Offline synthetic test build. No installed middleware, environment or token."""
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import argparse

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--configuration", choices=["debug", "release"], default="debug")
args = parser.parse_args()
optimization = ["-O0", "-g"] if args.configuration == "debug" else ["-O2"]
cc = os.environ.get("CC", "cc")
includes = ["-I"+str(root/p) for p in ["Sources/CSecurePIN/include", "Sources/CPINManagement/include", "Sources/CPKCS11", "Tools/PKCS11Tests"]]
with tempfile.TemporaryDirectory(prefix="signum-pin-admin-") as folder:
    stage = Path(folder)
    common = [cc,"-std=c11","-D_DEFAULT_SOURCE","-DSIGNUM_PIN_ADMIN_TESTING","-DSIGNUM_MOCK_PIN_ADMIN","-Wall","-Wextra","-Werror","-Wno-misleading-indentation","-pthread",*optimization,*includes]
    subprocess.run([*common,"-Dmlock=sg_pin_test_mlock","-c",str(root/"Sources/CSecurePIN/secure_pin.c"),"-o",str(stage/"secure.o")],check=True)
    subprocess.run([*common,"-include",str(root/"Tools/PINManagementTests/portable_mock.h"),"-c",str(root/"Tools/PKCS11Tests/mock_provider.c"),"-o",str(stage/"mock.o")],check=True)
    subprocess.run([*common,str(root/"Tools/PINManagementTests/admin_tests.c"),str(root/"Sources/CPINManagement/pin_management.c"),str(stage/"secure.o"),str(stage/"mock.o"),"-o",str(stage/"admin-tests")],check=True)
    subprocess.run([str(stage/"admin-tests")],check=True,timeout=30)
    # Product object has no test accessor, vendor import, loader or mutation API.
    subprocess.run([cc,"-std=c11","-D_DEFAULT_SOURCE",*includes,"-c",str(root/"Sources/CPINManagement/pin_management.c"),"-o",str(stage/"product.o")],check=True)
    symbols = subprocess.check_output(["nm",str(stage/"product.o")],text=True)
    for forbidden in ["sg_pin_test_","C_SetPIN","C_InitPIN","C_InitToken","C_Login","dlopen","dlsym","mock_"]:
        if forbidden in symbols:
            raise SystemExit("Unexpected product symbol: "+forbidden)
    print("PASS product object: no synthetic backend or mutating middleware symbols")
    coordination = root/"Sources/CProcessCoordination"
    flags = ["-I"+str(coordination/"include")]
    if sys.platform != "darwin":
        flags += ["-I"+str(root/"Tools/PINManagementTests/portable_stubs"),"-Dconfstr=sg_test_confstr","-D_CS_DARWIN_USER_TEMP_DIR=0","-DO_NOFOLLOW_ANY=O_NOFOLLOW"]
        extra = []
    else:
        flags += ["-I"+str(root/"Sources/COutputPermissions/include")]
        extra = [str(root/"Sources/COutputPermissions/output_permissions.c")]
    subprocess.run([cc,"-std=c11","-D_DEFAULT_SOURCE","-pthread","-Wall","-Wextra","-Werror","-Wno-misleading-indentation",*flags,
        str(coordination/"process_coordination.c"),str(root/"Tools/PINManagementTests/barrier_tests.c"),*extra,"-o",str(stage/"barrier-tests")],check=True)
    subprocess.run([str(stage/"barrier-tests"),str(stage)],check=True,timeout=15)
    platform = ["-dynamiclib", "-undefined", "dynamic_lookup"] if sys.platform == "darwin" else ["-shared","-fPIC"]
    mock = stage/("synthetic-provider.dylib" if sys.platform == "darwin" else "synthetic-provider.so")
    subprocess.run([*common,*platform,"-include",str(root/"Tools/PINManagementTests/portable_mock.h"),
        str(root/"Tools/PKCS11Tests/mock_provider.c"),"-o",str(mock)],check=True)
    export = ["-Wl,-export_dynamic"] if sys.platform == "darwin" else ["-Wl,--export-dynamic","-ldl"]
    subprocess.run([*common,"-I"+str(root/"Sources/CPKCS11/include"),"-I"+str(root/"Sources/CCertificatePolicy/include"),
        str(root/"Tools/PINManagementTests/public_info_tests.c"),str(root/"Sources/CPKCS11/pkcs11_shim.c"),*export,"-o",str(stage/"public-info-tests")],check=True)
    subprocess.run([str(stage/"public-info-tests"),str(mock)],check=True,timeout=15)
