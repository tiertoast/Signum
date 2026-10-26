#!/usr/bin/env python3
"""Collect public installation metadata; no credential or token command."""
import hashlib
import json
import plistlib
from pathlib import Path
import platform
import subprocess
import sys

def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, timeout=15).stdout

if sys.platform != "darwin" or len(sys.argv) != 2:
    raise SystemExit("Richiede macOS e il percorso del JSON prodotto da SignumPINPreflight.")
inventory = json.loads(Path(sys.argv[1]).read_text())
if inventory.get("schema") != "signum-pin-public-inventory-v1":
    raise SystemExit("Schema inventario non valido")
receipts = []
for identifier in run(["/usr/sbin/pkgutil", "--pkgs"]).decode().splitlines():
    if not any(name in identifier.lower() for name in ["opensc", "bit4id", "digitaldna"]):
        continue
    try:
        metadata = plistlib.loads(run(["/usr/sbin/pkgutil", "--pkg-info-plist", identifier]))
        receipts.append({key: metadata.get(key) for key in ["pkgid", "pkg-version", "install-time", "volume", "install-location"]})
    except Exception:
        receipts.append({"pkgid": identifier, "status": "receiptUnavailable"})
modules = []
seen = set()
for entry in inventory["entries"]:
    path = entry.get("canonicalPath")
    if not path or path in seen:
        continue
    seen.add(path)
    item = {"path": path, "reportedVersion": entry.get("reportedVersion"), "observedIdentity": entry.get("identity")}
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as module:
            for block in iter(lambda: module.read(1024 * 1024), b""):
                digest.update(block)
        item["sha256"] = digest.hexdigest()
        for key, command in [("codeSignature", ["/usr/bin/codesign", "-d", "--verbose=2", path]),
                             ("linkedLibraries", ["/usr/bin/otool", "-L", path])]:
            result = subprocess.run(command, capture_output=True, timeout=15)
            item[key] = (result.stdout + result.stderr).decode(errors="replace")[:32768]
            item[key+"ExitStatus"] = result.returncode
    except Exception:
        item["status"] = "installationMetadataUnavailable"
    modules.append(item)
print(json.dumps({"schema": "signum-pin-installation-inventory-v1", "macOS": platform.mac_ver()[0],
                  "architecture": platform.machine(), "packageReceipts": receipts, "modules": modules,
                  "notice": "Receipt, firma del codice e versione dichiarata sono evidenze distinte; nessuna capacità PIN/PUK qualificata."}, indent=2))
