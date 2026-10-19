#!/usr/bin/env python3
"""Authenticate/extract ClamAV locally for build QA. Does not run Installer or install system files.

Production setup is the native KumoMalwareSetup tool; no Python is needed by users.
--qa-relocate modifies/signs an isolated workspace copy only, never a production runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/clamav-lock.json"

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()

def command(arguments, timeout=120, env=None):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, timeout=timeout, env=env)
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    if result.returncode: raise RuntimeError(f"{Path(str(arguments[0])).name} failed ({result.returncode}): {text[-2000:]}")
    return text

def prepare(output, qa_relocate=False, definitions=False):
    lock = json.loads(LOCK.read_text()); output = output.resolve()
    if qa_relocate and not output.is_relative_to(ROOT / "build"):
        raise RuntimeError("QA relocation is limited to this repository's build directory")
    output.mkdir(parents=True, exist_ok=True, mode=0o700); output.chmod(0o700)
    cache = ROOT / "build/clamav-downloads"; cache.mkdir(parents=True, exist_ok=True)
    package = cache / f"clamav-{lock['version']}.macos.universal.pkg"
    if not package.exists() or digest(package) != lock["packageSHA256"]:
        partial = package.with_suffix(".partial")
        with urllib.request.urlopen(lock["packageURL"], timeout=60) as response, partial.open("wb") as handle:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > lock["packageBytes"]: raise RuntimeError("Package download exceeded pinned length")
                handle.write(block)
        if digest(partial) != lock["packageSHA256"] or partial.stat().st_size != lock["packageBytes"]:
            partial.unlink(missing_ok=True); raise RuntimeError("Package hash/size mismatch")
        partial.replace(package)
    signature = command(["/usr/sbin/pkgutil", "--check-signature", package])
    normalized = "".join(signature.split())
    if f"Developer ID Installer: Cisco ({lock['installerTeamID']})" not in signature or lock["installerLeafSHA256"] not in normalized:
        raise RuntimeError("Unexpected Apple installer signer")
    runtime = output / "runtime"
    if runtime.exists(): raise RuntimeError(f"Refusing to overwrite existing runtime: {runtime}")
    with tempfile.TemporaryDirectory(prefix="clamav-extract-", dir=output) as temporary:
        extracted = Path(temporary) / "payload"
        command(["/usr/sbin/pkgutil", "--expand-full", package, extracted])
        for kind in ["programs", "libraries"]:
            source = extracted / f"clamav-{lock['version']}.macos.universal-{kind}.pkg/Payload/usr/local/clamav"
            shutil.copytree(source, runtime, dirs_exist_ok=True, symlinks=True)
    for entry in lock["files"]:
        path = runtime / entry["path"]
        if "symlink" in entry:
            if not path.is_symlink() or str(path.readlink()) != entry["symlink"]: raise RuntimeError("Vendor alias mismatch")
        elif path.is_symlink() or digest(path) != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            raise RuntimeError("Vendor payload hash mismatch")
    (output / "installer-signature.txt").write_text(signature)
    receipt = {"version": lock["version"], "packageSHA256": lock["packageSHA256"], "installerTeamID": lock["installerTeamID"],
               "productionRuntimeModified": False, "qaOnly": qa_relocate, "productionInstallPrefix": lock["installPrefix"]}
    if qa_relocate:
        identity, _ = runpy.run_path(str(ROOT / "scripts/package.py"))["development_identity"]()
        old = b"/usr/local/clamav/lib"; new = b"@loader_path/../lib"
        for entry in lock["files"]:
            if "symlink" in entry or not (entry["path"].startswith("bin/") or entry["path"].endswith(".dylib")): continue
            path = runtime / entry["path"]; data = bytearray(path.read_bytes()); offset = 0
            while (offset := data.find(old, offset)) >= 0:
                if data[offset + len(old)] == 0: data[offset:offset+len(old)] = new + b"\0" * (len(old)-len(new))
                offset += len(old)
            path.write_bytes(data)
            command(["/usr/bin/codesign", "--force", "--sign", identity, "--timestamp=none", "--options", "runtime", "--identifier", path.name, path])
        qa_lock = json.loads(json.dumps(lock))
        for entry in qa_lock["files"]:
            if "sha256" in entry: entry["sha256"] = digest(runtime / entry["path"]); entry["bytes"] = (runtime / entry["path"]).stat().st_size
        (output / "qa-lock.json").write_text(json.dumps(qa_lock, indent=2) + "\n")
        receipt["qaModification"] = "Fixed user-local rpath; Apple Development signing. Never used by production installer/scanner."
    if definitions:
        if not qa_relocate: raise RuntimeError("The unmodified package requires its official /usr/local/clamav install; use --qa-relocate for isolated tests")
        database = output / "database"; database.mkdir(mode=0o700, exist_ok=True); database.chmod(0o700)
        config = output / "freshclam.conf"
        config.write_text(f'DatabaseDirectory "{database}"\nDatabaseMirror https://database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\nCVDCertsDirectory "{runtime}/etc/certs"\nScriptedUpdates no\nTestDatabases yes\nBytecode yes\nMaxAttempts 1\nConnectTimeout 20\nReceiveTimeout 60\n'); config.chmod(0o600)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C", "CVD_CERTS_DIR": str(runtime / "etc/certs")}
        try: result = command([runtime / "bin/freshclam", "--config-file=" + str(config), "--stdout"], timeout=600, env=env)
        except Exception as error:
            (output / "freshclam.log").write_text(str(error)); raise
        (output / "freshclam.log").write_text(result)
        for name in ["main", "daily", "bytecode"]:
            command([runtime / "bin/sigtool", "--verify", database / (name + ".cvd"), "--cvdcertsdir", runtime / "etc/certs"], env=env)
        receipt["officialDetachedSignaturesVerified"] = True
    (output / "preparation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/clamav-runtime")
    parser.add_argument("--qa-relocate", action="store_true")
    parser.add_argument("--definitions", action="store_true")
    options = parser.parse_args()
    print(json.dumps(prepare(options.output, options.qa_relocate, options.definitions), indent=2))
