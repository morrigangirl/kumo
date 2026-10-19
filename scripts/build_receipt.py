#!/usr/bin/env python3
"""Local provenance for a completed, signed Chromium source build.

The source driver records this only after Ninja and upstream signing succeed.
Packaging checks the original bytes, then embeds a path-free copy under its
code signature. Re-signing changes executable hashes, so embedded hashes record
the checked source outputs, not the final signed bytes. This prevents accidental
stale/arbitrary input claims; it is not an attestation against a workspace owner
who can modify this code, source, or receipt.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import tempfile


class ReceiptError(RuntimeError):
    """A source receipt is missing, stale, malformed, or does not match outputs."""


_SHA = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"\d+\.\d+\.\d+\.\d+")
_KIND = "kumo-chromium-source-build"
_FIELDS = frozenset({
    "schema", "kind", "chromiumVersion", "completedAt", "sourceLockSha256",
    "sourceInputsSha256", "gnArgsSha256", "engineMachOSha256",
    "frameworkMachOSha256", "infoPlistSha256", "frameworkInfoPlistSha256",
    "engineExecutablePath", "frameworkExecutablePath", "frameworkInfoPlistPath",
    "receiptSha256",
})
_HASH_FIELDS = frozenset(name for name in _FIELDS if name.endswith("Sha256"))
_MAIN = "Contents/MacOS/Chromium"
_FRAMEWORK = "Contents/Frameworks/Chromium Framework.framework"


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checksum(receipt):
    value = {key: item for key, item in receipt.items() if key != "receiptSha256"}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def _check_sha(value, name):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ReceiptError(f"Invalid source receipt {name}.")
    return value


def _inside(app, relative):
    path = (app / relative).resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(app):
        raise ReceiptError("Source receipt artifact resolves outside its application bundle.")
    return path


def _info(path):
    value = plistlib.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ReceiptError("Invalid source engine Info.plist.")
    return value


def _mach_o(path, file_type):
    with path.open("rb") as handle:
        header = handle.read(32)
    if len(header) != 32 or header[:4] != b"\xcf\xfa\xed\xfe":
        raise ReceiptError("Source engine must contain thin arm64 Mach-O executables.")
    words = struct.unpack("<8I", header)
    if words[1] != 0x0100000c or words[3] != file_type:
        raise ReceiptError("Source engine Mach-O architecture or executable role is incorrect.")


def _artifacts(app):
    app = Path(app).resolve(strict=True)
    if not app.is_dir() or app.suffix != ".app":
        raise ReceiptError("A source receipt requires a Chromium.app bundle.")
    info_path = _inside(app, "Contents/Info.plist")
    info = _info(info_path)
    version = info.get("CFBundleShortVersionString")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ReceiptError("Source engine is missing its full four-part Chromium version.")
    if info.get("CFBundleExecutable") != "Chromium":
        raise ReceiptError("Source engine bundle must use the Chromium executable.")
    main = _inside(app, _MAIN)
    framework_info_path = _inside(app, _FRAMEWORK + "/Resources/Info.plist")
    framework_info = _info(framework_info_path)
    if framework_info.get("CFBundleExecutable") != "Chromium Framework":
        raise ReceiptError("Source engine framework executable is incorrect.")
    if framework_info.get("CFBundleShortVersionString") != version:
        raise ReceiptError("Source engine and framework versions differ.")
    framework = _inside(app, _FRAMEWORK + "/Chromium Framework")
    _mach_o(main, 2)       # MH_EXECUTE
    _mach_o(framework, 6)  # MH_DYLIB
    return {
        "chromiumVersion": version,
        "engineExecutablePath": main.relative_to(app).as_posix(),
        "frameworkExecutablePath": framework.relative_to(app).as_posix(),
        "frameworkInfoPlistPath": framework_info_path.relative_to(app).as_posix(),
        "engineMachOSha256": _sha(main),
        "frameworkMachOSha256": _sha(framework),
        "infoPlistSha256": _sha(info_path),
        "frameworkInfoPlistSha256": _sha(framework_info_path),
    }


def _source(repo_root, input_digest):
    _check_sha(input_digest, "sourceInputsSha256")
    lock_path = Path(repo_root).resolve() / "config/source-lock.json"
    lock = json.loads(lock_path.read_text())
    if not isinstance(lock, dict):
        raise ReceiptError("The current source lock is not a JSON object.")
    version = lock.get("chromiumVersion")
    if type(lock.get("schema")) is not int or lock.get("schema") != 1 or lock.get("targetCpu") != "arm64" or not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ReceiptError("The current source lock is not a supported arm64 Chromium lock.")
    return version, _sha(lock_path)


def _validate(receipt, *, embedded):
    expected = _FIELDS if embedded else _FIELDS | {"engineAppPath"}
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise ReceiptError("Source receipt has unexpected or missing fields.")
    if type(receipt["schema"]) is not int or receipt["schema"] != 1 or receipt["kind"] != _KIND:
        raise ReceiptError("Unsupported source receipt schema or kind.")
    if not isinstance(receipt["chromiumVersion"], str) or not _VERSION.fullmatch(receipt["chromiumVersion"]):
        raise ReceiptError("Invalid source receipt Chromium version.")
    for name in _HASH_FIELDS:
        _check_sha(receipt[name], name)
    if receipt["receiptSha256"] != _checksum(receipt):
        raise ReceiptError("Source receipt checksum does not match its contents.")
    stamp = receipt["completedAt"]
    if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stamp):
        raise ReceiptError("Invalid source receipt completion timestamp.")
    try:
        completed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ReceiptError("Invalid source receipt completion timestamp.") from error
    if completed > datetime.now(timezone.utc):
        raise ReceiptError("Source receipt completion timestamp is in the future.")
    if receipt["engineExecutablePath"] != _MAIN:
        raise ReceiptError("Invalid source receipt main executable path.")
    framework_versions = []
    for key, ending in (("frameworkExecutablePath", "/Chromium Framework"),
                        ("frameworkInfoPlistPath", "/Resources/Info.plist")):
        value = receipt[key]
        # Resolve framework aliases once when recording; support upstream's
        # versioned layout without accepting arbitrary external paths.
        if not isinstance(value, str) or not re.fullmatch(re.escape(_FRAMEWORK) + r"/Versions/[A-Za-z0-9._-]+" + re.escape(ending), value):
            raise ReceiptError("Invalid source receipt framework artifact path.")
        component = value.removeprefix(_FRAMEWORK + "/Versions/").split("/", 1)[0]
        if component in (".", ".."):
            raise ReceiptError("Invalid source receipt framework version directory.")
        framework_versions.append(component)
    if len(set(framework_versions)) != 1:
        raise ReceiptError("Source receipt framework artifacts use different version directories.")
    if not embedded:
        path = receipt["engineAppPath"]
        if not isinstance(path, str) or not Path(path).is_absolute() or str(Path(path).resolve()) != path:
            raise ReceiptError("Invalid source receipt application path.")
    return receipt


def default_receipt_path(app):
    app = Path(app).resolve()
    return app.with_name(app.name + ".kumo-build-receipt.json")


def current_input_digest(repo_root):
    """Call only the trusted local source driver's pure input_digest function.

    Loading with a non-__main__ module name cannot run its CLI/build main guard.
    The source driver calls record_build with its digest directly instead.
    """
    path = Path(repo_root).resolve() / "scripts/source.py"
    spec = importlib.util.spec_from_file_location("_kumo_receipt_source_inputs", path)
    if spec is None or spec.loader is None:
        raise ReceiptError("Cannot load the source input fingerprint function.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    callback = getattr(module, "input_digest", None)
    if not callable(callback):
        raise ReceiptError("Source driver has no input fingerprint function.")
    return _check_sha(callback(), "sourceInputsSha256")


def invalidate_receipt(app, receipt_path=None):
    """Remove a previous success marker before a build may modify its outputs."""
    path = Path(receipt_path) if receipt_path is not None else default_receipt_path(app)
    path.unlink(missing_ok=True)


def record_build(app, repo_root, input_digest, gn_args, *, receipt_path=None):
    """Record outputs; the source driver owns the successful-build precondition."""
    app = Path(app).resolve(strict=True)
    version, lock_sha = _source(repo_root, input_digest)
    outputs = _artifacts(app)
    if outputs["chromiumVersion"] != version:
        raise ReceiptError("Built engine version does not match the current source lock.")
    receipt = {
        "schema": 1, "kind": _KIND,
        "completedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceLockSha256": lock_sha, "sourceInputsSha256": input_digest,
        "gnArgsSha256": _sha(gn_args), "engineAppPath": str(app), **outputs,
    }
    receipt["receiptSha256"] = _checksum(receipt)
    _validate(receipt, embedded=False)
    path = Path(receipt_path) if receipt_path is not None else default_receipt_path(app)
    path = path.absolute()
    # The receipt must not invalidate the source app's sealed resource contents.
    if path.resolve().is_relative_to(app):
        raise ReceiptError("Store the build receipt outside the signed app bundle.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".kumo-receipt-", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(receipt, handle, sort_keys=True, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return receipt


def verify_artifact_hashes(app, receipt):
    """Check source output bytes, including a staged copy before re-signing."""
    _validate(receipt, embedded=not isinstance(receipt, dict) or "engineAppPath" not in receipt)
    actual = _artifacts(app)
    if any(receipt[key] != value for key, value in actual.items()):
        raise ReceiptError("Source engine output hashes, paths, or version no longer match the completed build.")


def verify_embedded_receipt(receipt, repo_root, input_digest, engine_version):
    """Validate signed, path-free provenance against this checkout's inputs."""
    _validate(receipt, embedded=True)
    version, lock_sha = _source(repo_root, input_digest)
    if receipt["chromiumVersion"] != version or engine_version != version:
        raise ReceiptError("Source receipt engine version does not match the current source lock.")
    if receipt["sourceLockSha256"] != lock_sha or receipt["sourceInputsSha256"] != input_digest:
        raise ReceiptError("Source receipt does not match the current source lock and build inputs.")
    return dict(receipt)


def verify_receipt(app, repo_root, input_digest, receipt_path=None):
    """Verify original build outputs and return sanitized embeddable provenance."""
    app = Path(app).resolve(strict=True)
    path = Path(receipt_path) if receipt_path is not None else default_receipt_path(app)
    if not path.is_file():
        raise ReceiptError("No successful local source-build receipt exists for this engine. Run scripts/source.py build first.")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ReceiptError("Source build receipt is not valid JSON.") from error
    _validate(receipt, embedded=False)
    if receipt["engineAppPath"] != str(app):
        raise ReceiptError("Source receipt belongs to a different application path.")
    verify_artifact_hashes(app, receipt)
    sanitized = {key: value for key, value in receipt.items() if key != "engineAppPath"}
    sanitized["receiptSha256"] = _checksum(sanitized)
    return verify_embedded_receipt(sanitized, repo_root, input_digest, receipt["chromiumVersion"])
