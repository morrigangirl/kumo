#!/usr/bin/env python3
"""Package a native macOS preview, or a locally compiled Chromium.app.

The default runtime is an upstream binary, not a claim of a local Chromium build.
The verified app and nested Chromium code are re-signed consistently for development.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import runpy
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = "155.0.8059.39-1.1"
SHA256 = "1a71ee2aa987f471e5ba61e853a0d9aa4b634fa68213ad24df2e970b7729385b"
DOWNLOAD = f"https://github.com/ungoogled-software/ungoogled-chromium-macos/releases/download/{VERSION}/ungoogled-chromium_{VERSION}_arm64-macos.dmg"

def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def extension_id():
    public = base64.b64decode(json.loads((ROOT / "extension/manifest.json").read_text())["key"])
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(public).hexdigest()[:32])

def development_identity():
    config = json.loads((ROOT / "config/apple-signing.json").read_text())
    team = config["teamId"]
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise RuntimeError("Invalid configured Apple Developer team.")
    identities = subprocess.check_output(["security", "find-identity", "-v", "-p", "codesigning"], text=True)
    valid = set(re.findall(r'\b([0-9A-F]{40})\s+"Apple Development:', identities))
    pems = subprocess.check_output(["security", "find-certificate", "-a", "-p", "-c", "Apple Development:"], text=True)
    for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pems, re.S):
        digest = hashlib.sha1(base64.b64decode("".join(pem.splitlines()[1:-1]))).hexdigest().upper()
        if digest not in valid:
            continue
        subject = subprocess.check_output(["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"], input=pem, text=True)
        if re.search(r"(?:^|,)OU=" + re.escape(team) + r"(?:,|$)", subject.strip().removeprefix("subject=")):
            return digest, team
    raise RuntimeError("No valid Apple Development identity for the configured team. Run npm run check:signing; library validation cannot use an ad-hoc identity.")

def signature_policy(path, require_runtime=True, expected_team=None):
    details = subprocess.run(["codesign", "-d", "--verbose=3", str(path)], capture_output=True, text=True, check=True)
    match = re.search(r"\bflags=0x([0-9a-fA-F]+)\b", details.stderr)
    if not match:
        raise RuntimeError("Could not inspect the engine's signing policy.")
    # Ad-hoc and linker-signed status describe who made the signature; codesign
    # sets them itself. Retain the upstream runtime/restrict/library/kill policy.
    policy = int(match.group(1), 16) & ~0x20002
    if require_runtime and not policy & 0x10000:
        raise RuntimeError("The supplied engine is missing macOS hardened runtime.")
    if expected_team and not re.search(r"^TeamIdentifier=" + re.escape(expected_team) + r"$", details.stderr, re.M):
        raise RuntimeError("A packaged code signature belongs to the wrong Apple Developer team.")
    return policy

def remove_stale_tickets(app):
    """Remove inherited app notarization tickets before changing signatures.

    A stapled ticket belongs to the original CodeDirectory hashes. It lives at
    Contents/CodeResources, distinct from the resource seal inside
    Contents/_CodeSignature. Never follow aliases or remove legacy seal links.
    """
    removed = []
    for directory, directories, files in os.walk(app, followlinks=False):
        current = Path(directory)
        directories[:] = [name for name in directories if not (current / name).is_symlink()]
        if current.name != "Contents" or current.parent.suffix != ".app" or "CodeResources" not in files:
            continue
        ticket = current / "CodeResources"
        if not stat.S_ISREG(ticket.lstat().st_mode):
            continue
        with ticket.open("rb") as handle:
            if handle.read(4) != b"s8ch":
                continue
        ticket.unlink()
        removed.append(str(ticket.relative_to(app)))
    return removed

def resign_nested_code(destination, identity, team):
    # Library validation requires consistent signing of the engine and its
    # framework. Retaining another developer's framework signature while making
    # the main binary ad-hoc causes dyld to reject it. Keep every original role's
    # JIT entitlements and flags; do not disable library validation to evade this.
    root = destination / "Contents/Frameworks"
    bundles = [p for p in root.rglob("*") if not p.is_symlink() and p.is_dir() and p.suffix in (".app", ".framework")]
    bundle_mains = set()
    for bundle in bundles:
        plist = bundle / ("Contents/Info.plist" if bundle.suffix == ".app" else "Resources/Info.plist")
        info = plistlib.loads(plist.read_bytes())
        executable = bundle / ("Contents/MacOS" if bundle.suffix == ".app" else "") / info["CFBundleExecutable"]
        bundle_mains.add(executable.resolve())
    magics = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
    binaries = []
    for file in root.rglob("*"):
        if file.is_symlink() or not file.is_file() or file.resolve() in bundle_mains:
            continue
        with file.open("rb") as handle:
            if handle.read(4) in magics:
                binaries.append(file)
    for target in sorted(binaries, key=lambda p: len(p.parts), reverse=True) + sorted(bundles, key=lambda p: len(p.parts), reverse=True):
        policy = signature_policy(target, require_runtime=False)
        run("codesign", "--force", "--sign", identity, "--timestamp=none", "--preserve-metadata=identifier,entitlements,flags,runtime", target)
        if signature_policy(target, require_runtime=False, expected_team=team) != policy:
            raise RuntimeError("Re-signing changed a nested component's security policy.")

def verify_engine_start(destination):
    # Exercise dyld/library validation before publishing the staged app. Never
    # open the person's profile or Keychain as part of packaging.
    with tempfile.TemporaryDirectory(prefix="kumo-package-startup-") as profile:
        result = subprocess.run([str(destination / "Contents/MacOS/Chromium"),
            "--headless", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-sync", "--use-mock-keychain",
            "--password-store=basic", f"--user-data-dir={profile}", "--dump-dom", "about:blank"],
            capture_output=True, text=True, timeout=90)
        if result.returncode != 0 or "<html" not in result.stdout:
            raise RuntimeError("Staged engine failed its isolated startup check: " + result.stderr[-2500:])

def verified_phishing_resources(directory=None):
    """Verify prepared data before it enters the signed application resource seal."""
    directory = Path(directory) if directory else ROOT / "build/phishlang-model"
    try:
        info = json.loads((directory / "model-info.json").read_text())
        lock_bytes = (ROOT / "config/phishlang-model-lock.json").read_bytes()
        lock = json.loads(lock_bytes)
        if (info.get("schemaVersion") != 1 or info.get("sourceCommit") != lock["upstream"]["commit"] or
                info.get("modelVersion") != info.get("sourceCommit") or
                info.get("conversionLockSHA256") != hashlib.sha256(lock_bytes).hexdigest() or
                info.get("validation", {}).get("passed") is not True or
                info.get("computeUnits") != "cpuOnly" or info.get("windowSize") != 128 or
                info.get("stride") != 64 or info.get("precision") != "FLOAT32" or
                info.get("maxWindows") != 8 or info.get("classIndex") != 1):
            raise ValueError("Model provenance or interface differs from the lock")
        vocab = directory / "vocab.txt"
        expected_vocab = next(item["sha256"] for item in lock["upstream"]["artifacts"] if item["path"].endswith("/vocab.txt"))
        expected_weights = next(item["sha256"] for item in lock["upstream"]["artifacts"] if item["path"].endswith("/model.safetensors"))
        if vocab.is_symlink() or info["vocabSHA256"] != expected_vocab or digest(vocab) != expected_vocab:
            raise ValueError("Vocabulary hash mismatch")
        model = directory / "PhishLang.mlmodelc"
        if model.is_symlink() or not model.is_dir():
            raise ValueError("Compiled model is missing")
        manifest = []
        for path in sorted(model.rglob("*")):
            if path.is_symlink():
                raise ValueError("Model aliases are not accepted")
            if path.is_file():
                manifest.append({"path": path.relative_to(model).as_posix(), "bytes": path.stat().st_size, "sha256": digest(path)})
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        if (not manifest or manifest != info["modelFiles"] or sum(item["bytes"] for item in manifest) > 150_000_000 or
                hashlib.sha256(encoded).hexdigest() != info["modelDirectorySHA256"]):
            raise ValueError("Compiled model hashes differ from the validated conversion")
        if info["upstreamSafetensorsSHA256"] != expected_weights or digest(directory / "upstream/model.safetensors") != expected_weights:
            raise ValueError("Source weights differ from the validated conversion")
        return info
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise RuntimeError("PhishLang resources are missing or invalid. Run /usr/bin/python3 scripts/prepare-phishlang.py before packaging.") from error

def verify_phishing_start(destination):
    payload = json.dumps({"id": "package-probe", "type": "classify", "text": 'TITLE: { "text": "Public library hours" }'}).encode()
    helper = destination / "Contents/Helpers/KumoPhishing.app/Contents"
    result = subprocess.run([str(helper / "MacOS/KumoPhishingHost"), f"chrome-extension://{extension_id()}/"],
                            input=struct.pack("<I", len(payload)) + payload, capture_output=True, timeout=45)
    if result.returncode or len(result.stdout) < 4:
        raise RuntimeError("Sandboxed PhishLang host failed its isolated startup check.")
    length = struct.unpack("<I", result.stdout[:4])[0]
    if length > 262144 or len(result.stdout) != length + 4:
        raise RuntimeError("PhishLang host emitted an invalid Native Messaging frame.")
    reply = json.loads(result.stdout[4:])
    expected_version = json.loads((helper / "Resources/PhishLang/model-info.json").read_text())["modelVersion"]
    probability, windows, tokens = reply.get("probability"), reply.get("windows"), reply.get("tokenCount")
    if (reply.get("id") != "package-probe" or reply.get("ok") is not True or reply.get("available") is not True or
            reply.get("modelVersion") != expected_version or type(probability) not in (int, float) or
            not math.isfinite(probability) or not 0 <= probability <= 1 or
            type(windows) is not int or not 1 <= windows <= 8 or type(tokens) is not int or tokens < 0):
        raise RuntimeError("Sandboxed PhishLang host could not load and run the packaged local model.")

def assemble(engine, destination, local_source, installed_destination):
    receipt_api = None
    source_receipt = None
    if local_source:
        receipt_api = runpy.run_path(str(ROOT / "scripts/build_receipt.py"))
        source_receipt = receipt_api["verify_receipt"](
            engine, ROOT, receipt_api["current_input_digest"](ROOT))
    identity, signing_team = development_identity()
    phishing_info = verified_phishing_resources()
    run("bash", ROOT / "scripts/build-phishing.sh")
    # DMG Finder metadata can make strict codesign verification fail. Copy only
    # the app data, then verify its original sealed code before changing anything.
    run("ditto", "--norsrc", "--noextattr", engine, destination)
    run("codesign", "--verify", "--deep", "--strict", destination)
    if source_receipt is not None:
        receipt_api["verify_artifact_hashes"](destination, source_receipt)
    remove_stale_tickets(destination)
    engine_policy = signature_policy(destination)
    resources = destination / "Contents/Resources"
    phishing_bundle = destination / "Contents/Helpers/KumoPhishing.app"
    phishing_contents = phishing_bundle / "Contents"
    phishing_resources = phishing_contents / "Resources/PhishLang"
    phishing_resources.mkdir(parents=True)
    (phishing_contents / "MacOS").mkdir()
    (phishing_contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "app.kumo.phishing", "CFBundleExecutable": "KumoPhishingHost",
        "CFBundleName": "KumoPhishing", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1.0",
        "LSMinimumSystemVersion": "13.0", "LSBackgroundOnly": True,
    }))
    prepared = ROOT / "build/phishlang-model"
    shutil.copytree(prepared / "PhishLang.mlmodelc", phishing_resources / "PhishLang.mlmodelc")
    for name in ("vocab.txt", "model-info.json"):
        shutil.copyfile(prepared / name, phishing_resources / name)
    for name in ("NOTICE.md", "LICENSE-MobileBERT.txt"):
        shutil.copyfile(ROOT / "native/phishing" / name, phishing_resources / name)
    phishing_host = phishing_contents / "MacOS/KumoPhishingHost"
    shutil.copy2(ROOT / "build/phishing-native/KumoPhishingHost", phishing_host)
    (resources / "phishing-host-template.json").write_text(json.dumps({
        "name": "com.kumo.phishing", "description": "Kumo local PhishLang classifier",
        "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id()}/"],
    }, indent=2) + "\n")
    shutil.copytree(ROOT / "extension", resources / "KumoExtension")
    shutil.copytree(ROOT / "agent-bridge", resources / "agent-bridge", ignore=shutil.ignore_patterns("test", "node_modules"))
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js 22+ is required for the local agent bridge.")
    node_major = int(subprocess.check_output([node, "-p", "process.versions.node.split('.')[0]"], text=True).strip())
    if node_major < 22:
        raise RuntimeError("Node.js 22+ is required for the local agent bridge.")
    run("swiftc", "-O", "-target", "arm64-apple-macos13.0", ROOT / "native/launcher/main.swift", "-o", destination / "Contents/MacOS/Kumo", "-framework", "AppKit")
    icon_tool = ROOT / ".cache/make-kumo-icon"
    icon_tool.parent.mkdir(exist_ok=True)
    run("swiftc", "-O", "-target", "arm64-apple-macos13.0", ROOT / "native/launcher/icon.swift", "-o", icon_tool, "-framework", "AppKit")
    with tempfile.TemporaryDirectory(prefix="kumo-icon-") as temp:
        iconset = Path(temp) / "Kumo.iconset"
        run(icon_tool, iconset)
        run("iconutil", "--convert", "icns", "--output", resources / "Kumo.icns", iconset)
    info_path = destination / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    engine_version = VERSION
    if local_source:
        engine_version = str(info.get("CFBundleShortVersionString", ""))
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", engine_version):
            raise RuntimeError("The supplied engine is missing its full Chromium version.")
    info.update(CFBundleExecutable="Kumo", CFBundleName="Kumo", CFBundleDisplayName="Kumo", CFBundleIdentifier="app.kumo.browser", CFBundleShortVersionString="0.1.0", LSApplicationCategoryType="public.app-category.productivity")
    info["KumoEngineVersion"] = engine_version
    info.pop("CFBundleIconName", None)
    info["CFBundleIconFile"] = "Kumo.icns"
    info_path.write_bytes(plistlib.dumps(info))
    eid = extension_id()
    installed_resources = installed_destination / "Contents/Resources"
    bridge = installed_resources / "agent-bridge/cli.mjs"
    # Shell wrapper resolves its location, so native host launching survives moving the app.
    wrapper = resources / "kumo-native-host"
    wrapper.write_text("#!/bin/sh\nKUMO_RESOURCES=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\nexec " + shlex.quote(node) + ' "$KUMO_RESOURCES/agent-bridge/cli.mjs" native "$@"\n')
    wrapper.chmod(0o755)
    host = {"name": "com.kumo.agent_bridge", "description": "Kumo opt-in agent bridge", "type": "stdio", "allowed_origins": [f"chrome-extension://{eid}/"]}
    (resources / "native-host-template.json").write_text(json.dumps(host, indent=2) + "\n")
    setup = resources / "setup-agent"
    setup.write_text("#!/bin/sh\nKUMO_RESOURCES=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\nexec " + shlex.quote(node) + ' "$KUMO_RESOURCES/agent-bridge/cli.mjs" install --extension-id ' + shlex.quote(eid) + '\n')
    setup.chmod(0o755)
    # These commands only configure MCP when the person explicitly runs them.
    setup_command = shlex.quote(str(installed_resources / "setup-agent"))
    codex = f"{setup_command} && codex mcp add kumo -- {shlex.quote(node)} {shlex.quote(str(bridge))} mcp"
    claude = f"{setup_command} && claude mcp add --transport stdio --scope user kumo -- {shlex.quote(node)} {shlex.quote(str(bridge))} mcp"
    source_target_version = json.loads((ROOT / "config/source-lock.json").read_text())["chromiumVersion"]
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", source_target_version):
        raise RuntimeError("The source lock is missing its full Chromium target version.")
    build_info = {"engineVersion": engine_version, "sourceTargetVersion": source_target_version, "sourceCompiledLocally": local_source, "codeSigningTeamId": signing_team, "signingMode": "apple-development", "extensionId": eid, "codexSetupCommand": codex, "claudeSetupCommand": claude}
    build_info["phishingProtection"] = {
        "included": True, "modelVersion": phishing_info["modelVersion"],
        "modelDirectorySHA256": phishing_info["modelDirectorySHA256"],
        "vocabSHA256": phishing_info["vocabSHA256"], "computeUnits": "cpuOnly",
        "experimental": True, "enabledByDefault": False,
        "localDevelopmentOnly": phishing_info.get("localDevelopmentOnly") is True,
        "rightsStatus": phishing_info.get("rightsStatus", "unverified"),
    }
    if source_receipt is not None:
        build_info["sourceBuildReceipt"] = source_receipt
    (resources / "KumoExtension/build-info.json").write_text(json.dumps(build_info, indent=2) + "\n")
    (resources / "KumoExtension/engine-version.js").write_text("export const ENGINE_VERSION = " + json.dumps(engine_version.split("-")[0]) + ";\n")
    # The ':' XML form is needed here; modern '-' prints a human-readable tree.
    entitlements = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(engine)], capture_output=True, check=True).stdout
    with tempfile.NamedTemporaryFile(suffix=".plist") as handle:
        handle.write(entitlements)
        handle.flush()
        resign_nested_code(destination, identity, signing_team)
        # The classifier has no browser/agent privileges or network entitlement.
        # It reads only its bundled model and bounded Native Messaging frames.
        with tempfile.NamedTemporaryFile(suffix=".plist") as phishing_entitlements:
            phishing_entitlements.write(plistlib.dumps({"com.apple.security.app-sandbox": True}))
            phishing_entitlements.flush()
            run("codesign", "--force", "--sign", identity, "--timestamp=none", "--identifier", "app.kumo.phishing",
                "--options", hex(engine_policy), "--entitlements", phishing_entitlements.name, phishing_bundle)
            signature_policy(phishing_bundle, expected_team=signing_team)
        # Both executables are bound to this bundle's modified Info.plist.
        for target in (destination / "Contents/MacOS/Chromium", destination):
            run("codesign", "--force", "--sign", identity, "--timestamp=none", "--identifier", "app.kumo.browser",
                "--options", hex(engine_policy), "--entitlements", handle.name, target)
            if signature_policy(target, expected_team=signing_team) != engine_policy:
                raise RuntimeError("Packaging changed the engine's macOS signing protections.")
    run("codesign", "--verify", "--deep", "--strict", "-R", f'=anchor apple generic and certificate leaf[subject.OU] = "{signing_team}"', destination)
    verify_engine_start(destination)
    verify_phishing_start(destination)
    return build_info

def publish_preview(staged, destination):
    """Atomically replace a preview, or exclusively publish its first copy.

    After a swap the previous app is at ``staged`` for the caller's temporary
    directory cleanup. If the destination changes existence during publication,
    fail without falling back to a non-atomic or overwriting rename.
    """
    flags = 0x00000002 if destination.exists() else 0x00000004
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(staged), os.fsencode(destination), flags):
        raise OSError(ctypes.get_errno(), "Atomic preview publication failed; no fallback replacement was attempted.")

def ensure_app_closed(destination):
    # Inspect executable paths, without regex matching or command-line arguments.
    # Helpers can outlive the main process and still need this bundle's resources.
    try:
        processes = subprocess.run(["ps", "-axo", "comm="], capture_output=True,
                                   text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError("Could not check whether Kumo is running; app replacement was stopped.") from error
    prefix = str(destination / "Contents") + "/"
    if any(executable.lstrip().startswith(prefix) for executable in processes.stdout.splitlines()):
        raise RuntimeError("Quit Kumo and its helpers before rebuilding its application bundle.")

def numeric_engine_version(value):
    """Compare Chromium's four numeric components, ignoring packaging revision."""
    if (not isinstance(value, str) or len(value) > 80
            or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+(?:-\d+(?:\.\d+)*)?", value)):
        raise RuntimeError("Expected a full four-part Chromium engine version.")
    parts = tuple(int(part) for part in value.split("-", 1)[0].split("."))
    if any(part > 0xffffffff for part in parts):
        raise RuntimeError("Chromium engine version component is out of range.")
    return parts

def incoming_engine_version(engine, local_source):
    if not local_source:
        return VERSION  # The preview download is checksum-pinned before packaging.
    try:
        # Info.plist is sealed by the original main executable's signature.
        subprocess.run(["codesign", "--verify", "--strict", str(engine)],
                       capture_output=True, text=True, check=True)
        info = plistlib.loads((engine / "Contents/Info.plist").read_bytes())
        version = info.get("CFBundleShortVersionString") if isinstance(info, dict) else None
        numeric_engine_version(version)
        return version
    except (OSError, ValueError, plistlib.InvalidFileException, subprocess.CalledProcessError) as error:
        raise RuntimeError("Could not verify the incoming source engine's signed version metadata.") from error

def ensure_no_engine_downgrade(destination, incoming_version):
    incoming = numeric_engine_version(incoming_version)
    if not destination.exists():
        return
    try:
        subprocess.run(["codesign", "--verify", "--strict", str(destination)],
                       capture_output=True, text=True, check=True)
        info = plistlib.loads((destination / "Contents/Info.plist").read_bytes())
        installed_version = info.get("KumoEngineVersion") if isinstance(info, dict) else None
        installed = numeric_engine_version(installed_version)
    except (OSError, ValueError, RuntimeError, plistlib.InvalidFileException, subprocess.CalledProcessError) as error:
        raise RuntimeError("Could not verify the existing app's signed Kumo engine version; replacement was stopped. Choose a separate --output path.") from error
    if incoming < installed:
        raise RuntimeError(f"Refusing Chromium engine downgrade from {installed_version} to {incoming_version}. "
                           "Build the current source engine, or choose a separate --output path for preview QA.")

def package(engine, destination, local_source):
    # Build and verify beside the existing app. A compiler/signing failure must
    # leave the last working browser available.
    destination.parent.mkdir(parents=True, exist_ok=True)
    ensure_app_closed(destination)
    ensure_no_engine_downgrade(destination, incoming_engine_version(engine, local_source))
    with tempfile.TemporaryDirectory(prefix=".kumo-package-", dir=destination.parent) as temporary:
        staged = Path(temporary) / destination.name
        build_info = assemble(engine, staged, local_source, destination)
        ensure_app_closed(destination)
        ensure_no_engine_downgrade(destination, build_info["engineVersion"])
        publish_preview(staged, destination)
    (destination.parent / "build-info.json").write_text(json.dumps(build_info, indent=2) + "\n")
    print(f"\nBuilt {destination}\nEngine: {'locally supplied source build' if local_source else 'checksum-verified upstream binary'}\nExtension ID: {build_info['extensionId']}\nApple development signature ({build_info['codeSigningTeamId']}); not an Apple-notarized Kumo release.\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-app", type=Path, help="Package your locally compiled Chromium.app")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/Kumo.app")
    args = parser.parse_args()
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        parser.error("This packaging target requires an Apple Silicon Mac.")
    if args.engine_app:
        package(args.engine_app.resolve(), args.output.resolve(), True)
        return
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    dmg = cache / "chromium-arm64.dmg"
    if not dmg.exists():
        partial = dmg.with_suffix(".partial")
        print("Downloading pinned Chromium runtime…", flush=True)
        urllib.request.urlretrieve(DOWNLOAD, partial)
        partial.rename(dmg)
    if digest(dmg) != SHA256:
        raise RuntimeError("Runtime checksum mismatch. Refusing to package this download.")
    with tempfile.TemporaryDirectory(prefix="kumo-mount-") as mount:
        run("hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mount, dmg)
        try:
            engine = Path(mount) / "Chromium.app"
            package(engine, args.output.resolve(), False)
        finally:
            run("hdiutil", "detach", mount)

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Kumo packaging: {error}", file=sys.stderr)
        sys.exit(1)
