#!/usr/bin/env python3
"""Build a separate native PhishLang add-on. Does not install, publish or alter Kumo.

Model provenance stays intact. No Python, conversion tools, browser profile, private
key, developer-machine path or Google authentication data enters this package.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_ID = "ejmohaggcahgfhmgkdiicnmmlpnhgfmi"
ORIGIN = f"chrome-extension://{EXTENSION_ID}/"
HOST = "com.kumo.phishlang"
BUNDLE = "app.kumo.phishlang"
TEAM = "PV65ZWXCWX"
APP_NAME = "Kumo PhishLang.app"
FRONTEND = ("manifest.json", "background.js", "settings.html", "settings.js", "settings-state.js",
            "phishing-warning.html", "phishing-warning.js", "standalone.css")
SHARED = ("phishing-background.js", "phishing-content.js")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as file:
        for data in iter(lambda: file.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def regular(path, maximum=150_000_000):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > maximum:
        raise RuntimeError("Package inputs must be bounded regular files with one link: " + path.name)


def plain_tree(path, maximum=180_000_000):
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("Package input must be an ordinary directory: " + path.name)
    size = 0
    for item in sorted(path.rglob("*")):
        value = item.lstat()
        if stat.S_ISDIR(value.st_mode):
            continue
        regular(item, maximum)
        size += value.st_size
        if size > maximum:
            raise RuntimeError("Package resource tree exceeds its limit.")


def extension_id(key):
    public = base64.b64decode(key, validate=True)
    if not public or len(public) > 8192:
        raise ValueError("Invalid extension public key")
    return "".join(chr(97 + int(char, 16)) for char in hashlib.sha256(public).hexdigest()[:32])


def verify_copied_model(directory, expected):
    """Bind the exact copied bytes to the model manifest verified before staging."""
    regular(directory / "model-info.json", 65_536)
    if json.loads((directory / "model-info.json").read_text()) != expected:
        raise RuntimeError("Copied model metadata changed during packaging.")
    regular(directory / "vocab.txt", 2_000_000)
    if digest(directory / "vocab.txt") != expected["vocabSHA256"]:
        raise RuntimeError("Copied model vocabulary differs from the verified source.")
    compiled = directory / "PhishLang.mlmodelc"
    plain_tree(compiled)
    manifest = [{"path": item.relative_to(compiled).as_posix(), "bytes": item.stat().st_size, "sha256": digest(item)}
                for item in sorted(compiled.rglob("*")) if item.is_file()]
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    if manifest != expected["modelFiles"] or hashlib.sha256(encoded).hexdigest() != expected["modelDirectorySHA256"]:
        raise RuntimeError("Copied model bytes differ from the verified source.")


def verified_model(source_root, resources):
    # Reuse the browser packager's pinned conversion/hash validation, without its
    # build/sign/install entry points. Explicit resource paths allow an isolated
    # source worktree to consume the immutable validated conversion directory.
    for directory in (resources, resources / "upstream"):
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("Model source directories cannot be aliases.")
    for name in ("model-info.json", "vocab.txt", "upstream/model.safetensors"):
        regular(resources / name)
    plain_tree(resources / "PhishLang.mlmodelc")
    regular(source_root / "config/phishlang-model-lock.json", 1_000_000)
    spec = importlib.util.spec_from_file_location("kumo_phishlang_addon_model", source_root / "scripts/package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = source_root
    return module.verified_phishing_resources(resources)


def copy_extension(source_root, source, destination, model):
    plain_tree(source, maximum=2_000_000)
    manifest = json.loads((source / "manifest.json").read_text())
    if extension_id(manifest.get("key", "")) != EXTENSION_ID or manifest.get("manifest_version") != 3:
        raise RuntimeError("The add-on must use its dedicated pinned Manifest V3 identity.")
    if manifest.get("incognito") != "not_allowed":
        raise RuntimeError("The add-on must exclude incognito browsing.")
    destination.mkdir()
    for name in FRONTEND:
        regular(source / name, 1_000_000)
        shutil.copyfile(source / name, destination / name)
    for name in SHARED:
        regular(source_root / "extension" / name, 1_000_000)
        shutil.copyfile(source_root / "extension" / name, destination / name)
    protection = {"included": True, "experimental": True, "enabledByDefault": False,
                  "modelVersion": model["modelVersion"], "modelDirectorySHA256": model["modelDirectorySHA256"],
                  "vocabSHA256": model["vocabSHA256"], "computeUnits": "cpuOnly", "nativeHost": HOST,
                  "localDevelopmentOnly": model.get("localDevelopmentOnly") is True,
                  "rightsStatus": model.get("rightsStatus", "unverified")}
    (destination / "build-info.json").write_text(json.dumps({"schemaVersion": 1, "name": "Kumo PhishLang",
        "extensionId": EXTENSION_ID, "version": manifest["version"], "phishingProtection": protection}, indent=2) + "\n")
    return manifest


def run(*arguments, **kwargs):
    return subprocess.run([str(item) for item in arguments], check=True, **kwargs)


def native_binaries(source_root, helper_source=None):
    package = Path(helper_source) if helper_source else source_root / "native/phishing"
    if package.is_symlink() or not package.is_dir():
        raise RuntimeError("Native helper source must be an ordinary Swift package directory.")
    scratch = source_root / "build/phishlang-addon-native"
    for product in ("KumoPhishingHost", "KumoPhishLangSetup"):
        run("xcrun", "swift", "build", "--package-path", package, "--scratch-path", scratch,
            "--configuration", "release", "--product", product)
    result = run("xcrun", "swift", "build", "--package-path", package, "--scratch-path", scratch,
                 "--configuration", "release", "--show-bin-path", capture_output=True, text=True)
    directory = Path(result.stdout.strip())
    for name in ("KumoPhishingHost", "KumoPhishLangSetup"):
        regular(directory / name, 10_000_000)
    return directory


def verify_start(application):
    helper = application / "Contents/MacOS/KumoPhishingHost"
    payload = json.dumps({"id": "addon-package-probe", "type": "classify", "text": 'TITLE: { "text": "Public library opening hours" }'}).encode()
    result = run(helper, ORIGIN, input=struct.pack("<I", len(payload)) + payload, capture_output=True, timeout=45)
    if len(result.stdout) < 4:
        raise RuntimeError("Sandboxed add-on did not return a Native Messaging frame.")
    length = struct.unpack("<I", result.stdout[:4])[0]
    if not 0 < length <= 262144 or len(result.stdout) != length + 4:
        raise RuntimeError("Sandboxed add-on returned an invalid Native Messaging frame.")
    reply = json.loads(result.stdout[4:])
    model = json.loads((application / "Contents/Resources/PhishLang/model-info.json").read_text())
    probability = reply.get("probability")
    if (reply.get("ok") is not True or reply.get("available") is not True or reply.get("id") != "addon-package-probe" or
            reply.get("modelVersion") != model["modelVersion"] or type(probability) not in (int, float) or
            not math.isfinite(probability) or not 0 <= probability <= 1 or
            type(reply.get("windows")) is not int or not 1 <= reply["windows"] <= 8):
        raise RuntimeError("Sandboxed add-on could not load and run its packaged model.")
    for origin in ("chrome-extension://eldkgppmnhligdekahicdcdndcoongio/", ORIGIN.upper(), ORIGIN + "evil"):
        blocked = subprocess.run([str(helper), origin], input=b"", capture_output=True, timeout=10)
        if blocked.returncode != 64 or blocked.stdout:
            raise RuntimeError("Standalone host admitted an unauthorized extension origin.")
    return {"available": True, "modelVersion": reply["modelVersion"], "windows": reply["windows"], "originChecks": 4}


def assemble(source_root, extension_source, model_resources, output, identity, allow_adhoc=False, helper_source=None):
    if output.exists() or output.is_symlink():
        raise RuntimeError("Output already exists; choose a new add-on package directory.")
    if identity == "-":
        if not allow_adhoc:
            raise RuntimeError("Ad-hoc signing requires the explicit QA-only --allow-adhoc option.")
    elif not re.fullmatch(r"[0-9A-Fa-f]{40}", identity):
        raise RuntimeError("Use a Keychain signing identity SHA-1 fingerprint.")
    info = verified_model(source_root, model_resources)
    binaries = native_binaries(source_root, helper_source)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".kumo-phishlang-package-", dir=output.parent) as temporary:
        stage = Path(temporary) / output.name
        stage.mkdir()
        manifest = copy_extension(source_root, extension_source, stage / "extension", info)
        application = stage / APP_NAME
        contents = application / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        resources = contents / "Resources"
        resources.mkdir()
        model = resources / "PhishLang"
        model.mkdir()
        shutil.copytree(model_resources / "PhishLang.mlmodelc", model / "PhishLang.mlmodelc")
        for name in ("vocab.txt", "model-info.json"):
            shutil.copyfile(model_resources / name, model / name)
        for name in ("NOTICE.md", "LICENSE-MobileBERT.txt"):
            regular(source_root / "native/phishing" / name, 1_000_000)
            shutil.copyfile(source_root / "native/phishing" / name, model / name)
        verify_copied_model(model, info)
        shutil.copytree(stage / "extension", resources / "Extension")
        for item in sorted((stage / "extension").iterdir()):
            if digest(item) != digest(resources / "Extension" / item.name):
                raise RuntimeError("Copied extension bytes changed during packaging.")
        shutil.copy2(binaries / "KumoPhishingHost", contents / "MacOS/KumoPhishingHost")
        (contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": BUNDLE, "CFBundleExecutable": "KumoPhishingHost", "CFBundleName": "Kumo PhishLang",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": manifest["version"],
            "LSMinimumSystemVersion": "13.0", "LSBackgroundOnly": True,
            "KumoPhishLangExtensionOrigin": ORIGIN, "KumoPhishLangPackageIdentifier": BUNDLE,
        }))
        tools = stage / "Tools"
        tools.mkdir()
        setup = tools / "KumoPhishLangSetup"
        shutil.copy2(binaries / "KumoPhishLangSetup", setup)
        # SwiftPM emits debug/source path records even for release builds.
        # Strip copied binaries only; the original build products stay intact.
        for executable in (contents / "MacOS/KumoPhishingHost", setup):
            run("/usr/bin/strip", "-S", executable)
        for action in ("install", "uninstall"):
            wrapper = stage / (action + ".command")
            wrapper.write_text('#!/bin/bash\nset -euo pipefail\ntask_dir="$(cd "$(dirname "$0")" && pwd)"\nexec "$task_dir/Tools/KumoPhishLangSetup" ' + action + ' "$@"\n')
            wrapper.chmod(0o755)
        (stage / "README.txt").write_text('''Kumo PhishLang 0.1.0 — optional experimental local phishing detection

Requires an Apple silicon Mac, macOS 13 or later, and Kumo. No Python, Node,
Xcode, extension-store account, administrator password or model download is
needed to run this package. This package does not change Kumo.app.

1. Extract the package. Run install.command (double-click or use Terminal).
2. In Kumo open chrome://extensions, enable Developer mode, choose Load unpacked,
   and select ~/Library/Application Support/KumoPhishLang/extension.
3. Open Kumo PhishLang settings, enable protection and grant website access.

The installer copies the signed native companion into ~/Applications/Kumo
PhishLang.app and registers com.kumo.phishlang for this user's Kumo only. The
extension is copied from the signed companion into the stable location above,
so the extracted download can be moved or deleted after installation.

The companion runs on demand in the macOS App Sandbox with no network access.
No daemon or login item is installed. Detection is off until you enable it.
Only bounded, privacy-filtered page content is classified locally. It excludes
filled form values, editable content and private windows. Warnings are an
experimental signal; no-signal is not a guarantee that a site is safe.

To remove it, close the add-on, run uninstall.command from this package and
remove Kumo PhishLang from chrome://extensions. Uninstall removes only owned
PhishLang app, host registration and stable extension files; browser preferences
and other native hosts are preserved. Keep this package for its uninstaller.

Inspect status: Tools/KumoPhishLangSetup status

PhishLang model and paper attribution, conversion metadata and the MobileBERT
base license are included inside Kumo PhishLang.app/Contents/Resources/PhishLang.
Original upstream licensing/provenance fields are retained, without claiming
that separate redistribution rights were verified. No author endorsement is
implied. This add-on has not been qualified on an actual 8 GB Mac.
''')
        documentation = source_root / "addons/phishlang/README.md"
        if documentation.exists():
            regular(documentation, 1_000_000)
            shutil.copyfile(documentation, stage / "README.md")
        entitlements = Path(temporary) / "sandbox.plist"
        entitlements.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}))
        timestamp = "--timestamp=none" if identity == "-" else "--timestamp"
        run("codesign", "--force", "--sign", identity, timestamp, "--options", "0x12a00", "--identifier", BUNDLE,
            "--entitlements", entitlements, application)
        run("codesign", "--force", "--sign", identity, timestamp, "--options", "0x12a00", "--identifier", BUNDLE + ".setup", setup)
        requirement = [] if identity == "-" else ["-R=anchor apple generic and certificate leaf[subject.OU] = \"" + TEAM + "\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists"]
        for item in (application, setup):
            run("codesign", "--verify", "--strict", "--all-architectures", *requirement, item)
        probe = verify_start(application)
        forbidden = [str(source_root).encode(), str(model_resources).encode(), str(Path.home()).encode()]
        for item in sorted(stage.rglob("*")):
            if item.is_file():
                data = item.read_bytes()
                if any(prefix in data for prefix in forbidden):
                    raise RuntimeError("A build-machine path remains in the distributable: " + item.relative_to(stage).as_posix())
        entries = [{"path": item.relative_to(stage).as_posix(), "bytes": item.stat().st_size, "sha256": digest(item)}
                   for item in sorted(stage.rglob("*")) if item.is_file()]
        receipt = {"schemaVersion": 1, "name": "Kumo PhishLang", "version": manifest["version"],
                   "extensionId": EXTENSION_ID, "nativeHost": HOST, "bundleIdentifier": BUNDLE,
                   "platform": "macOS-arm64", "minimumMacOS": "13.0", "experimental": True, "enabledByDefault": False,
                   "modelVersion": info["modelVersion"], "modelDirectorySHA256": info["modelDirectorySHA256"],
                   "upstreamSafetensorsSHA256": info["upstreamSafetensorsSHA256"],
                   "conversionLockSHA256": info["conversionLockSHA256"], "rightsStatus": info.get("rightsStatus", "unverified"),
                   "modelLocalDevelopmentOnly": info.get("localDevelopmentOnly") is True,
                   "signing": "ad-hoc-qa" if identity == "-" else "apple-team-" + TEAM,
                   "notarization": "not-submitted", "probe": probe, "files": entries}
        (stage / "package-info.json").write_text(json.dumps(receipt, indent=2) + "\n")
        stage.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--extension", type=Path)
    parser.add_argument("--model-resources", type=Path, required=True)
    parser.add_argument("--helper-source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--allow-adhoc", action="store_true", help="Allow ad-hoc signing for isolated local QA only")
    args = parser.parse_args()
    root = args.source_root.absolute()
    receipt = assemble(root, args.extension.absolute() if args.extension else root / "addons/phishlang/extension",
                       args.model_resources.absolute(), args.output.absolute(), args.identity, args.allow_adhoc, args.helper_source)
    print(json.dumps({"ok": True, "output": str(args.output.absolute()), "extensionId": receipt["extensionId"],
                      "modelVersion": receipt["modelVersion"], "installed": False, "published": False}, indent=2))


if __name__ == "__main__":
    main()
