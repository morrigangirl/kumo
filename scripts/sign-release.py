#!/usr/bin/env python3
"""Inspect or sign a separate Kumo release copy using the selected Apple team."""
import argparse
import base64
import ctypes
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEBUG = {"get-task-allow", "com.apple.security.get-task-allow"}
IDENTITY_KEYS = {"application-identifier", "com.apple.application-identifier", "com.apple.developer.team-identifier"}
MAGIC = {bytes.fromhex(value) for value in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}
# Public Security.framework CSCommon.h: preserve existing policy flags, excluding
# ad-hoc/linker-signed/other signature-format bits. Always enable Hardened Runtime.
POLICY_MASK = 0x0001 | 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x10000
RUNTIME = 0x10000
MAIN_POLICY = RUNTIME | 0x0800 | 0x2000 | 0x0200
JIT_POLICY = RUNTIME | 0x0800 | 0x0200


def run(*args, data=None, check=True):
    result = subprocess.run([str(arg) for arg in args], input=data, capture_output=True)
    if check and result.returncode:
        # Never print an environment, credential, or entire notary response.
        raise RuntimeError(f"{Path(args[0]).name} {args[1] if len(args) > 1 else ''} failed (exit {result.returncode}).")
    return result


def signing_metadata(target):
    result = run("/usr/bin/codesign", "-d", "--verbose=4", "--entitlements", ":-", target, check=False)
    if result.returncode:
        return {"identifier": None, "flags": 0, "entitlements": {}, "details": "", "cdhash": None}
    details = result.stderr.decode("utf-8", "replace")
    identifier = re.search(r"^Identifier=(.+)$", details, re.M)
    flags = re.search(r"\bflags=0x([0-9a-fA-F]+)", details)
    cdhash = re.search(r"^CDHash=(.+)$", details, re.M)
    entitlements = plistlib.loads(result.stdout) if result.stdout.strip() else {}
    if not isinstance(entitlements, dict):
        raise RuntimeError("Code signature entitlements must be a dictionary.")
    return {"identifier": identifier[1] if identifier else None,
            "flags": int(flags[1], 16) if flags else 0,
            "entitlements": entitlements, "details": details, "cdhash": cdhash[1] if cdhash else None}


def identities_for_team(team):
    identities = run("/usr/bin/security", "find-identity", "-v", "-p", "codesigning").stdout.decode()
    valid = dict(re.findall(r'\b([0-9A-F]{40})\s+"([^"]+)"', identities))
    pems = run("/usr/bin/security", "find-certificate", "-a", "-p").stdout.decode()
    found = {}
    for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pems, re.S):
        der = base64.b64decode("".join(pem.splitlines()[1:-1]))
        digest = hashlib.sha1(der).hexdigest().upper()
        if digest not in valid or digest in found or not valid[digest].startswith("Developer ID Application:"):
            continue
        description = run("/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-text", data=pem.encode()).stdout.decode()
        subject = description.splitlines()[0].removeprefix("subject=").strip()
        ou = re.search(r"(?:^|,)\s*OU=([A-Z0-9]{10})(?:,|$)", subject)
        if ou and ou[1] == team and "1.2.840.113635.100.6.1.13" in description:
            found[digest] = {"sha1": digest, "name": valid[digest], "teamId": team}
    return list(found.values())


def validate_profile(profile, config, identity_sha1=None, now=None):
    """Validate the decoded public Developer ID profile, without modifying it."""
    now = now or dt.datetime.now(dt.timezone.utc)
    ent = profile.get("Entitlements", {})
    team, bundle = config["teamId"], config["bundleIdentifier"]
    app_id = f"{team}.{bundle}"
    if team not in profile.get("TeamIdentifier", []) or ent.get("com.apple.developer.team-identifier") != team:
        raise RuntimeError("Provisioning profile is for a different Apple team.")
    actual_id = ent.get("com.apple.application-identifier", ent.get("application-identifier"))
    if actual_id != app_id:
        raise RuntimeError("Provisioning profile must contain the exact Kumo App ID; wildcards are refused.")
    if not set(profile.get("Platform", [])).intersection({"OSX", "macOS"}):
        raise RuntimeError("Provisioning profile must authorize macOS.")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, dt.datetime):
        raise RuntimeError("Provisioning profile has no valid expiration date.")
    expires = expires.replace(tzinfo=dt.timezone.utc) if expires.tzinfo is None else expires
    if expires <= now:
        raise RuntimeError("Provisioning profile has expired.")
    created = profile.get("CreationDate")
    if isinstance(created, dt.datetime):
        created = created.replace(tzinfo=dt.timezone.utc) if created.tzinfo is None else created
        if created > now:
            raise RuntimeError("Provisioning profile is not yet valid.")
    if profile.get("ProvisionsAllDevices") is not True or profile.get("ProvisionedDevices"):
        raise RuntimeError("A Developer ID all-device distribution profile is required.")
    if any(ent.get(key) for key in DEBUG):
        raise RuntimeError("A development/debug provisioning profile cannot authorize this release.")
    if ent.get(config["browserPasskeyEntitlement"]) is not True:
        raise RuntimeError("Provisioning profile does not approve the browser passkey entitlement.")
    certificates = profile.get("DeveloperCertificates", [])
    hashes = {hashlib.sha1(value).hexdigest().upper() for value in certificates if isinstance(value, bytes)}
    if not hashes or (identity_sha1 is not None and identity_sha1 not in hashes):
        raise RuntimeError("Provisioning profile does not authorize the selected signing certificate.")
    return {"name": profile.get("Name"), "uuid": profile.get("UUID"),
            "expires": expires.isoformat(), "appId": app_id, "browserPasskeysApproved": True}


def clean_entitlements(existing, config, primary=False, profile_approved=False, jit=False):
    ent = dict(existing)
    for key in DEBUG | IDENTITY_KEYS | {config["browserPasskeyEntitlement"]}:
        ent.pop(key, None)
    for key in ent:
        if key.startswith(("com.apple.private.", "com.apple.developer.")) or key in {
                "keychain-access-groups", "com.apple.security.application-groups", "aps-environment"}:
            raise RuntimeError(f"Unsupported identity-bound entitlement {key}; a separate reviewed profile workflow is required.")
    if jit:
        ent["com.apple.security.cs.allow-jit"] = True
    if primary and profile_approved:
        ent.update({"com.apple.application-identifier": f'{config["teamId"]}.{config["bundleIdentifier"]}',
                    "com.apple.developer.team-identifier": config["teamId"],
                    config["browserPasskeyEntitlement"]: True})
    return ent


@dataclass
class Item:
    relative: str
    identifier: str
    flags: int
    entitlements: dict

    def summary(self):
        return {"path": self.relative, "identifier": self.identifier,
                "options": hex(self.flags), "entitlementKeys": sorted(self.entitlements)}


def bundle_info(bundle):
    for file in (bundle / "Contents/Info.plist", bundle / "Resources/Info.plist", bundle / "Info.plist"):
        if file.is_file():
            return plistlib.loads(file.read_bytes())
    return {}


def inventory(app, config, profile_approved=False):
    """Walk real files once, never traversing framework version symlinks twice."""
    app = app.resolve()
    bundles, machos = [app], []
    for directory, dirs, files in os.walk(app, followlinks=False):
        for name in dirs + files:
            candidate = Path(directory) / name
            if candidate.is_symlink() and not candidate.resolve().is_relative_to(app):
                raise RuntimeError("App contains a symlink outside its bundle; release copy would not be self-contained.")
        for name in dirs:
            candidate = Path(directory) / name
            if not candidate.is_symlink() and candidate.suffix in {".app", ".framework", ".xpc", ".appex", ".bundle", ".plugin"}:
                if bundle_info(candidate).get("CFBundleExecutable"):
                    bundles.append(candidate)
        for name in files:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                with candidate.open("rb") as handle:
                    if handle.read(4) in MAGIC:
                        machos.append(candidate)
    covered = set()
    for bundle in bundles:
        executable = bundle_info(bundle).get("CFBundleExecutable", "")
        for candidate in (bundle / "Contents/MacOS" / executable, bundle / executable):
            if candidate.is_file():
                covered.add(candidate.resolve())
                break
    targets = bundles + [file for file in machos if file.resolve() not in covered]
    engine = app / "Contents/MacOS/Chromium"
    if engine not in targets or engine not in machos:
        raise RuntimeError("Kumo's separate native Chromium executable is missing.")
    main_ent = signing_metadata(engine)["entitlements"]
    items = []
    for target in targets:
        relative = str(target.relative_to(app)) if target != app else "."
        metadata = signing_metadata(target)
        primary = target in {app, engine}
        helper = target.suffix == ".app" and target != app and "Chromium Helper" in target.name
        jit = helper and ("Renderer" in target.name or "GPU" in target.name)
        flags = (metadata["flags"] & POLICY_MASK) | RUNTIME
        if primary or (helper and not jit):
            flags |= MAIN_POLICY
        elif jit:
            flags |= JIT_POLICY
        ent = dict(main_ent, **metadata["entitlements"]) if primary else metadata["entitlements"]
        ent = clean_entitlements(ent, config, primary, profile_approved, jit)
        identifier = config["bundleIdentifier"] if primary else metadata["identifier"] or bundle_info(target).get("CFBundleIdentifier")
        if not identifier:
            identifier = config["bundleIdentifier"] + ".code." + hashlib.sha256(relative.encode()).hexdigest()[:16]
        items.append(Item(relative, identifier, flags, ent))
    # A bundle seals its children only after they have their final signatures.
    return sorted(items, key=lambda item: (-len(Path(item.relative).parts), item.relative))


def running_apps(paths):
    commands = run("/bin/ps", "-axo", "pid=,command=").stdout.decode("utf-8", "replace").splitlines()
    return [str(app) for app in paths if any(
        re.sub(r"^\s*\d+\s+", "", line).startswith(str(app / "Contents") + "/") for line in commands)]


def verify_item(target, item, config):
    requirement = ('anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   f'and certificate leaf[subject.OU] = "{config["teamId"]}"')
    run("/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R", requirement, target)
    metadata = signing_metadata(target)
    details = metadata["details"]
    if (metadata["identifier"] != item.identifier or f'TeamIdentifier={config["teamId"]}\n' not in details
            or not re.search(r"^Timestamp=.+", details, re.M)
            or not re.search(r"^Authority=Developer ID Application:", details, re.M)
            or metadata["flags"] & item.flags != item.flags
            or metadata["entitlements"] != item.entitlements
            or DEBUG.intersection(metadata["entitlements"])):
        raise RuntimeError(f"Release signature, timestamp, flags, identity, or entitlements did not match the plan: {item.relative}")


def publish_exclusive(staged, output):
    # Darwin's public renamex_np(RENAME_EXCL) atomically publishes without ever
    # replacing another release that appeared after the earlier existence check.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(staged), os.fsencode(output), 0x00000004):
        raise OSError(ctypes.get_errno(), "Atomic release publication failed; existing outputs are never overwritten.")


def remove_stale_tickets(app):
    """Discard inherited s8ch tickets without touching signing resource seals."""
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


def configure_release_updater(staged, notarization_requested):
    """Enable the signed updater only in the separately notarized release copy."""
    release_api = runpy.run_path(str(ROOT / "scripts/github-release.py"))
    release = release_api["load_config"]()
    resources = staged / "Contents/Resources"
    policy_path = resources / "kumo-update-config.json"
    policy = json.loads(policy_path.read_text())
    if any(policy.get(key) != value for key, value in release.items()):
        raise RuntimeError("Packaged updater configuration differs from the selected release.")
    info = bundle_info(staged)
    expected = {
        "CFBundleShortVersionString": release["version"], "CFBundleVersion": release["build"],
        "SUFeedURL": release["feedURL"], "SUPublicEDKey": release["publicEDKey"],
        "SURequireSignedFeed": True, "SUVerifyUpdateBeforeExtraction": True,
        "SUSignedFeedFailureExpirationInterval": 0, "SUEnableSystemProfiling": False,
        "SUAllowsAutomaticUpdates": False,
    }
    if any(info.get(key) != value or type(info.get(key)) is not type(value) for key, value in expected.items()):
        raise RuntimeError("Packaged updater trust or version metadata does not match the release.")
    build_path = resources / "KumoExtension/build-info.json"
    build = json.loads(build_path.read_text())
    release_api["validate_public_model_scope"](build)
    updates = build.get("appUpdates", {})
    if (updates.get("included") is not True or updates.get("repository") != release["repository"]
            or updates.get("feedURL") != release["feedURL"] or updates.get("version") != release["version"]
            or updates.get("build") != release["build"]):
        raise RuntimeError("Packaged update status does not match the release configuration.")
    policy["enabled"] = bool(notarization_requested)
    updates["ready"] = bool(notarization_requested)
    build["signingMode"] = "developer-id"
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    build_path.write_text(json.dumps(build, indent=2) + "\n")


def sign_release(app, output, items, config, identity, profile_bytes, notary_profile, source_hash):
    if running_apps([app, output]) or output.exists():
        raise RuntimeError("Quit the input/output app and choose a new output path before signing.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".kumo-release-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        staged = temporary / output.name
        run("/usr/bin/ditto", "--norsrc", "--noextattr", app, staged)
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", staged)
        if signing_metadata(staged)["cdhash"] != source_hash:
            raise RuntimeError("The input app changed during release preparation; no release was signed.")
        remove_stale_tickets(staged)
        configure_release_updater(staged, bool(notary_profile))
        # Never inherit an upstream/development provisioning profile.
        for name in ("embedded.provisionprofile", "embedded.mobileprovision"):
            for file in staged.rglob(name):
                file.unlink()
        if profile_bytes:
            (staged / "Contents/embedded.provisionprofile").write_bytes(profile_bytes)
        for number, item in enumerate(items):
            target = staged if item.relative == "." else staged / item.relative
            entitlements = temporary / f"entitlements-{number}.plist"
            entitlements.write_bytes(plistlib.dumps(item.entitlements, fmt=plistlib.FMT_XML))
            command = ["/usr/bin/codesign", "--force", "--sign", identity["sha1"], "--timestamp",
                       "--identifier", item.identifier, "--options", hex(item.flags)]
            # Empty files deliberately replace any inherited claims; dylibs also
            # receive an explicit empty set instead of --preserve-metadata.
            run(*command, "--entitlements", entitlements, target)
            verify_item(target, item, config)
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", staged)
        submission = None
        if notary_profile:
            archive = temporary / "notarize.zip"
            run("/usr/bin/ditto", "-c", "-k", "--keepParent", staged, archive)
            result = run("/usr/bin/xcrun", "notarytool", "submit", archive,
                         "--keychain-profile", notary_profile, "--wait", "--output-format", "json", check=False)
            try:
                response = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                raise RuntimeError("notarytool returned no valid JSON result; no release was published.") from None
            submission = response.get("id")
            if result.returncode or response.get("status") != "Accepted" or not submission:
                raise RuntimeError(f"Notarization was not Accepted (status {response.get('status', 'unknown')}); no release was published.")
            run("/usr/bin/xcrun", "stapler", "staple", staged)
            run("/usr/bin/xcrun", "stapler", "validate", staged)
            run("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", staged)
        # Stapling must not invalidate any earlier signature or team check.
        for item in items:
            verify_item(staged if item.relative == "." else staged / item.relative, item, config)
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", staged)
        if running_apps([app, output, staged]):
            raise RuntimeError("An app started during release preparation; quit it and retry.")
        publish_exclusive(staged, output)
        return {"output": str(output), "teamId": config["teamId"], "identity": identity["name"],
                "signedCodeItems": len(items), "notarized": bool(submission), "submissionId": submission,
                "browserPasskeyProfileEmbedded": bool(profile_bytes), "originalAppPreserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--doctor", action="store_true", help="Read public metadata and show readiness (default)")
    mode.add_argument("--dry-run", action="store_true", help="Show every signing item and planned commands; change nothing")
    mode.add_argument("--sign", action="store_true", help="Actually sign a separate copy after all prerequisites pass")
    parser.add_argument("--app", type=Path, default=ROOT / "dist/Kumo.app")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/releases/Kumo.app")
    parser.add_argument("--identity", help="Exact installed Developer ID Application SHA-1 or name for the selected team")
    parser.add_argument("--profile", type=Path, help="Apple-issued Developer ID macOS profile approving Kumo browser passkeys")
    parser.add_argument("--notary-profile", help="Existing notarytool Keychain profile name; no credentials accepted here")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This release signer requires macOS.")
    config = json.loads((ROOT / "config/apple-signing.json").read_text())
    if not re.fullmatch(r"[A-Z0-9]{10}", config["teamId"]) or not re.fullmatch(r"[A-Za-z0-9.-]+", config["bundleIdentifier"]):
        raise RuntimeError("Invalid selected team or bundle identifier in apple-signing.json.")
    app, output = args.app.resolve(), args.output.resolve()
    if (not app.is_dir() or app.suffix != ".app" or output.suffix != ".app"
            or app == output or app.is_relative_to(output) or output.is_relative_to(app)):
        raise RuntimeError("Input must be an existing .app; output must be a separate .app outside it.")
    if args.notary_profile and (not args.notary_profile.strip() or args.notary_profile.startswith("-")
                               or any(ord(value) < 32 for value in args.notary_profile)):
        raise RuntimeError("Use a nonempty existing Keychain profile name, without control characters.")
    blockers = []
    if output.exists():
        blockers.append("Output already exists; choose a new path. Releases are never overwritten.")
    running = running_apps([app, output])
    if running:
        blockers.append("Quit the input/output Kumo app before making a release copy.")
    info = bundle_info(app)
    if info.get("CFBundleIdentifier") != config["bundleIdentifier"] or info.get("CFBundleExecutable") != "Kumo":
        blockers.append("Input must be the completed packaged Kumo app with the selected bundle identifier and Swift launcher.")
    build_file = app / "Contents/Resources/KumoExtension/build-info.json"
    build = json.loads(build_file.read_text())
    try:
        release_api = runpy.run_path(str(ROOT / "scripts/github-release.py"))
        release_api["validate_public_model_scope"](build)
    except RuntimeError as error:
        blockers.append(str(error))
    if build.get("sourceCompiledLocally") is not True:
        blockers.append("Production release requires Kumo's locally compiled source build; this app is the upstream preview.")
    source_version = json.loads((ROOT / "config/source-lock.json").read_text())["chromiumVersion"]
    if not isinstance(source_version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", source_version):
        raise RuntimeError("The current source lock has no valid Chromium target version.")
    if build.get("engineVersion") != source_version or build.get("sourceTargetVersion") != source_version:
        blockers.append("Production release requires engineVersion and sourceTargetVersion to exactly match the current source lock.")
    receipt = build.get("sourceBuildReceipt")
    if not isinstance(receipt, dict):
        blockers.append("Production release requires the verified, embedded local source-build receipt; a source-build Boolean is insufficient.")
    else:
        try:
            receipt_api = runpy.run_path(str(ROOT / "scripts/build_receipt.py"))
            receipt_api["verify_embedded_receipt"](
                receipt, ROOT, receipt_api["current_input_digest"](ROOT), build.get("engineVersion"))
        except (RuntimeError, OSError, ValueError) as error:
            blockers.append("Production source-build receipt is invalid: " + str(error))
    if run("/usr/bin/codesign", "--verify", "--deep", "--strict", app, check=False).returncode:
        blockers.append("Input app failed strict signature verification; complete packaging first.")
    identities = identities_for_team(config["teamId"])
    candidates = [value for value in identities if not args.identity or args.identity in {value["sha1"], value["name"]}]
    identity = candidates[0] if len(candidates) == 1 else None
    if identity is None:
        blockers.append("Select exactly one installed, valid Developer ID Application identity for the configured team; Apple Development is insufficient.")
    profile_file = args.profile.resolve() if args.profile else None
    profile_summary = None
    profile_bytes = None
    if profile_file:
        # Decode the exact bytes we later embed, rather than rereading a path
        # whose contents could change after validation.
        profile_bytes = profile_file.read_bytes()
        decoded = plistlib.loads(run("/usr/bin/security", "cms", "-D", data=profile_bytes).stdout)
        profile_summary = validate_profile(decoded, config, identity["sha1"] if identity else None)
    source_hash = signing_metadata(app)["cdhash"]
    items = inventory(app, config, profile_summary is not None)
    plan = {"mode": "sign" if args.sign else "dry-run" if args.dry_run else "doctor",
            "ready": not blockers, "input": str(app), "output": str(output), "target": config,
            "developerIdIdentities": identities, "selectedIdentity": identity, "profile": profile_summary,
            "inputCodeDirectoryHash": source_hash, "engineVersion": build.get("engineVersion"),
            "managedPasskeysWillBeClaimed": profile_summary is not None,
            "notaryKeychainProfile": args.notary_profile, "runningAppPaths": running,
            "blockers": blockers, "codeItems": [item.summary() for item in items],
            "publication": "Separate sibling staging copy; atomic exclusive rename after verification; input never modified."}
    if args.dry_run:
        plan["commands"] = [
            ["ditto", "--norsrc", "--noextattr", str(app), "<STAGE>/" + output.name],
            *[["codesign", "--force", "--sign", identity["sha1"] if identity else "<MISSING_DEVELOPER_ID>",
               "--timestamp", "--identifier", item.identifier, "--options", hex(item.flags),
               "--entitlements", f"<TEMP>/entitlements-{number}.plist", "<STAGE>/" + output.name + "/" + item.relative]
              for number, item in enumerate(items)],
            ["codesign", "--verify", "--deep", "--strict", "--all-architectures", "<STAGE>/" + output.name]]
        if args.notary_profile:
            plan["commands"] += [["ditto", "-c", "-k", "--keepParent", "<STAGE>/" + output.name, "<TEMP>/notarize.zip"],
                ["xcrun", "notarytool", "submit", "<TEMP>/notarize.zip", "--keychain-profile", args.notary_profile, "--wait", "--output-format", "json"],
                ["xcrun", "stapler", "staple", "<STAGE>/" + output.name], ["xcrun", "stapler", "validate", "<STAGE>/" + output.name]]
    print(json.dumps(plan, indent=2), flush=True)
    if blockers:
        return 1
    if args.sign:
        print(json.dumps(sign_release(app, output, items, config, identity, profile_bytes, args.notary_profile, source_hash), indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, plistlib.InvalidFileException) as error:
        print(f"Release signing stopped: {error}", file=sys.stderr)
        sys.exit(1)
