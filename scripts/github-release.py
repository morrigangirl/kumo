#!/usr/bin/env python3
"""Prepare signed Kumo updates, then upload reviewable GitHub Release assets.

Preparation is local except for the explicitly requested Apple notarization.
Uploading creates a draft; only upload --publish makes it public/latest.
Private signing keys remain in the macOS Keychain.
"""
import argparse
import base64
import ctypes
import datetime as dt
import email.utils
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
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
_PHISHLANG_POLICY = runpy.run_path(str(ROOT / "scripts/phishlang-policy.py"))
REPOSITORY = "morrigangirl/kumo"
FEED_URL = f"https://github.com/{REPOSITORY}/releases/latest/download/appcast.xml"
SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
BUILD = re.compile(r"[1-9][0-9]{0,17}")
TAG = re.compile(r"v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-([1-9][0-9]{0,17})")
ET.register_namespace("sparkle", SPARKLE)


def run(*args, data=None, maximum=16 * 1024 * 1024):
    result = subprocess.run([str(value) for value in args], input=data, capture_output=True)
    if result.returncode:
        # Avoid echoing subprocess output, credentials, private paths, or a
        # notarytool response. All commands use argument arrays, never a shell.
        raise RuntimeError(f"{Path(args[0]).name} {args[1] if len(args) > 1 else ''} failed (exit {result.returncode}).")
    if len(result.stdout) > maximum:
        raise RuntimeError("Command output exceeded the release metadata limit.")
    return result.stdout


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def base64_value(value, size, name):
    if not isinstance(value, str):
        raise RuntimeError(f"A real {name} is required; release signing is not configured.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise RuntimeError(f"Invalid {name}.") from None
    if len(decoded) != size or base64.b64encode(decoded).decode() != value:
        raise RuntimeError(f"Invalid {name}.")
    return value


def load_config(path=ROOT / "config/release.json", require_key=True):
    config = json.loads(Path(path).read_text())
    if not isinstance(config, dict) or set(config) != {"schemaVersion", "repository", "version", "build", "feedURL", "publicEDKey", "signingKeyAccount"}:
        raise RuntimeError("Unexpected release configuration fields.")
    if type(config["schemaVersion"]) is not int or config["schemaVersion"] != 1 or config["repository"] != REPOSITORY or config["feedURL"] != FEED_URL:
        raise RuntimeError("Release configuration must target Kumo's pinned GitHub repository and HTTPS appcast.")
    if not isinstance(config["version"], str) or not VERSION.fullmatch(config["version"]):
        raise RuntimeError("Release version must contain exactly three decimal components.")
    if not isinstance(config["build"], str) or not BUILD.fullmatch(config["build"]):
        raise RuntimeError("Release build must be a positive, increasing integer of at most 18 digits.")
    if config["publicEDKey"] is not None or require_key:
        base64_value(config["publicEDKey"], 32, "Sparkle Ed25519 public key")
    if not isinstance(config["signingKeyAccount"], str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,128}", config["signingKeyAccount"]):
        raise RuntimeError("Invalid Sparkle Keychain account name.")
    return config


def release_tag(config):
    return f'v{config["version"]}-{config["build"]}'


def archive_name(config):
    return f'Kumo-{config["version"]}-{config["build"]}-macos-arm64.zip'


def asset_url(config, filename):
    if Path(filename).name != filename or not re.fullmatch(r"[A-Za-z0-9._-]+", filename):
        raise RuntimeError("Invalid release asset name.")
    return f'https://github.com/{REPOSITORY}/releases/download/{release_tag(config)}/{filename}'


def check_monotonic(config, releases):
    """Refuse downgrade, reused build counters, and ambiguous old release tags."""
    if not isinstance(releases, list):
        raise RuntimeError("GitHub release inventory must be an array.")
    current = release_tag(config)
    matched = None
    current_version = tuple(map(int, config["version"].split(".")))
    for release in releases:
        if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
            raise RuntimeError("Malformed GitHub release metadata.")
        match = TAG.fullmatch(release["tag_name"])
        if not match:
            raise RuntimeError("An existing release has an unrecognized build tag; reconcile its version before publishing.")
        if release["tag_name"] == current:
            if release.get("draft") is not True or matched is not None:
                raise RuntimeError("This release already exists publicly or appears more than once; published assets are immutable.")
            matched = release
            continue
        if int(match[2]) >= int(config["build"]):
            raise RuntimeError("Release build must exceed every existing release build, including drafts.")
        if tuple(map(int, match[1].split("."))) > current_version:
            raise RuntimeError("Release marketing version must not decrease.")
    return matched


def validate_public_model_scope(build):
    """Require explicit project authorization without rewriting upstream facts."""
    _PHISHLANG_POLICY["validate_public_model_scope"](build, ROOT)


def app_metadata(app, config, production=False):
    if app.name != "Kumo.app" or not app.is_dir() or app.is_symlink():
        raise RuntimeError("The release input must be a real Kumo.app directory.")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    signing = json.loads((ROOT / "config/apple-signing.json").read_text())
    expected = {"CFBundleIdentifier": signing["bundleIdentifier"], "CFBundleExecutable": "Kumo",
                "CFBundleShortVersionString": config["version"], "CFBundleVersion": config["build"],
                "SUFeedURL": config["feedURL"], "SUPublicEDKey": config["publicEDKey"],
                "SURequireSignedFeed": True, "SUVerifyUpdateBeforeExtraction": True,
                "SUSignedFeedFailureExpirationInterval": 0, "SUEnableSystemProfiling": False,
                "SUAllowsAutomaticUpdates": False}
    for key, value in expected.items():
        # bool is a subclass of int in Python: also compare exact types.
        if info.get(key) != value or type(info.get(key)) is not type(value):
            raise RuntimeError(f"Packaged app does not match the release policy: {key}.")
    minimum = info.get("LSMinimumSystemVersion")
    if not isinstance(minimum, str) or not re.fullmatch(r"[1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?", minimum):
        raise RuntimeError("App has no supported minimum macOS version.")
    minimum = minimum if minimum.count(".") == 2 else minimum + ".0"
    build = json.loads((app / "Contents/Resources/KumoExtension/build-info.json").read_text())
    if not isinstance(build, dict) or build.get("sourceCompiledLocally") is not True or not isinstance(build.get("sourceBuildReceipt"), dict):
        raise RuntimeError("Releases require the completed local Chromium source-build receipt.")
    if production:
        validate_public_model_scope(build)
    receipt_api = runpy.run_path(str(ROOT / "scripts/build_receipt.py"))
    receipt_api["verify_embedded_receipt"](build["sourceBuildReceipt"], ROOT,
                                         receipt_api["current_input_digest"](ROOT), build.get("engineVersion"))
    runtime = json.loads((app / "Contents/Resources/kumo-update-config.json").read_text())
    if not isinstance(runtime, dict):
        raise RuntimeError("App updater configuration must be a dictionary.")
    for key in ("schemaVersion", "repository", "version", "build", "feedURL", "publicEDKey"):
        if runtime.get(key) != config[key] or type(runtime.get(key)) is not type(config[key]):
            raise RuntimeError(f"App's updater configuration differs from the release policy: {key}.")
    app_updates = build.get("appUpdates")
    if production and (runtime.get("enabled") is not True or not isinstance(app_updates, dict) or app_updates.get("ready") is not True):
        raise RuntimeError("The release app has not enabled its verified production updater.")
    return {"bundleIdentifier": signing["bundleIdentifier"], "signingTeamId": signing["teamId"],
            "minimumSystemVersion": minimum, "engineVersion": build.get("engineVersion"),
            "sourceBuildReceiptSha256": build["sourceBuildReceipt"].get("receiptSha256")}


def verify_developer_id(app, team):
    requirement = ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   f'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "{team}"')
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", f"-R={requirement}", app)
    run("/usr/bin/xcrun", "stapler", "validate", app)
    run("/usr/sbin/spctl", "--assess", "--type", "execute", app)
    details = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)], capture_output=True, check=True).stderr.decode()
    match = re.search(r"^CDHash=([0-9a-f]{40})$", details, re.M)
    if not match or "Timestamp=" not in details:
        raise RuntimeError("Release app requires a timestamped Developer ID signature.")
    return match[1]


def tools(config):
    # This verifier must not download or modify tools. Preparing the pinned
    # official distribution is a separate build step.
    run(sys.executable, ROOT / "scripts/prepare-sparkle.py", "--verify")
    directory = ROOT / "build/sparkle/bin"
    public = run(directory / "generate_keys", "--account", config["signingKeyAccount"], "-p", maximum=4096).decode().strip()
    if public != config["publicEDKey"]:
        raise RuntimeError("The existing Keychain signing key does not match the committed public key.")
    return directory / "sign_update"


def sign_archive(signer, config, archive):
    signature = run(signer, "--account", config["signingKeyAccount"], "-p", archive, maximum=4096).decode().strip()
    base64_value(signature, 64, "archive signature")
    run(signer, "--account", config["signingKeyAccount"], "--verify", archive, signature)
    return signature


def appcast(config, metadata, size, signature, notes, published=None):
    base64_value(signature, 64, "archive signature")
    if type(size) is not int or not 0 < size < 2 * 1024 ** 3:
        raise RuntimeError("Update archive must fit GitHub's release asset limit (under 2 GiB).")
    published = published or dt.datetime.now(dt.timezone.utc)
    if published.tzinfo is None:
        raise RuntimeError("Release time must include a timezone.")
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "Kumo updates"
    ET.SubElement(channel, "link").text = f"https://github.com/{REPOSITORY}/releases"
    ET.SubElement(channel, "description").text = "Signed Kumo macOS browser releases"
    item = ET.SubElement(channel, "item")
    ET.SubElement(item, "title").text = f'Kumo {config["version"]}'
    ET.SubElement(item, "link").text = f'https://github.com/{REPOSITORY}/releases/tag/{release_tag(config)}'
    ET.SubElement(item, f"{{{SPARKLE}}}version").text = config["build"]
    ET.SubElement(item, f"{{{SPARKLE}}}shortVersionString").text = config["version"]
    ET.SubElement(item, f"{{{SPARKLE}}}minimumSystemVersion").text = metadata["minimumSystemVersion"]
    ET.SubElement(item, f"{{{SPARKLE}}}hardwareRequirements").text = "arm64"
    ET.SubElement(item, "pubDate").text = email.utils.format_datetime(published.astimezone(dt.timezone.utc))
    ET.SubElement(item, "description", {f"{{{SPARKLE}}}format": "plain-text"}).text = notes
    ET.SubElement(item, "enclosure", {"url": asset_url(config, archive_name(config)), "length": str(size),
                                     "type": "application/octet-stream", f"{{{SPARKLE}}}edSignature": signature})
    ET.indent(rss)
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True) + b"\n"


def git_commit():
    if run("git", "-C", ROOT, "status", "--porcelain", "--untracked-files=normal").strip():
        raise RuntimeError("Commit the reviewed release inputs first; the release checkout must be clean.")
    commit = run("git", "-C", ROOT, "rev-parse", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("Release checkout has no exact Git commit.")
    return commit


def publish_directory(staging, output):
    # A race must never replace an earlier release directory.
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(staging), os.fsencode(output), 0x00000004):  # RENAME_EXCL
        raise RuntimeError("Release output already exists or could not be published exclusively.")


def prepare(args, config):
    if sys.platform != "darwin":
        raise RuntimeError("Preparing a notarized Kumo release requires macOS.")
    if not args.notary_profile:
        raise RuntimeError("An existing notarytool Keychain profile is required; unnotarized releases are refused.")
    commit = git_commit()
    app = args.app.resolve()
    metadata = app_metadata(app, config)
    validate_public_model_scope(json.loads((app / "Contents/Resources/KumoExtension/build-info.json").read_text()))
    signer = tools(config)
    notes_bytes = args.notes.read_bytes()
    if not notes_bytes or len(notes_bytes) > 65536:
        raise RuntimeError("Release notes must contain 1–65536 UTF-8 bytes.")
    notes = notes_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
    if any(ord(value) < 32 and value not in "\n\t" for value in notes):
        raise RuntimeError("Release notes contain unsupported control characters.")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError("Output already exists; release directories are never overwritten.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".kumo-github-release-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        signed = temporary / "Kumo.app"
        command = [sys.executable, ROOT / "scripts/sign-release.py", "--sign", "--app", app,
                   "--output", signed, "--notary-profile", args.notary_profile]
        if getattr(args, "notary_keychain", None) is not None:
            command += ["--notary-keychain", args.notary_keychain]
        if args.identity:
            command += ["--identity", args.identity]
        if args.profile:
            command += ["--profile", args.profile]
        run(*command)
        app_metadata(signed, config, production=True)
        metadata["codeDirectoryHash"] = verify_developer_id(signed, metadata["signingTeamId"])
        metadata["notarized"] = True
        staged = temporary / "assets"
        staged.mkdir(mode=0o700)
        archive = staged / archive_name(config)
        run("/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", signed, archive)
        signature = sign_archive(signer, config, archive)
        feed = staged / "appcast.xml"
        feed.write_bytes(appcast(config, metadata, archive.stat().st_size, signature, notes))
        run(signer, "--account", config["signingKeyAccount"], feed)
        run(signer, "--account", config["signingKeyAccount"], "--verify", feed)
        (staged / "release-notes.md").write_text(notes)
        manifest = {"schemaVersion": 1, "repository": REPOSITORY, "tag": release_tag(config),
                    "version": config["version"], "build": config["build"], "feedURL": config["feedURL"],
                    "publicEDKey": config["publicEDKey"], "commit": commit, "app": metadata,
                    "archive": {"name": archive.name, "url": asset_url(config, archive.name),
                                "length": archive.stat().st_size, "sha256": digest(archive), "edSignature": signature},
                    "appcast": {"name": "appcast.xml", "sha256": digest(feed)},
                    "releaseNotes": {"name": "release-notes.md", "sha256": digest(staged / "release-notes.md")}}
        (staged / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        names = [archive.name, "appcast.xml", "release-notes.md", "release.json"]
        (staged / "SHA256SUMS").write_text("".join(f"{digest(staged / name)}  {name}\n" for name in sorted(names)))
        # Extract and inspect the bytes that will actually be distributed.
        verify_assets(staged, config, signer)
        if git_commit() != commit:
            raise RuntimeError("Checkout changed during release preparation.")
        publish_directory(staged, output)
    return {"prepared": True, "tag": release_tag(config), "output": str(output), "uploaded": False}


def verify_assets(directory, config, signer=None):
    directory = directory.resolve()
    expected = {archive_name(config), "appcast.xml", "release.json", "release-notes.md", "SHA256SUMS"}
    if {entry.name for entry in directory.iterdir()} != expected:
        raise RuntimeError("Release directory must contain exactly the five expected assets.")
    for name in expected:
        entry = directory / name
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("Release assets must be regular files without symlinks or hard links.")
    if (directory / "release.json").stat().st_size > 65536 or (directory / "appcast.xml").stat().st_size > 131072:
        raise RuntimeError("Release metadata exceeds its size limit.")
    manifest = json.loads((directory / "release.json").read_text())
    if not isinstance(manifest, dict):
        raise RuntimeError("Release manifest must be a dictionary.")
    for key, value in {"schemaVersion": 1, "repository": REPOSITORY, "tag": release_tag(config),
                       "version": config["version"], "build": config["build"], "feedURL": FEED_URL,
                       "publicEDKey": config["publicEDKey"]}.items():
        if manifest.get(key) != value or type(manifest.get(key)) is not type(value):
            raise RuntimeError(f"Release manifest does not match configuration: {key}.")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", "")):
        raise RuntimeError("Release manifest has no exact Git commit.")
    archive = directory / archive_name(config)
    archive_metadata = manifest.get("archive", {})
    if not isinstance(archive_metadata, dict) or not isinstance(manifest.get("app"), dict):
        raise RuntimeError("Release archive and application metadata must be dictionaries.")
    if archive_metadata.get("name") != archive.name or archive_metadata.get("url") != asset_url(config, archive.name):
        raise RuntimeError("Release archive must use the exact immutable GitHub tag URL.")
    if (type(archive_metadata.get("length")) is not int or not 0 < archive.stat().st_size < 2 * 1024 ** 3
            or archive_metadata.get("length") != archive.stat().st_size or archive_metadata.get("sha256") != digest(archive)):
        raise RuntimeError("Release archive length or checksum changed.")
    signature = base64_value(archive_metadata.get("edSignature"), 64, "archive signature")
    for key, name in [("appcast", "appcast.xml"), ("releaseNotes", "release-notes.md")]:
        if manifest.get(key) != {"name": name, "sha256": digest(directory / name)}:
            raise RuntimeError("Release appcast or notes checksum changed.")
    checksums = "".join(f"{digest(directory / name)}  {name}\n" for name in sorted(expected - {"SHA256SUMS"}))
    if (directory / "SHA256SUMS").read_text() != checksums:
        raise RuntimeError("Release checksum list is invalid.")
    signer = signer or tools(config)
    run(signer, "--account", config["signingKeyAccount"], "--verify", archive, signature)
    run(signer, "--account", config["signingKeyAccount"], "--verify", directory / "appcast.xml")
    xml = ET.fromstring((directory / "appcast.xml").read_bytes())
    items = xml.findall("./channel/item")
    if len(items) != 1:
        raise RuntimeError("The stable appcast must describe exactly one current release.")
    item = items[0]
    enclosure = item.find("enclosure")
    if (item.findtext(f"{{{SPARKLE}}}version") != config["build"]
            or item.findtext(f"{{{SPARKLE}}}shortVersionString") != config["version"]
            or item.findtext(f"{{{SPARKLE}}}minimumSystemVersion") != manifest.get("app", {}).get("minimumSystemVersion")
            or item.findtext(f"{{{SPARKLE}}}hardwareRequirements") != "arm64"
            or item.find("description") is None
            or item.find("description").get(f"{{{SPARKLE}}}format") != "plain-text"
            or item.findtext("description") != (directory / "release-notes.md").read_text()
            or enclosure is None or enclosure.attrib != {"url": archive_metadata["url"], "length": str(archive_metadata["length"]),
                     "type": "application/octet-stream", f"{{{SPARKLE}}}edSignature": signature}):
        raise RuntimeError("Signed appcast does not match the intended release archive.")
    with tempfile.TemporaryDirectory(prefix="kumo-release-verification-") as temporary:
        run("/usr/bin/ditto", "-x", "-k", archive, temporary)
        extracted = Path(temporary) / "Kumo.app"
        metadata = app_metadata(extracted, config, production=True)
        metadata["codeDirectoryHash"] = verify_developer_id(extracted, metadata["signingTeamId"])
        metadata["notarized"] = True
        if metadata != manifest.get("app"):
            raise RuntimeError("Archived app identity, source receipt or notarization metadata changed.")
    return manifest


def github_releases(config):
    pages = json.loads(run("gh", "api", "--paginate", "--slurp", f'repos/{config["repository"]}/releases?per_page=100'))
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise RuntimeError("GitHub returned no bounded release inventory.")
    return [release for page in pages for release in page]


def remote_tag_commit(config):
    """Resolve lightweight or annotated remote tags; --target alone is ignored
    by GitHub when a tag already exists, so it cannot establish this binding.
    """
    value = json.loads(run("gh", "api", f'repos/{REPOSITORY}/git/ref/tags/{release_tag(config)}'))
    for _ in range(8):
        item = value.get("object", {}) if isinstance(value, dict) else {}
        if not isinstance(item, dict):
            break
        kind, sha = item.get("type"), item.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            break
        if kind == "commit":
            return sha
        if kind != "tag":
            break
        value = json.loads(run("gh", "api", f"repos/{REPOSITORY}/git/tags/{sha}"))
    raise RuntimeError("The remote release tag does not resolve to one bounded Git commit.")


def upload(args, config):
    directory = args.artifacts.resolve()
    manifest = verify_assets(directory, config)
    if git_commit() != manifest["commit"]:
        raise RuntimeError("Upload must use the clean checkout from which these assets were prepared.")
    tag = release_tag(config)
    if run("git", "-C", ROOT, "rev-parse", f"refs/tags/{tag}^{{commit}}").decode().strip() != manifest["commit"]:
        raise RuntimeError("The reviewed release tag must point to the prepared source commit.")
    if remote_tag_commit(config) != manifest["commit"]:
        raise RuntimeError("The GitHub release tag points to a different commit.")
    existing = check_monotonic(config, github_releases(config))
    files = sorted(entry.name for entry in directory.iterdir())
    notes = directory / "release-notes.md"
    if existing is None:
        run("gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--verify-tag",
            "--target", manifest["commit"], "--title", f'Kumo {config["version"]}', "--notes-file", notes)
    # Reconcile partial failed uploads without clobbering any existing bytes.
    remote = json.loads(run("gh", "release", "view", tag, "--repo", REPOSITORY,
                            "--json", "assets,isDraft,isPrerelease,tagName,name,body"))
    if (not isinstance(remote, dict) or remote.get("isDraft") is not True or remote.get("tagName") != tag
            or remote.get("isPrerelease") is not False
            or remote.get("name") != f'Kumo {config["version"]}'
            or remote.get("body", "").rstrip() != notes.read_text().rstrip()):
        raise RuntimeError("Existing draft identity or notes differ; review it before continuing.")
    assets = remote.get("assets")
    if not isinstance(assets, list) or any(not isinstance(value, dict) or value.get("name") not in files for value in assets):
        raise RuntimeError("Existing draft contains unexpected assets.")
    present = [value["name"] for value in assets]
    if len(set(present)) != len(present):
        raise RuntimeError("Existing draft contains duplicate asset names.")
    with tempfile.TemporaryDirectory(prefix="kumo-github-assets-") as temporary:
        for name in present:
            run("gh", "release", "download", tag, "--repo", REPOSITORY, "--pattern", name, "--dir", temporary)
            if digest(Path(temporary) / name) != digest(directory / name):
                raise RuntimeError("An uploaded asset differs; published release assets are never overwritten.")
    missing = [directory / name for name in files if name not in present]
    if missing:
        run("gh", "release", "upload", tag, "--repo", REPOSITORY, *missing)
    # Fetch every completed draft asset before allowing public publication.
    with tempfile.TemporaryDirectory(prefix="kumo-github-draft-verification-") as temporary:
        run("gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", temporary)
        verify_assets(Path(temporary), config)
        for name in files:
            if digest(Path(temporary) / name) != digest(directory / name):
                raise RuntimeError("GitHub draft download differs from the locally verified assets.")
    check_monotonic(config, github_releases(config))
    if args.publish:
        if remote_tag_commit(config) != manifest["commit"]:
            raise RuntimeError("The GitHub release tag changed before publication.")
        run("gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest")
    return {"uploaded": True, "published": bool(args.publish), "tag": tag,
            "url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}", "feedURL": FEED_URL}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    doctor_parser = commands.add_parser("doctor", help="Read release configuration and report local prerequisites without signing or uploading")
    doctor_parser.add_argument("--app", type=Path, default=ROOT / "dist/Kumo.app")
    prepare_parser = commands.add_parser("prepare", help="Sign, notarize and archive a separate app; upload nothing to GitHub")
    prepare_parser.add_argument("--app", type=Path, default=ROOT / "dist/Kumo.app")
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--notes", type=Path, required=True)
    prepare_parser.add_argument("--identity")
    prepare_parser.add_argument("--profile", type=Path)
    prepare_parser.add_argument("--notary-profile", required=True)
    prepare_parser.add_argument("--notary-keychain", type=Path,
                                help="Keychain file containing the saved notary profile")
    verify_parser = commands.add_parser("verify", help="Verify release assets and archived Developer ID/notarized app locally")
    verify_parser.add_argument("--artifacts", type=Path, required=True)
    upload_parser = commands.add_parser("upload", help="Upload verified assets to a GitHub draft; --publish also makes it public/latest")
    upload_parser.add_argument("--artifacts", type=Path, required=True)
    upload_parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    config = load_config(require_key=args.command != "doctor")
    if args.command == "doctor":
        blockers = []
        if config["publicEDKey"] is None:
            blockers.append("The public Sparkle signing key has not been configured.")
        if not (ROOT / "build/sparkle/bin/sign_update").is_file():
            blockers.append("Prepare the pinned official Sparkle distribution first.")
        build_path = args.app / "Contents/Resources/KumoExtension/build-info.json"
        if build_path.is_file():
            try:
                validate_public_model_scope(json.loads(build_path.read_text()))
            except RuntimeError as error:
                blockers.append(str(error))
        blockers.append("Production preparation also requires a clean committed source build, Developer ID identity, and existing notarytool Keychain profile.")
        print(json.dumps({"repository": REPOSITORY, "tag": release_tag(config), "feedURL": FEED_URL,
                          "keyConfigured": config["publicEDKey"] is not None,
                          "blockersOrRequiredChecks": blockers, "uploadsPerformed": False}, indent=2))
        return 0
    if sys.platform != "darwin":
        parser.error("Production release verification and publishing require macOS.")
    result = prepare(args, config) if args.command == "prepare" else upload(args, config) if args.command == "upload" else {
        "verified": True, "tag": verify_assets(args.artifacts, config)["tag"], "uploadsPerformed": False}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, ET.ParseError) as error:
        print(f"Release stopped: {error}", file=sys.stderr)
        sys.exit(1)
