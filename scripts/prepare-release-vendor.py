#!/usr/bin/env python3
"""Prepare clean, exact upstream Git revisions for a dedicated release runner.

Existing dirty checkouts are refused, never reset or deleted. All paths are
derived from this checkout; ignored vendor/build caches survive workflow runs.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = {
    "macosPackaging": ("https://github.com/ungoogled-software/ungoogled-chromium-macos.git", "vendor/ungoogled-chromium-macos"),
    "ungoogledChromium": ("https://github.com/ungoogled-software/ungoogled-chromium.git", "vendor/ungoogled-chromium-core"),
}


def git(directory, *arguments):
    result = subprocess.run(["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
                             "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-C", str(directory), *arguments],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Pinned vendor Git operation failed: {arguments[0]} (exit {result.returncode}).")
    return result.stdout.strip()


def pins(lock):
    if lock.get("schema") != 1 or lock.get("targetCpu") != "arm64":
        raise RuntimeError("Unsupported release source lock.")
    result = []
    for name, (url, relative) in UPSTREAM.items():
        value = lock.get(name, {})
        if value.get("repository") != url or not isinstance(value.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", value["commit"]):
            raise RuntimeError("Release vendor must use its exact pinned public upstream and commit.")
        if name == "ungoogledChromium" and value.get("path") != relative:
            raise RuntimeError("Unexpected common-core vendor path.")
        result.append((name, url, relative, value["commit"]))
    return result


def prepare(root, lock):
    result = []
    vendor = root / "vendor"
    if vendor.is_symlink() or (vendor.exists() and not vendor.is_dir()):
        raise RuntimeError("Release vendor parent must be a real directory.")
    vendor.mkdir(exist_ok=True)
    for name, url, relative, commit in pins(lock):
        directory = root / relative
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError("Release vendor checkout must be a real directory.")
        if directory.exists():
            if not (directory / ".git").is_dir():
                raise RuntimeError("Existing vendor directory is not an owned standalone checkout; preserve it and choose a clean runner workspace.")
            if git(directory, "remote", "get-url", "origin") != url:
                raise RuntimeError("Existing vendor checkout has a different upstream URL.")
            if git(directory, "status", "--porcelain", "--untracked-files=all"):
                raise RuntimeError("Existing vendor checkout has local changes; they will not be reset.")
        else:
            directory.mkdir()
            git(directory, "init")
            git(directory, "remote", "add", "origin", url)
        git(directory, "fetch", "--depth", "1", "origin", commit)
        git(directory, "-c", "advice.detachedHead=false", "checkout", "--detach", commit)
        if name == "macosPackaging":
            git(directory, "submodule", "sync", "--recursive")
            git(directory, "submodule", "update", "--init", "--recursive", "--depth", "1")
        if git(directory, "rev-parse", "HEAD") != commit or git(directory, "status", "--porcelain", "--untracked-files=all"):
            raise RuntimeError("Vendor revision or clean-state verification failed after checkout.")
        result.append({"path": relative, "commit": commit, "clean": True})
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    lock = json.loads((ROOT / "config/source-lock.json").read_text())
    print(json.dumps({"vendor": prepare(ROOT, lock)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Release vendor preparation stopped: {error}", file=sys.stderr)
        sys.exit(1)
