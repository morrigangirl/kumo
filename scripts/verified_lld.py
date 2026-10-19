#!/usr/bin/env python3
"""Install only a checksum-pinned LLD executable from an LLVM zstd archive.

The archive and extracted executable have independent mandatory SHA256 pins.
Attestation fields are descriptive lock metadata; this helper does not claim to
verify a signature or attestation. Published destinations are immutable: an
existing incomplete or different directory is an error, never a repair target.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit


class LinkerError(RuntimeError):
    pass


def _sha(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LinkerError(f"Invalid {label} SHA256")
    return value


def _url(value, label):
    if not isinstance(value, str) or any(character.isspace() for character in value):
        raise LinkerError(f"Invalid {label} URL")
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and
                 not parsed.username and not parsed.password and
                 parsed.port in (None, 443) and not parsed.query and not parsed.fragment)
    except ValueError as error:
        raise LinkerError(f"Invalid {label} URL") from error
    if not valid:
        raise LinkerError(f"Invalid {label} URL")
    return parsed


def _settings(settings):
    if not isinstance(settings, dict):
        raise LinkerError("LLD settings must be a dictionary")
    required = {"version", "url", "sha256", "archiveRoot", "binarySha256",
                "binarySize", "relativePath"}
    if not required.issubset(settings):
        raise LinkerError("Missing required LLD settings")
    result = dict(settings)
    version = result["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise LinkerError("Invalid LLD version")
    _sha(result["sha256"], "archive")
    binary_sha = _sha(result["binarySha256"], "binary")
    if type(result["binarySize"]) is not int or result["binarySize"] <= 0:
        raise LinkerError("Invalid LLD binary size")
    archive_root = result["archiveRoot"]
    if (not isinstance(archive_root, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", archive_root) or
            archive_root in (".", "..")):
        raise LinkerError("Invalid LLD archive root")
    expected = f"third_party/kumo-lld/{version}-{binary_sha}"
    if result["relativePath"] != expected:
        raise LinkerError("LLD relativePath must contain its version and full binary SHA256")
    parsed = _url(result["url"], "archive")
    filename = PurePosixPath(parsed.path).name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\.tar\.zst", filename):
        raise LinkerError("Invalid LLD archive filename")
    result["cacheName"] = filename
    attestation = ("attestationUrl" in result, "attestationSha256" in result)
    if attestation[0] != attestation[1]:
        raise LinkerError("Attestation metadata requires both URL and SHA256")
    if attestation[0]:
        _url(result["attestationUrl"], "attestation")
        _sha(result["attestationSha256"], "attestation")
    return result


def _root(path):
    try:
        result = Path(path).resolve(strict=True)
    except OSError as error:
        raise LinkerError(f"Missing root directory: {path}") from error
    if not result.is_dir():
        raise LinkerError(f"Expected root directory: {path}")
    return result


def _directories(root, parts, *, create):
    current = root
    for part in parts:
        current = current / part
        if create:
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                pass
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise LinkerError(f"Missing LLD directory: {current}") from error
        if not stat.S_ISDIR(info.st_mode):
            raise LinkerError(f"LLD directory must not be a symlink or non-directory: {current}")
    return current


def _file_sha(path):
    """Hash a regular file without following its final path component."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise LinkerError(f"Expected regular file: {path}")
            result = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                result.update(chunk)
            after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise LinkerError(f"File changed during verification: {path}")
        return result.hexdigest(), after
    except OSError as error:
        raise LinkerError(f"Cannot verify regular file: {path}") from error


def _verify_destination(destination, settings):
    for directory, names in ((destination, {"bin"}),
                             (destination / "bin", {"lld", "ld64.lld"})):
        try:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
                raise LinkerError(f"Invalid immutable LLD directory: {directory}")
            if {item.name for item in directory.iterdir()} != names:
                raise LinkerError(f"Unexpected or missing immutable LLD entries: {directory}")
        except OSError as error:
            raise LinkerError(f"Missing or invalid immutable LLD directory: {directory}") from error
    binary = destination / "bin/lld"
    checksum, info = _file_sha(binary)
    if (checksum != settings["binarySha256"] or info.st_size != settings["binarySize"] or
            stat.S_IMODE(info.st_mode) != 0o755 or info.st_nlink != 1):
        raise LinkerError(f"Immutable LLD binary hash, size, mode, or link count differs: {binary}")
    link = destination / "bin/ld64.lld"
    try:
        if not link.is_symlink() or os.readlink(link) != "lld":
            raise LinkerError(f"Immutable LLD symlink must point literally to lld: {link}")
    except OSError as error:
        raise LinkerError(f"Cannot verify immutable LLD symlink: {link}") from error
    return link


def verify_linker(src: Path, settings: dict) -> Path:
    """Verify an existing immutable installation without writes or downloads."""
    settings = _settings(settings)
    src = _root(src)
    parts = PurePosixPath(settings["relativePath"]).parts
    _directories(src, parts[:-1], create=False)
    return _verify_destination(src.joinpath(*parts), settings)


def _archive(root, settings):
    cache = _directories(root, (".cache", "source-downloads"), create=True)
    archive = cache / settings["cacheName"]
    if os.path.lexists(archive):
        if _file_sha(archive)[0] != settings["sha256"]:
            raise LinkerError(f"Cached LLD archive checksum mismatch: {archive}")
        return archive
    partial = archive.with_name(archive.name + ".part")
    lock = archive.with_name(archive.name + ".download-lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise LinkerError(f"LLD download already locked: {lock}") from error
    os.close(descriptor)
    try:
        if os.path.lexists(partial):
            info = partial.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LinkerError(f"LLD partial archive must be a regular file with one link: {partial}")
        subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                        "--retry", "3", "--continue-at", "-", "--proto", "=https",
                        "--proto-redir", "=https", "--output", str(partial),
                        settings["url"]], check=True)
        if _file_sha(partial)[0] != settings["sha256"]:
            raise LinkerError(f"Downloaded LLD archive checksum mismatch: {partial}")
        try:
            # A hard-link publication cannot overwrite a concurrent cache file.
            os.link(partial, archive, follow_symlinks=False)
        except FileExistsError:
            if _file_sha(archive)[0] != settings["sha256"]:
                raise LinkerError(f"Concurrent LLD cache checksum mismatch: {archive}")
        partial.unlink()
        return archive
    except (OSError, subprocess.SubprocessError) as error:
        raise LinkerError(f"Could not download verified LLD archive: {archive}") from error
    finally:
        lock.unlink()


def _extract(archive, staging, settings):
    names = {f'{settings["archiveRoot"]}/bin/lld': "binary",
             f'{settings["archiveRoot"]}/bin/ld64.lld': "symlink"}
    seen = set()
    binary_dir = staging / "bin"
    binary_dir.mkdir(mode=0o755)
    binary_dir.chmod(0o755)
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(["zstd", "--decompress", "--stdout", "--long=31",
                                    "--", str(archive)], stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|", ignore_zeros=True) as contents:
                for member in contents:
                    name = member.name.rstrip("/") if member.isdir() else member.name
                    parts = name.split("/")
                    if (not name or "\\" in name or any(part in ("", ".", "..") for part in parts) or
                            parts[0] != settings["archiveRoot"]):
                        raise LinkerError(f"Unsafe or unexpected LLD archive path: {member.name!r}")
                    if name not in names:
                        continue
                    if name in seen:
                        raise LinkerError(f"Duplicate selected LLD archive entry: {name}")
                    seen.add(name)
                    if names[name] == "symlink":
                        if (not member.issym() or member.linkname != "lld" or member.size != 0 or
                                member.mode != 0o755):
                            raise LinkerError("LLD archive ld64.lld must be a mode-0755 symlink to lld")
                        (binary_dir / "ld64.lld").symlink_to("lld")
                        continue
                    if (not member.isreg() or member.sparse is not None or
                            member.size != settings["binarySize"] or member.mode != 0o755):
                        raise LinkerError("LLD archive lld must be a regular mode-0755 file of locked size")
                    source = contents.extractfile(member)
                    if source is None:
                        raise LinkerError("Missing selected LLD archive binary data")
                    checksum = hashlib.sha256()
                    length = 0
                    with source, (binary_dir / "lld").open("xb") as target:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            length += len(chunk)
                            checksum.update(chunk)
                            target.write(chunk)
                    if length != settings["binarySize"] or checksum.hexdigest() != settings["binarySha256"]:
                        raise LinkerError("Extracted LLD binary checksum or size mismatch")
                    (binary_dir / "lld").chmod(0o755)
            # Consume the complete zstd frame, including checksum/truncation errors.
            while process.stdout.read(1024 * 1024):
                pass
            if process.wait() != 0:
                errors.seek(0)
                raise LinkerError("LLD zstd decompression failed: " + errors.read(4096).decode(errors="replace"))
            if seen != set(names):
                raise LinkerError("Missing selected LLD archive entries")
        except (tarfile.TarError, OSError) as error:
            raise LinkerError("Invalid LLD compressed archive") from error
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def _rename_exclusive(source, destination):
    """Atomic directory publication that never replaces an existing path."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = library.renamex_np
        function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        arguments = (os.fsencode(source), os.fsencode(destination), 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        function = library.renameat2
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        arguments = (-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise LinkerError("Atomic no-replace directory rename is unavailable on this platform")
    function.restype = ctypes.c_int
    if function(*arguments) != 0:
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise LinkerError(f"Immutable LLD destination already exists: {destination}")
        raise LinkerError(f"Atomic LLD publication failed: {os.strerror(code)}")


def ensure_linker(src: Path, root: Path, settings: dict) -> Path:
    """Verify/download the locked archive and atomically install its LLD only."""
    settings = _settings(settings)
    src, root = _root(src), _root(root)
    parts = PurePosixPath(settings["relativePath"]).parts
    destination = src.joinpath(*parts)
    # Validate existing ancestors before following a destination path.
    existing = src
    for part in parts[:-1]:
        existing = existing / part
        if not os.path.lexists(existing):
            break
        if not stat.S_ISDIR(existing.lstat().st_mode):
            raise LinkerError(f"LLD ancestor is a symlink or non-directory: {existing}")
    if os.path.lexists(destination):
        return verify_linker(src, settings)
    archive = _archive(root, settings)  # Verify archive before any extraction.
    parent = _directories(src, parts[:-1], create=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-lld-", dir=parent))
    try:
        staging.chmod(0o755)
        _extract(archive, staging, settings)
        _verify_destination(staging, settings)
        _rename_exclusive(staging, destination)
        return verify_linker(src, settings)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
