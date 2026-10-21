#!/usr/bin/env python3
"""Guard the exact macOS 155 recipe port to Chromium 156's official tools.

The upstream checkouts remain immutable. Only a fresh copied recipe is adapted;
replay or drift requires a new workspace. Keep Chromium's Rust parsers, compiler
consistency checks, sanitizer logic and GN include checks instead of reviving
fallbacks for the former external LLVM/Rust distribution.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from urllib.parse import urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
VERSION = "156.0.8078.47"
MACOS_COMMIT = "28552f14731fe8f60422e19bbc2361468d420b25"
COMMON_COMMIT = "0673f8701c94e5688c33ef8ce5e36602d311d246"
CHROMIUM_COMMIT = "1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775"
_ORIGINAL = {
    "patches/series": "01749d41c829517e9bcdcf56a1698edf9c2c4cfb0232aa3060ea8e4ee4d76b28",
    "downloads-arm64.ini": "019cfa595f29da37510ca803e3864b1715bfc70872882604ae5d23b8050aa1de",
    "retrieve_and_unpack_resource.py": "338ce89506e5075dca5ef71582d28f800a54364a6581cbc6c90de65e223e7fd2",
}
_RETAINED = (
    "disable-crashpad-handler.patch", "disable-symbol-order-verification.patch",
    "fix-disabling-safebrowsing.patch", "fix-dsymutil.patch",
    "fix-nasm-build-config.patch", "use-system-python.patch", "fix-esbuild.patch",
    "fix-typescript-isolated-declarations.patch",
)
_RUST_REWIRING = '''    rust_name = f"{'aarch64' if host_arch == 'arm64' else 'x86_64'}-apple-darwin"
    rust_dir = SRC_DIR / "third_party" / "rust-toolchain"
    rust_bin_dir = rust_dir / "bin"
    rust_lib_dir = rust_dir / f"rust-std-{rust_name}" / "lib" / "rustlib" / rust_name / "lib"
    rustc_lib_dir = rust_dir / "rustc" / "lib" / "rustlib" / rust_name / "lib"

    rust_bin_dir.mkdir(parents=True, exist_ok=True)
    (rust_dir / "lib").mkdir(parents=True, exist_ok=True)
    (rust_bin_dir / "rustc").symlink_to(rust_dir / "rustc" / "bin" / "rustc")
    (rust_bin_dir / "cargo").symlink_to(rust_dir / "cargo" / "bin" / "cargo")
    (rust_bin_dir / "rustfmt").symlink_to(
        rust_dir / "rustfmt-preview" / "bin" / "rustfmt")
    rustc_lib_dir.symlink_to(rust_lib_dir)
    (rust_dir / "rustfmt-preview" / "lib").symlink_to(rust_dir / "rustc" / "lib")
'''
_OLD_INSTALL_NAME = '''    (llvm_bin_dir / "install_name_tool").symlink_to(
        llvm_bin_dir / "llvm-install-name-tool")
'''
_NEW_INSTALL_NAME = '''    # The official archive is already in Chromium's bin/lib layout.
    install_name_tool = llvm_bin_dir / "install_name_tool"
    if os.path.lexists(install_name_tool):
        if (not install_name_tool.is_symlink() or
                os.readlink(install_name_tool) != "llvm-install-name-tool"):
            raise RuntimeError("Unexpected install_name_tool entry")
    else:
        install_name_tool.symlink_to("llvm-install-name-tool")
'''
# Exact expected output hashes bind the copied retriever and series after the
# narrowly scoped policy transformation. Their inputs are whole-file pinned.
_ADAPTED_RETRIEVER_SHA256 = "5295aff11a39ee7baa42f9632284702fa0c9063137dc4422c4bc7a0414a9471a"
_TOOLCHAINS = {'source': {'commit': '1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775',
            'url': 'https://chromium.googlesource.com/chromium/src/+/1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775/DEPS',
            'sha256': '3535b3175635f9984c82a3f0c2a8e70f0ed2cfdb2a352f40446c9fddf2490703'},
 'clang': {'url': 'https://commondatastorage.googleapis.com/chromium-browser-clang/Mac_arm64/clang-llvmorg-24-init-7747-g62397f8b-53.tar.xz',
           'sha256': '7ce015cde974fc32bb80e1f48aa7dddbdcbe44fd6f8614de5e63cae4733960d5',
           'size': 44452152,
           'generation': 1790402697155562,
           'outputPath': 'third_party/llvm-build/Release+Asserts',
           'revision': 'llvmorg-24-init-7747-g62397f8b-53'},
 'rust': {'url': 'https://commondatastorage.googleapis.com/chromium-browser-clang/Mac_arm64/rust-toolchain-1edd55dcfcd573872c727fa3e086369a71661ee0-2-llvmorg-24-init-7747-g62397f8b.tar.xz',
          'sha256': '5db21ffd4909ce82c0832df9d1eb06b01b15a54176b7341e39f7181f4b483dbc',
          'size': 248304876,
          'generation': 1789143391575553,
          'outputPath': 'third_party/rust-toolchain',
          'revision': '1edd55dcfcd573872c727fa3e086369a71661ee0-2-llvmorg-24-init-7747-g62397f8b',
          'crubitRevision': 'a355b02da81bc9f350925c73ec0322ce4d5140f1',
          'bindgenRevision': '73c69d681eec90b84ffba4f993b5fb2f19580781'},
 'llvmObjdump': {'url': 'https://commondatastorage.googleapis.com/chromium-browser-clang/Mac_arm64/llvmobjdump-llvmorg-24-init-7747-g62397f8b-53.tar.xz',
                 'sha256': 'f93f89580341f51b80c713776a2f9645f090a971d82e459abbcc11fdd21b2ae4',
                 'size': 5202064,
                 'generation': 1790402697359142,
                 'outputPath': 'third_party/llvm-build/Release+Asserts'},
 'clangFormat': {'url': 'https://storage.googleapis.com/chromium-clang-format/945e45cbcb5443c3e569d5e0783fd012154fc4a7',
                 'sha256': 'a1fb17260eda2971f52ed341501b93703b0fce69ffb43a179b891b66f6f63e5a',
                 'size': 3245456,
                 'generation': 1779297393605542,
                 'outputPath': 'buildtools/mac_arm64-format/clang-format'},
 'typescript': {'format': 'cipdZip',
                'package': 'chromium/third_party/typescript/mac-arm64',
                'version': 'version:2@7.0.2',
                'instanceID': '63sEajfB6_MIU0PehstKopK1_P_yfUm21-o-zedkrz0C',
                'url': 'https://chrome-infra-packages.appspot.com/dl/chromium/third_party/typescript/mac-arm64/+/63sEajfB6_MIU0PehstKopK1_P_yfUm21-o-zedkrz0C',
                'sha256': 'eb7b046a37c1ebf3085343de86cb4aa292b5fcfff27d49b6d7ea3ecde764af3d',
                'size': 9650018,
                'generation': 1785474623781988,
                'outputPath': 'third_party/typescript/mac-arm64/src',
                'cacheName': 'typescript-7.0.2-mac-arm64-eb7b046a37c1ebf3085343de86cb4aa292b5fcfff27d49b6d7ea3ecde764af3d.zip',
                'packageVersion': '7.0.2',
                'memberCount': 118,
                'unpackedSize': 27509796,
                'sourceInputs': {'third_party/typescript/tsgo.gni': 'a62fb314e30f62e7b7ee4176a7d3eb78bbcf429f9f72ebe71f576b7bfcf7f4f6',
                                 'third_party/typescript/typescript.py': '968a454eca00fa9514d33b72959d54c609a58a202519ba003eee5d4ff861ad55',
                                 'third_party/devtools-frontend/src/scripts/build/typescript/typescript_vars.gni': '6e834d2ba894b4596fe3a425f220a8389bc0917bf73d13fb19206c4ef9c4b718',
                                 'third_party/devtools-frontend/src/third_party/typescript/typescript.py': 'ef6417d77e1251888aeb356e2afffbd395e158b6ee06a13a59ca0788bebda636',
                                 'ui/webui/webui_features.gni': 'da7bb41e65cb553d8d01d03c01f63fa172e71c430d70748e935e79c6def85e5c'}}}
_NODE = {
    "url": "https://nodejs.org/dist/v24.12.0/node-v24.12.0-darwin-arm64.tar.xz",
    "sha512": "cd6b64563c73c4b482b557ab6715f513a1edde1fd05c33718d3bc0ab2361701b932953334c7fa07246f935dc5e36e74c10cb86d98ef59a6ac745b9f889e3bdcd",
    "outputPath": "third_party/node/mac_arm64/node-darwin-arm64",
    "strip": "node-v24.12.0-darwin-arm64",
}
_RUST_VERSION = (
    "rustc 1.100.0 1edd55dcfcd573872c727fa3e086369a71661ee0 "
    "(1edd55dcfcd573872c727fa3e086369a71661ee0-2-llvmorg-24-init-7747-g62397f8b chromium)\n"
    "crubit: a355b02da81bc9f350925c73ec0322ce4d5140f1\n"
    "bindgen: 73c69d681eec90b84ffba4f993b5fb2f19580781\n\n"
)


class RecipeCompatibilityError(RuntimeError):
    pass


def _check_lock(lock):
    if (not isinstance(lock, dict) or lock.get("schema") != 1 or
            lock.get("targetCpu") != "arm64" or lock.get("chromiumVersion") != VERSION or
            lock.get("chromiumCommit") != CHROMIUM_COMMIT or
            not isinstance(lock.get("macosPackaging"), dict) or
            not isinstance(lock.get("ungoogledChromium"), dict) or
            lock["macosPackaging"].get("commit") != MACOS_COMMIT or
            lock["ungoogledChromium"].get("commit") != COMMON_COMMIT or
            lock.get("officialToolchains") != _TOOLCHAINS or
            lock.get("rustArchive") != {"url": _TOOLCHAINS["rust"]["url"],
                                        "sha256": _TOOLCHAINS["rust"]["sha256"]}):
        raise RecipeCompatibilityError("Unsupported macOS recipe or official toolchain pins")
    return _TOOLCHAINS


def _directory(path):
    """Walk real directory components using no-follow file descriptors."""
    if ".." in Path(path).parts:
        raise RecipeCompatibilityError("Directory traversal is not allowed")
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.getuid()):
        raise RecipeCompatibilityError("Expected an owned regular file with one link")


def _open(path, flags=os.O_RDONLY):
    parent = _directory(Path(path).parent)
    try:
        descriptor = os.open(Path(path).name, flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        try:
            _regular(os.fstat(descriptor))
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parent)


def _read(path, limit=1024 * 1024):
    descriptor = _open(path)
    with os.fdopen(descriptor, "rb") as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            raise RecipeCompatibilityError("Unexpected file size: " + str(path))
        return handle.read(limit + 1)


def _hash(path, algorithm="sha256"):
    descriptor = _open(path)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        result = hashlib.file_digest(handle, algorithm).hexdigest()
        after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                        after.st_mtime_ns, after.st_ctime_ns):
            raise RecipeCompatibilityError("File changed during verification")
        return result


def _replace_owned(path, original, replacement):
    """Write only the verified open inode, never a substituted path target."""
    descriptor = _open(path, os.O_RDWR)
    with os.fdopen(descriptor, "r+b") as handle:
        before = os.fstat(handle.fileno())
        if handle.read() != original:
            raise RecipeCompatibilityError("Recipe file changed before adaptation")
        current = Path(path).lstat()
        _regular(current)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise RecipeCompatibilityError("Recipe path changed before adaptation")
        handle.seek(0)
        handle.write(replacement)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
        current = Path(path).lstat()
        _regular(current)
        _regular(os.fstat(handle.fileno()))
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise RecipeCompatibilityError("Recipe path changed during adaptation")
    if _read(path) != replacement:
        raise RecipeCompatibilityError("Recipe bytes changed during adaptation")


def _manifest(tools):
    def section(name, item):
        filename = urlsplit(item["url"]).path.rsplit("/", 1)[-1]
        return (f"[{name}]\nurl = {item['url']}\ndownload_filename = {filename}\n"
                f"sha256 = {item['sha256']}\noutput_path = {item['outputPath']}\n\n")
    node = ("[nodejs]\nversion = 24.12.0\n"
            "url = https://nodejs.org/dist/v%(version)s/node-v%(version)s-darwin-arm64.tar.xz\n"
            "download_filename = node-v%(version)s-darwin-arm64.tar.xz\n"
            "strip_leading_dirs = node-v%(version)s-darwin-arm64\n"
            f"sha512 = {_NODE['sha512']}\noutput_path = {_NODE['outputPath']}\n\n")
    return ("# Exact official Chromium 156 tools; Node retains the pinned macOS recipe resource.\n\n" +
            section("llvm", tools["clang"]) + node + section("rust", tools["rust"]) +
            section("llvmobjdump", tools["llvmObjdump"])).encode()


def _series():
    return "".join("ungoogled-chromium/macos/" + name + "\n" for name in _RETAINED).encode()


def _adapted_hashes(tools):
    return {"patches/series": hashlib.sha256(_series()).hexdigest(),
            "downloads-arm64.ini": hashlib.sha256(_manifest(tools)).hexdigest(),
            "retrieve_and_unpack_resource.py": _ADAPTED_RETRIEVER_SHA256}


def adapt_recipe(recipe, lock):
    """Select eight unchanged patches and exact matching official tool resources."""
    tools = _check_lock(lock)
    recipe = Path(recipe)
    try:
        descriptor = _directory(recipe)
        os.close(descriptor)
        if os.path.lexists(recipe / ".git") or os.path.lexists(recipe / "build/src"):
            raise RecipeCompatibilityError("Only a fresh isolated recipe copy may be adapted")
        originals = {name: _read(recipe / name) for name in _ORIGINAL}
        if any(hashlib.sha256(data).hexdigest() != _ORIGINAL[name]
               for name, data in originals.items()):
            raise RecipeCompatibilityError("Original recipe preimage changed or was already adapted")
        original_series = originals["patches/series"].decode().splitlines()
        if any(original_series.count("ungoogled-chromium/macos/" + name) != 1 for name in _RETAINED):
            raise RecipeCompatibilityError("Unexpected original macOS patch selection")
        retriever = originals["retrieve_and_unpack_resource.py"].decode()
        if retriever.count(_RUST_REWIRING) != 1 or retriever.count(_OLD_INSTALL_NAME) != 1:
            raise RecipeCompatibilityError("Original generic-Rust layout changed")
        retriever = retriever.replace(_RUST_REWIRING, "", 1).replace(
            _OLD_INSTALL_NAME, _NEW_INSTALL_NAME, 1).encode()
        replacements = {"patches/series": _series(), "downloads-arm64.ini": _manifest(tools),
                        "retrieve_and_unpack_resource.py": retriever}
        expected = _adapted_hashes(tools)
        if any(hashlib.sha256(data).hexdigest() != expected[name]
               for name, data in replacements.items()):
            raise RecipeCompatibilityError("Internal adapted recipe checksum differs")
        # Verify all three preimages before the first write. A partial failure
        # cannot be replayed: source preparation must use a new workspace.
        for name in originals:
            if _read(recipe / name) != originals[name]:
                raise RecipeCompatibilityError("Recipe changed before adaptation")
        for name, data in replacements.items():
            _replace_owned(recipe / name, originals[name], data)
        return {"chromiumVersion": VERSION, "macosCommit": MACOS_COMMIT,
                "commonCommit": COMMON_COMMIT, "retainedPatches": list(_RETAINED),
                "omittedPatches": [line.rsplit("/", 1)[-1] for line in original_series
                                   if line and line.rsplit("/", 1)[-1] not in _RETAINED],
                "originalSHA256": dict(_ORIGINAL), "adaptedSHA256": expected,
                "policy": "matching official Chromium tools; preserve upstream Rust and security checks"}
    except OSError as error:
        raise RecipeCompatibilityError("Cannot safely adapt copied macOS recipe") from error


def _verify_recipe(recipe, tools):
    for name, expected in _adapted_hashes(tools).items():
        if _hash(Path(recipe) / name) != expected:
            raise RecipeCompatibilityError("Adapted recipe drift: " + name)


def _cache_name(key, item):
    return (item["cacheName"] if key == "typescript" else
            "clang-format-945e45cbcb5443c3e569d5e0783fd012154fc4a7" if key == "clangFormat"
            else urlsplit(item["url"]).path.rsplit("/", 1)[-1])


def _ensure_cache(key, item):
    cache = ROOT / ".cache/source-downloads"
    cache.mkdir(parents=True, exist_ok=True)
    descriptor = _directory(cache)
    os.close(descriptor)
    destination = cache / _cache_name(key, item)
    if not os.path.lexists(destination):
        descriptor, temporary = tempfile.mkstemp(prefix=destination.name + ".download-", dir=cache)
        try:
            total = 0
            checksum = hashlib.sha256()
            with os.fdopen(descriptor, "wb") as handle, urlopen(
                    (item["url"] if item.get("format") == "cipdZip" else
                     item["url"] + "?generation=" + str(item["generation"])), timeout=60) as response:
                if (response.status != 200 or
                        int(response.headers.get("x-goog-generation", "0")) != item["generation"]):
                    raise RecipeCompatibilityError("Official resource generation differs")
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > item["size"]:
                        raise RecipeCompatibilityError("Official resource exceeds pinned size")
                    checksum.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if total != item["size"] or checksum.hexdigest() != item["sha256"]:
                raise RecipeCompatibilityError("Official resource checksum or size differs")
            os.chmod(temporary, 0o644)
            os.link(temporary, destination)  # Exclusive publication; preserve any competing entry.
        finally:
            os.unlink(temporary)
    descriptor = _open(destination)
    with os.fdopen(descriptor, "rb") as handle:
        if os.fstat(handle.fileno()).st_size != item["size"]:
            raise RecipeCompatibilityError("Cached official resource size differs")
    if _hash(destination) != item["sha256"]:
        raise RecipeCompatibilityError("Cached official resource checksum differs")
    return destination


def _safe_path(root, relative, *, directory=False):
    parts = PurePosixPath(relative).parts
    if PurePosixPath(relative).is_absolute() or ".." in parts:
        raise RecipeCompatibilityError("Archive member escapes toolchain output")
    result = Path(root).joinpath(*parts)
    descriptor = _directory(result if directory else result.parent)
    os.close(descriptor)
    return result


def _verify_archive(archive, root, *, strip=None):
    """Compare every installed archive member to publisher-pinned payload bytes."""
    expected = set()
    seen = set()
    manifest = hashlib.sha256()
    descriptor = _open(archive)
    with os.fdopen(descriptor, "rb") as source, tarfile.open(fileobj=source, mode="r|xz") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.islnk():
                raise RecipeCompatibilityError("Unsafe official archive member")
            if strip:
                try:
                    path = path.relative_to(strip)
                except ValueError as error:
                    raise RecipeCompatibilityError("Unexpected Node archive prefix") from error
            name = str(path)
            if name == ".":
                continue
            if name in seen:
                raise RecipeCompatibilityError("Duplicate official archive member")
            seen.add(name)
            expected.add(name)
            expected.update(str(parent) for parent in path.parents if str(parent) != ".")
            destination = _safe_path(root, name, directory=member.isdir())
            if member.isdir():
                continue
            info = destination.lstat()
            manifest.update(name.encode() + b"\0")
            if member.issym():
                resolved = posixpath.normpath(posixpath.join(str(path.parent), member.linkname))
                if (PurePosixPath(member.linkname).is_absolute() or resolved == ".." or
                        resolved.startswith("../") or not stat.S_ISLNK(info.st_mode) or
                        os.readlink(destination) != member.linkname):
                    raise RecipeCompatibilityError("Official toolchain symlink differs")
                manifest.update(b"link\0" + member.linkname.encode())
            elif member.isfile():
                _regular(info)
                if info.st_size != member.size or stat.S_IMODE(info.st_mode) != member.mode:
                    raise RecipeCompatibilityError("Installed toolchain file size or mode differs: " + name)
                payload = tar.extractfile(member)
                checksum = hashlib.file_digest(payload, "sha256").hexdigest()
                if _hash(destination) != checksum:
                    raise RecipeCompatibilityError("Installed toolchain file checksum differs: " + name)
                manifest.update(checksum.encode())
            else:
                raise RecipeCompatibilityError("Unsupported official archive member")
    return expected, manifest.hexdigest()


def _verify_tree(root, expected):
    actual = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            actual.add(str((Path(directory) / name).relative_to(root)))
    if actual != expected:
        raise RecipeCompatibilityError("Unexpected or missing installed toolchain entries")


def verify_platform(recipe, lock):
    """Recheck exact recipe, archives, installed payloads and prebuilt tools."""
    tools = _check_lock(lock)
    recipe = Path(recipe)
    try:
        _verify_recipe(recipe, tools)
        src = recipe / "build/src"
        descriptor = _directory(src)
        os.close(descriptor)
        if _hash(src / "DEPS") != tools["source"]["sha256"]:
            raise RecipeCompatibilityError("Official Chromium DEPS preimage differs")
        records = {}
        entries = {}
        for key in ("clang", "rust", "llvmObjdump"):
            item = tools[key]
            archive = ROOT / ".cache/source-downloads" / _cache_name(key, item)
            if archive.stat().st_size != item["size"] or _hash(archive) != item["sha256"]:
                raise RecipeCompatibilityError("Official cached archive differs")
            output = _safe_path(src, item["outputPath"], directory=True)
            names, tree_sha = _verify_archive(archive, output)
            entries.setdefault(item["outputPath"], set()).update(names)
            records[key] = {"archiveSHA256": item["sha256"], "installedManifestSHA256": tree_sha,
                            "memberCount": len(names)}
        llvm = src / tools["clang"]["outputPath"]
        alias = llvm / "bin/install_name_tool"
        if not alias.is_symlink() or os.readlink(alias) != "llvm-install-name-tool":
            raise RecipeCompatibilityError("Unexpected install_name_tool alias")
        entries[tools["clang"]["outputPath"]].add("bin/install_name_tool")
        for relative, expected in entries.items():
            _verify_tree(src / relative, expected)
        node_archive = ROOT / ".cache/source-downloads" / "node-v24.12.0-darwin-arm64.tar.xz"
        if _hash(node_archive, "sha512") != _NODE["sha512"]:
            raise RecipeCompatibilityError("Pinned Node archive differs")
        node_output = _safe_path(src, _NODE["outputPath"], directory=True)
        node_names, node_tree_sha = _verify_archive(node_archive, node_output, strip=_NODE["strip"])
        _verify_tree(node_output, node_names)
        records["node"] = {"archiveSHA512": _NODE["sha512"], "installedManifestSHA256": node_tree_sha}
        formatter = _safe_path(src, tools["clangFormat"]["outputPath"])
        if formatter.stat().st_size != tools["clangFormat"]["size"] or _hash(formatter) != tools["clangFormat"]["sha256"]:
            raise RecipeCompatibilityError("Installed official formatter differs")
        if _read(llvm / "cr_build_revision") != (tools["clang"]["revision"] + "\n").encode():
            raise RecipeCompatibilityError("Official Clang revision stamp differs")
        rust = src / tools["rust"]["outputPath"]
        if _read(rust / "VERSION") != _RUST_VERSION.encode():
            raise RecipeCompatibilityError("Official Rust/Crubit/bindgen version stamp differs")
        required = [llvm / "bin/clang", llvm / "bin/llvm-objdump", rust / "bin/rustc",
                    rust / "bin/bindgen", rust / "bin/cc_bindings_from_rs", formatter,
                    node_output / "bin/node"]
        for binary in required:
            descriptor = _open(binary)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not info.st_mode & 0o111 or handle.read(8) != bytes.fromhex("cffaedfe0c000001"):
                    raise RecipeCompatibilityError("Required native arm64 tool is missing or invalid: " + str(binary))
        for relative in ("lib/third_party/crubit/BUILD.gn", "lib/libclang.dylib"):
            descriptor = _open(rust / relative)
            os.close(descriptor)
        records["typescript"] = _verify_typescript(src, ROOT / ".cache/source-downloads" /
                                                   _cache_name("typescript", tools["typescript"]),
                                                   tools["typescript"])
        required.append(src / tools["typescript"]["outputPath"] / "lib/tsc")
        return {"chromiumVersion": VERSION, "officialToolchainSource": tools["source"],
                "resources": records, "requiredTools": [str(p.relative_to(src)) for p in required],
                "clangRevision": tools["clang"]["revision"], "rustVersion": _RUST_VERSION,
                "prebuiltBindgen": True, "prebuiltCrubit": True}
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise RecipeCompatibilityError("Cannot verify installed official platform resources") from error


def prepare_platform(recipe, lock):
    """Run only the guarded copied retriever, install raw formatter and verify."""
    tools = _check_lock(lock)
    recipe = Path(recipe)
    try:
        _verify_recipe(recipe, tools)
        src = recipe / "build/src"
        descriptor = _directory(src)
        os.close(descriptor)
        for relative in ("third_party", "third_party/llvm-build", "third_party/node",
                         "third_party/rust-toolchain", "third_party/dawn", "buildtools"):
            candidate = src / relative
            if os.path.lexists(candidate):
                descriptor = _directory(candidate)
                os.close(descriptor)
        cache = recipe / "build/download_cache"
        if not cache.is_symlink() or cache.resolve(strict=True) != (ROOT / ".cache/source-downloads").resolve(strict=True):
            raise RecipeCompatibilityError("Recipe download cache points elsewhere")
        for key in ("clang", "rust", "llvmObjdump", "clangFormat", "typescript"):
            _ensure_cache(key, tools[key])
        node_archive = ROOT / ".cache/source-downloads" / "node-v24.12.0-darwin-arm64.tar.xz"
        if os.path.lexists(node_archive) and _hash(node_archive, "sha512") != _NODE["sha512"]:
            raise RecipeCompatibilityError("Existing Node archive differs")
        subprocess.run([sys.executable, str(recipe / "retrieve_and_unpack_resource.py"),
                        "-p", "arm64"], check=True)
        _verify_recipe(recipe, tools)
        formatter = src / tools["clangFormat"]["outputPath"]
        if not formatter.parent.exists():
            parent = formatter.parent.parent
            descriptor = _directory(parent)
            os.close(descriptor)
            formatter.parent.mkdir(mode=0o755)
        descriptor = _directory(formatter.parent)
        os.close(descriptor)
        data = _read(ROOT / ".cache/source-downloads" / _cache_name("clangFormat", tools["clangFormat"]),
                     limit=tools["clangFormat"]["size"])
        if os.path.lexists(formatter):
            if _read(formatter, limit=len(data)) != data:
                raise RecipeCompatibilityError("Existing formatter differs; it will not be replaced")
        else:
            descriptor, temporary = tempfile.mkstemp(prefix=".clang-format-", dir=formatter.parent)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o755)
                os.link(temporary, formatter)
            finally:
                os.unlink(temporary)
        _install_typescript(src, ROOT / ".cache/source-downloads" /
                            _cache_name("typescript", tools["typescript"]), tools["typescript"])
        return verify_platform(recipe, lock)
    except (OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise RecipeCompatibilityError("Official platform preparation failed closed") from error


def _typescript_sources(src, item):
    for relative, expected in item["sourceInputs"].items():
        if _hash(Path(src) / relative) != expected:
            raise RecipeCompatibilityError("Original TypeScript source policy differs: " + relative)
    deps = _read(Path(src) / "DEPS").decode()
    declaration = ("'package': '" + item["package"] + "',\n"
                   "              'version': '" + item["version"] + "'")
    if deps.count(declaration) != 1:
        raise RecipeCompatibilityError("Official DEPS TypeScript version differs")
    text = _read(Path(src) / "third_party/typescript/tsgo.gni").decode()
    libraries = re.findall(r'"(lib[^"/]*\.d\.ts)"', text)
    if len(libraries) != 108 or len(set(libraries)) != 108:
        raise RecipeCompatibilityError("Original TypeScript GN library inputs differ")
    return {"lib/" + name for name in libraries} | {"lib/tsc"}


def _zip_shape(contents, item):
    infos = contents.infolist()
    if len(infos) != item["memberCount"] or sum(i.file_size for i in infos) != item["unpackedSize"]:
        raise RecipeCompatibilityError("Official TypeScript ZIP shape differs")
    seen = set()
    for info in infos:
        parts = info.filename.split("/")
        mode = info.external_attr >> 16
        if (not info.filename or "\\" in info.filename or
                any(p in ("", ".", "..") for p in parts) or
                any(ord(c) < 32 or ord(c) > 126 for c in info.filename) or
                info.orig_filename != info.filename or
                PurePosixPath(info.filename).is_absolute() or info.filename in seen or
                info.is_dir() or stat.S_IFMT(mode) != stat.S_IFREG or
                stat.S_IMODE(mode) not in (0o400, 0o500) or info.flag_bits & 1 or
                info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            raise RecipeCompatibilityError("Unsafe or duplicate TypeScript ZIP member")
        seen.add(info.filename)
    if any(str(parent) in seen for name in seen for parent in PurePosixPath(name).parents
           if str(parent) != "."):
        raise RecipeCompatibilityError("TypeScript ZIP file/directory collision")
    for name in ("package.json", ".cipdpkg/manifest.json"):
        if name not in seen or contents.getinfo(name).file_size > 16384:
            raise RecipeCompatibilityError("Missing or oversized TypeScript metadata")
    try:
        package = json.loads(contents.read("package.json"))
        manifest = json.loads(contents.read(".cipdpkg/manifest.json"))
    except (ValueError, UnicodeError) as error:
        raise RecipeCompatibilityError("Malformed TypeScript package metadata") from error
    if (not isinstance(package, dict) or package.get("version") != item["packageVersion"] or
            package.get("name") != "@typescript/typescript-darwin-arm64" or
            package.get("os") != ["darwin"] or package.get("cpu") != ["arm64"] or
            manifest != {"format_version": "1.1", "package_name": item["package"], "install_mode": "copy"}):
        raise RecipeCompatibilityError("TypeScript package identity or version differs")
    return infos, seen


def _check_zip_archive(archive, item):
    descriptor = _open(archive)
    with os.fdopen(descriptor, "rb") as handle:
        if os.fstat(handle.fileno()).st_size != item["size"]:
            raise RecipeCompatibilityError("TypeScript ZIP size differs")
    if _hash(archive) != item["sha256"]:
        raise RecipeCompatibilityError("TypeScript ZIP checksum differs")


def _verify_typescript(src, archive, item, output=None):
    required = _typescript_sources(src, item)
    _check_zip_archive(archive, item)
    output = Path(output) if output is not None else Path(src) / item["outputPath"]
    descriptor = _directory(output)
    os.close(descriptor)
    expected = set()
    checksum = hashlib.sha256()
    descriptor = _open(archive)
    with os.fdopen(descriptor, "rb") as handle, zipfile.ZipFile(handle) as contents:
        infos, names = _zip_shape(contents, item)
        if not required.issubset(names):
            raise RecipeCompatibilityError("TypeScript ZIP misses declared GN compiler/library inputs")
        for info in infos:
            path = PurePosixPath(info.filename)
            expected.add(info.filename)
            expected.update(str(parent) for parent in path.parents if str(parent) != ".")
            target = _safe_path(output, info.filename)
            descriptor = _open(target)
            with os.fdopen(descriptor, "rb") as installed:
                native_info = os.fstat(installed.fileno())
                if (native_info.st_size != info.file_size or
                        stat.S_IMODE(native_info.st_mode) != stat.S_IMODE(info.external_attr >> 16)):
                    raise RecipeCompatibilityError("Installed TypeScript file size or mode differs")
            with contents.open(info) as payload:
                payload_sha = hashlib.file_digest(payload, "sha256").hexdigest()
            if _hash(target) != payload_sha:
                raise RecipeCompatibilityError("Installed TypeScript file checksum differs")
            checksum.update(info.filename.encode() + b"\0" + payload_sha.encode())
    _verify_tree(output, expected)
    descriptor = _open(output / "lib/tsc")
    with os.fdopen(descriptor, "rb") as handle:
        if not os.fstat(handle.fileno()).st_mode & 0o111 or handle.read(8) != bytes.fromhex("cffaedfe0c000001"):
            raise RecipeCompatibilityError("Official TypeScript compiler is not native arm64")
    return {"archiveSHA256": item["sha256"], "instanceID": item["instanceID"],
            "packageVersion": item["packageVersion"], "memberCount": len(infos),
            "verifiedGNInputs": len(required), "installedManifestSHA256": checksum.hexdigest()}


def _mkdirs(root, relative):
    if PurePosixPath(relative).is_absolute() or "\\" in relative:
        raise RecipeCompatibilityError("Toolchain directory must be relative")
    descriptor = _directory(root)
    try:
        for name in PurePosixPath(relative).parts:
            if name in ("", ".", ".."):
                raise RecipeCompatibilityError("Invalid toolchain directory component")
            try:
                os.mkdir(name, mode=0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)
    return Path(root) / relative


def _rename_exclusive(source, destination):
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = library.renamex_np
        function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        arguments = (os.fsencode(source), os.fsencode(destination), 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        function = library.renameat2
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        arguments = (-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    else:
        raise RecipeCompatibilityError("Atomic no-replace publication is unavailable")
    function.restype = ctypes.c_int
    if function(*arguments) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def _install_typescript(src, archive, item):
    _typescript_sources(src, item)
    _check_zip_archive(archive, item)
    output = Path(src) / item["outputPath"]
    parent = _mkdirs(src, str(PurePosixPath(item["outputPath"]).parent))
    if os.path.lexists(output):
        return _verify_typescript(src, archive, item)
    staging = Path(tempfile.mkdtemp(prefix=".typescript-", dir=parent))
    try:
        descriptor = _open(archive)
        with os.fdopen(descriptor, "rb") as handle, zipfile.ZipFile(handle) as contents:
            infos, _ = _zip_shape(contents, item)
            for info in infos:
                relative = PurePosixPath(info.filename)
                if str(relative.parent) != ".":
                    _mkdirs(staging, str(relative.parent))
                target = _safe_path(staging, info.filename)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as destination, contents.open(info) as payload:
                    copied = 0
                    while chunk := payload.read(1024 * 1024):
                        copied += len(chunk)
                        if copied > info.file_size:
                            raise RecipeCompatibilityError("TypeScript ZIP exceeds declared file size")
                        destination.write(chunk)
                    if copied != info.file_size:
                        raise RecipeCompatibilityError("Truncated TypeScript ZIP file")
                    destination.flush()
                    os.fsync(destination.fileno())
                    os.fchmod(destination.fileno(), stat.S_IMODE(info.external_attr >> 16))
        _verify_typescript(src, archive, item, output=staging)
        staging.chmod(0o755)
        _rename_exclusive(staging, output)
        return _verify_typescript(src, archive, item)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
