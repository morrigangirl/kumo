#!/usr/bin/env python3
"""Audit and promote a separately prepared Chromium tree without losing Ninja outputs.

This preserves preparation caches, not a claim that retained objects validate the
new version. The normal source build must regenerate GN before running Ninja.
Only the audit directory is written by plan. Apply is intentionally fail closed;
an interrupted apply leaves state.inProgress=promotion and backed-up preimages.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = (
    "third_party/llvm-build/Release+Asserts",
    "third_party/rust-toolchain",
    "third_party/node/mac",
    "third_party/node/mac_arm64",
)
ESBUILD = "third_party/devtools-frontend/src/node_modules/esbuild"
INTERMEDIATE = "third_party/rust-toolchain-intermediate"
NINJA = "third_party/llvm-build/Release+Asserts/bin/ninja"
ARGS = "out/Default/args.gn"
BINDGEN_COMMIT = "73c69d681eec90b84ffba4f993b5fb2f19580781"
PLATFORM_INPUTS = (
    "downloads-arm64.ini", "downloads-arm64-rustlib.ini",
    "downloads-x86-64.ini", "downloads-x86-64-rustlib.ini",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".promotion-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def under(path, root):
    return path == root or root in path.parents


def validate_relative(relative):
    p = PurePosixPath(relative)
    require(relative and not p.is_absolute() and ".." not in p.parts and "." not in p.parts,
            f"Unsafe manifest path: {relative!r}")


def normalize_link(target, candidate, retained):
    prefix = str(candidate)
    if target == prefix or target.startswith(prefix + os.sep):
        return str(retained) + target[len(prefix):]
    return target


def cache_path(relative):
    parts = PurePosixPath(relative).parts
    return "__pycache__" in parts or parts[-1].endswith(".pyc")


def source_excluded(relative):
    return cache_path(relative) or any(relative == p or relative.startswith(p + "/")
        for p in ("out", INTERMEDIATE, ESBUILD, *PLATFORM))


def node(path, candidate, retained):
    info = path.lstat()
    result = {"mode": stat.S_IMODE(info.st_mode)}
    if stat.S_ISREG(info.st_mode):
        result.update(type="file", sha256=sha(path), size=info.st_size)
    elif stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        result.update(type="link", target=normalize_link(target, candidate, retained)
                      if under(path.absolute(), candidate) else target)
    elif stat.S_ISDIR(info.st_mode):
        result.update(type="dir")
    else:
        raise RuntimeError(f"Unsupported filesystem node: {path}")
    return result


def manifest(root, candidate, retained, exclude=lambda relative: False):
    """Never follow links; omit empty directory containers (including cache-only ones)."""
    root = Path(root)
    require(not root.is_symlink(), f"Manifest root is a symlink: {root}")
    if not root.exists():
        return {}
    require(root.is_dir() and not root.is_symlink(), f"Expected real directory: {root}")
    result = {}

    def visit(folder, prefix=""):
        managed = False
        with os.scandir(folder) as entries:
            children = sorted(entries, key=lambda e: e.name)
        for entry in children:
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            validate_relative(rel)
            if exclude(rel):
                continue
            path = root / rel
            value = node(path, candidate, retained)
            if value["type"] == "dir":
                if visit(path, rel):
                    result[rel] = value
                    managed = True
            else:
                result[rel] = value
                managed = True
        return managed

    visit(root)
    return dict(sorted(result.items()))


def changed(before, after):
    return [p for p in sorted(set(before) | set(after)) if before.get(p) != after.get(p)]


def group_alive(pgid):
    require(pgid > 1, "--old-pgid must identify the old build process group")
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Promotion:
    def __init__(self, candidate, retained, audit, pgid, project=ROOT,
                 expected_retained_version="155.0.8059.39"):
        self.candidate = Path(candidate).absolute()
        self.retained = Path(retained).absolute()
        self.audit = Path(audit).absolute()
        self.project = Path(project).resolve()
        self.pgid = pgid
        self.expected_retained_version = expected_retained_version
        for path in (self.candidate, self.retained):
            require(path == path.resolve(), f"Work root must have no symlink aliases: {path}")
            require(path.is_dir(), f"Missing work root: {path}")
        require(not under(self.candidate, self.retained) and not under(self.retained, self.candidate),
                "Candidate and retained work roots must be disjoint")
        require(not under(self.audit.resolve(), self.candidate), "Audit must be outside candidate work")
        require(self.audit == self.audit.resolve(), "Audit path must have no symlink aliases")
        for path in (self.csrc, self.rsrc, self.candidate / "recipe", self.retained / "recipe"):
            require(path.is_dir() and not path.is_symlink() and path == path.resolve(),
                    f"Source/recipe path has missing or symlink ancestors: {path}")
        require(not under(self.audit.resolve(), self.retained / "recipe"),
                "Audit must be outside the retained recipe")

    @property
    def csrc(self):
        return self.candidate / "recipe/build/src"

    @property
    def rsrc(self):
        return self.retained / "recipe/build/src"

    def entry(self, path):
        require(path.is_file() and not path.is_symlink(), f"Expected regular file: {path}")
        return node(path, self.candidate, self.retained)

    def validate_identity(self):
        lock_path = self.project / "config/source-lock.json"
        lock = json.loads(lock_path.read_text())
        state = json.loads((self.candidate / "state.json").read_text())
        require("ready" in state.get("done", []) and not state.get("inProgress"),
                "Candidate preparation is not ready")
        digest = runpy.run_path(str(self.project / "scripts/source.py"))["input_digest"]()
        require(state.get("inputDigest") == digest, "Candidate inputDigest differs from current source recipe")
        def chromium_version(src):
            version = dict(line.split("=", 1) for line in (src / "chrome/VERSION").read_text().splitlines() if "=" in line)
            return ".".join(version.get(k, "") for k in ("MAJOR", "MINOR", "BUILD", "PATCH"))
        actual = chromium_version(self.csrc)
        require(actual == lock["chromiumVersion"], "Candidate chrome/VERSION differs from source lock")
        common = "recipe/ungoogled-chromium/chromium_version.txt"
        require((self.candidate / common).read_text().strip() == actual,
                "Candidate common chromium_version.txt differs from source version")
        old_version = chromium_version(self.rsrc)
        require(old_version == self.expected_retained_version and
                (self.retained / common).read_text().strip() == old_version,
                "Retained chrome/VERSION/common version differs from expected old provenance")
        old = json.loads((self.retained / "state.json").read_text())
        require("ready" in old.get("done", []) and not old.get("inProgress"), "Retained preparation is not ready")
        return {"lock": lock, "lockSha256": sha(lock_path), "candidateState": state,
                "retainedState": old, "retainedVersion": old_version, "candidateVersion": actual,
                "inputDigest": digest}

    def resource_audit(self, lock):
        records = {}
        for rel in PLATFORM_INPUTS:
            a, b = self.candidate / "recipe" / rel, self.retained / "recipe" / rel
            require(a.is_file() and b.is_file(), f"Missing platform resource inputs: {rel}")
            candidate_sha, retained_sha = sha(a), sha(b)
            version_metadata_only = False
            if candidate_sha != retained_sha:
                # source.py's ConfigParser writes this unused DEFAULT into the
                # platform manifest while inserting the pinned Rust checksum.
                # Admit exactly this reviewed version-line change, no tool URL,
                # hash, extraction setting or other byte change.
                old = f"_chromium_version = {self.expected_retained_version}\n"
                new = f"_chromium_version = {lock['chromiumVersion']}\n"
                before, after = b.read_text(), a.read_text()
                version_metadata_only = (rel == "downloads-arm64.ini" and
                    before.count(old) == 1 and before.replace(old, new, 1) == after)
                require(version_metadata_only, f"Platform resource inputs changed: {rel}")
            records[rel] = {"candidateSha256": candidate_sha,
                            "retainedSha256": retained_sha,
                            "expectedVersionMetadataOnly": version_metadata_only}
        config = configparser.ConfigParser()
        config.read(self.candidate / "recipe/downloads-arm64.ini")
        cache = self.candidate / "recipe/build/download_cache"
        for section in config.sections():
            filename = config.get(section, "download_filename")
            require(Path(filename).name == filename, f"Unsafe resource filename: {filename}")
            path = cache / filename
            algorithm = "sha512" if config.has_option(section, "sha512") else "sha256"
            expected = config.get(section, algorithm, fallback=None)
            if section == "rust":
                require(config.get(section, "url") == lock["rustArchive"]["url"], "Rust archive URL differs from lock")
                require(expected == lock["rustArchive"][algorithm], "Rust archive checksum differs from lock")
            require(expected and path.is_file() and sha(path, algorithm) == expected,
                    f"Platform archive checksum failed: {filename}")
            old_path = self.retained / "recipe/build/download_cache" / filename
            require(old_path.is_file() and (path.resolve() == old_path.resolve() or sha(old_path, algorithm) == expected),
                    f"Old platform archive differs: {filename}")
            records[filename] = {algorithm: expected, "size": path.stat().st_size}
        source = lock["sourceArchive"]
        filename = source["url"].rsplit("/", 1)[-1]
        path = cache / filename
        require(path.is_file() and sha(path) == source["sha256"], "Candidate source archive checksum failed")
        records[filename] = {"sha256": source["sha256"], "size": path.stat().st_size}
        return records

    def checkpoint(self, name, value):
        """Persist successful read-only proof; apply never substitutes it for rehashing."""
        write_json(self.audit / "checkpoints" / (name + ".json"), {
            "schema": 1, "stage": name, "completedAtUnixNs": time.time_ns(),
            "valueSha256": json_hash(value), "value": value,
            "note": "Planning evidence only. Apply independently rehashes actual inputs before mutation.",
        })

    def platform_audit(self, checkpoint=False):
        records = {}
        # Fail on helper/runtime prerequisites before the expensive whole-tree
        # comparisons. Chromium's run_bindgen.py supplies this same explicit
        # library search path for the pinned libclang dependency on macOS.
        bindgen = self.rsrc / "third_party/rust-toolchain/bin/bindgen"
        require(bindgen.is_file() and not bindgen.is_symlink(), "Missing built bindgen helper")
        clang_lib = self.rsrc / "third_party/rust-toolchain/lib/libclang.dylib"
        require(clang_lib.is_file() and not clang_lib.is_symlink() and sha(clang_lib) ==
                sha(self.rsrc / "third_party/llvm-build/Release+Asserts/lib/libclang.dylib"),
                "Installed bindgen libclang differs from LLVM toolchain")
        bindgen_env = os.environ.copy()
        bindgen_env["DYLD_LIBRARY_PATH"] = str(clang_lib.parent)
        version = subprocess.check_output([str(bindgen), "--version"], text=True, env=bindgen_env).strip()
        require(version == "bindgen 0.73.2", f"Unexpected bindgen version: {version}")
        gn = self.rsrc / "out/Default/gn"
        require(gn.is_file() and not gn.is_symlink(), "Missing retained GN helper")
        gn_version = subprocess.check_output([str(gn), "--version"], text=True).strip()
        require(gn_version, "Retained GN helper did not report a version")
        allowed = {"third_party/rust-toolchain": {"bin/bindgen", "lib/libclang.dylib"},
                   "third_party/llvm-build/Release+Asserts": {"bin/ninja"}}
        for rel in PLATFORM:
            a = manifest(self.csrc / rel, self.candidate, self.retained, cache_path)
            b = manifest(self.rsrc / rel, self.candidate, self.retained, cache_path)
            extras = {p for p in b if p not in a and b[p]["type"] != "dir"}
            require(extras <= allowed.get(rel, set()), f"Unexpected old platform additions in {rel}: {sorted(extras)}")
            for p in a:
                require(a[p] == b.get(p), f"Pristine platform content differs: {rel}/{p}")
            # No unknown directory mode differences escape the file checks above.
            for p in set(b) - set(a):
                require(b[p]["type"] != "dir" or any(q.startswith(p + "/") for q in extras),
                        f"Unexpected old platform directory: {rel}/{p}")
            records[rel] = {"candidate": a, "retained": b}
            if checkpoint:
                self.checkpoint("platform-" + rel.replace("/", "__"), records[rel])
        ninja = self.rsrc / NINJA
        if ninja.is_symlink() or ninja.exists():
            require(ninja.is_symlink() and os.readlink(ninja) == str(self.retained / "ninja-native-first.py"),
                    "Old LLVM Ninja addition is not the known ordering shim")
        for rel in ("tools/rust", "tools/clang/scripts", "tools/gn"):
            require(manifest(self.csrc / rel, self.candidate, self.retained, cache_path) ==
                    manifest(self.rsrc / rel, self.candidate, self.retained, cache_path),
                    f"Helper source inputs changed; rebuild helpers before promotion: {rel}")
        checkout = self.rsrc / INTERMEDIATE / "bindgen-src"
        commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        require(commit == BINDGEN_COMMIT, "Bindgen checkout revision differs from expected source input")
        require(not subprocess.check_output(["git", "--no-optional-locks", "-C", str(checkout), "status", "--porcelain", "--untracked-files=normal"], text=True).strip(),
                "Bindgen checkout has local changes")
        records["helpers"] = {"bindgenCommit": commit, "bindgenVersion": version,
            "bindgenSha256": sha(bindgen), "libclangSha256": sha(clang_lib),
            "gnSha256": sha(gn), "gnVersion": gn_version,
            "bindgenLibrarySearchPath": str(clang_lib.parent),
            "removeNinjaShim": ninja.is_symlink()}
        link = self.rsrc / ESBUILD
        require(link.is_symlink() and os.readlink(link) == str(self.retained / "recipe/build/esbuild-node/node_modules/esbuild")
                and link.is_dir(), "Established esbuild link is missing or points elsewhere")
        return records

    def snapshots(self, checkpoint=False):
        controls = lambda relative: relative == "build" or relative.startswith("build/") or cache_path(relative)
        result = {}
        for name, root, exclude in (("candidateSource", self.csrc, source_excluded),
                ("retainedSource", self.rsrc, source_excluded),
                ("candidateRecipe", self.candidate / "recipe", controls),
                ("retainedRecipe", self.retained / "recipe", controls)):
            result[name] = manifest(root, self.candidate, self.retained, exclude)
            if checkpoint:
                self.checkpoint("snapshot-" + name, result[name])
        result["candidateArgs"] = self.entry(self.csrc / ARGS)
        result["retainedArgs"] = self.entry(self.rsrc / ARGS)
        return result

    def symlink_audit(self, snapshots):
        """Reject known broken new links before mutation; retain upstream history."""
        unchanged = {"source": {}, "recipe": {}}
        for label, candidate_key, retained_key, candidate_root, retained_root in (
                ("source", "candidateSource", "retainedSource", self.csrc, self.rsrc),
                ("recipe", "candidateRecipe", "retainedRecipe",
                 self.candidate / "recipe", self.retained / "recipe")):
            for relative, value in snapshots[candidate_key].items():
                if value["type"] != "link" or (candidate_root / relative).exists():
                    continue
                require(snapshots[retained_key].get(relative) == value and
                        not (retained_root / relative).exists(),
                        f"Candidate has a newly dangling symlink; review before promotion: {label}/{relative}")
                unchanged[label][relative] = value
        return unchanged

    def protected_metadata(self):
        """Cheap inode/mtime audit: outputs may grow during plan, but must freeze during apply."""
        records = {}
        for prefix in ("out", INTERMEDIATE):
            root = self.rsrc / prefix
            if not root.exists():
                continue
            for current, directories, files in os.walk(root, followlinks=False):
                for name in directories + files:
                    path = Path(current) / name
                    rel = path.relative_to(self.rsrc).as_posix()
                    if rel == ARGS:
                        continue
                    info = path.lstat()
                    record = {"inode": info.st_ino, "mode": info.st_mode}
                    if not stat.S_ISDIR(info.st_mode):
                        record.update(size=info.st_size, mtimeNs=info.st_mtime_ns)
                    if stat.S_ISLNK(info.st_mode):
                        record["target"] = os.readlink(path)
                    records[rel] = record
        return records

    def make_plan(self):
        require(not (self.audit / "plan.json").exists(), "Audit already contains a plan; use a new audit directory")
        print("Checking prepared source identities...", flush=True)
        identity = self.validate_identity()
        self.checkpoint("identity", identity)
        print("Verifying pinned archive checksums...", flush=True)
        resources = self.resource_audit(identity["lock"])
        self.checkpoint("resources", resources)
        print("Comparing pristine toolchains and retained helpers...", flush=True)
        platforms = self.platform_audit(checkpoint=True)
        self.checkpoint("platforms", platforms)
        print("Hashing candidate and retained source/recipe manifests...", flush=True)
        snapshots = self.snapshots(checkpoint=True)
        unchanged_dangling = self.symlink_audit(snapshots)
        plan = {"schema": 1, "candidateWork": str(self.candidate), "retainedWork": str(self.retained),
                "oldPgid": self.pgid, "createdAtUnixNs": time.time_ns(), "identity": identity,
                "resources": resources, "platforms": platforms, "snapshots": snapshots,
                "unchangedDanglingSymlinks": unchanged_dangling,
                "changes": {"source": changed(snapshots["retainedSource"], snapshots["candidateSource"]),
                            "recipe": changed(snapshots["retainedRecipe"], snapshots["candidateRecipe"]),
                            "args": snapshots["candidateArgs"] != snapshots["retainedArgs"]},
                "notes": ["Empty directory containers are not source identity.",
                    "Python caches, all out/, Rust intermediate output, platform directories and established esbuild link are protected.",
                    "Source preparation readiness requires fresh GN generation before Ninja."]}
        # Capture every directory-to-file/link collision before any apply can remove it.
        for before, after, root in ((snapshots["retainedSource"], snapshots["candidateSource"], self.rsrc),
                                    (snapshots["retainedRecipe"], snapshots["candidateRecipe"], self.retained / "recipe")):
            for rel in changed(before, after):
                if before.get(rel, {}).get("type") == "dir" and after.get(rel, {}).get("type") not in ("dir", None):
                    for current, directories, files in os.walk(root / rel, followlinks=False):
                        for name in directories + files:
                            child = (Path(current) / name).relative_to(root).as_posix()
                            excluded = source_excluded(child) if root == self.rsrc else (
                                cache_path(child) or child == "build" or child.startswith("build/"))
                            require(not excluded, f"Type replacement would remove a protected output/toolchain/Python cache: {rel}")
        write_json(self.audit / "plan.json", plan)
        write_json(self.audit / "plan-sha256.json", {"sha256": json_hash(plan)})
        return plan

    def backup(self, root, label, before, after):
        destination = self.audit / "preimages" / label
        for rel in changed(before, after):
            if rel not in before:
                continue
            old = root / rel
            saved = destination / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            require(saved.parent == saved.parent.resolve(), f"Backup parent is a symlink: {saved}")
            if before[rel]["type"] == "dir":
                saved.mkdir(exist_ok=True)
                shutil.copystat(old, saved, follow_symlinks=False)
            elif before[rel]["type"] == "link":
                saved.symlink_to(os.readlink(old))
            else:
                shutil.copy2(old, saved, follow_symlinks=False)

    def synchronize(self, source, destination, before, after):
        delta = changed(before, after)
        for rel in sorted(delta, key=lambda p: (-len(PurePosixPath(p).parts), p)):
            old, new = before.get(rel), after.get(rel)
            if old and (new is None or old["type"] != new["type"]):
                target = destination / rel
                if old["type"] == "dir":
                    try:
                        target.rmdir()
                    except OSError:
                        require(new is None, f"Cannot replace nonempty directory: {target}")
                else:
                    target.unlink()
        for rel in sorted(delta, key=lambda p: (len(PurePosixPath(p).parts), p)):
            value = after.get(rel)
            if value is None:
                continue
            target = destination / rel
            # A parent symlink was either rejected at entry or replaced earlier.
            require(target.parent == target.parent.resolve(), f"Destination parent is a symlink: {target}")
            if value["type"] == "dir":
                target.mkdir(exist_ok=True)
                target.chmod(value["mode"])
            elif value["type"] == "link":
                temporary = target.with_name(target.name + ".promotion-link")
                require(not temporary.exists() and not temporary.is_symlink(), f"Temporary link exists: {temporary}")
                temporary.symlink_to(value["target"])
                os.replace(temporary, target)
            else:
                fd, temporary = tempfile.mkstemp(prefix=".promotion-", dir=target.parent)
                try:
                    with os.fdopen(fd, "wb") as output, (source / rel).open("rb") as input_file:
                        shutil.copyfileobj(input_file, output, 1024 * 1024)
                    os.chmod(temporary, value["mode"])
                    os.utime(temporary, ns=(time.time_ns(), time.time_ns()))
                    require(sha(temporary) == value["sha256"], f"Candidate changed while copying: {rel}")
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)

    def apply(self):
        plan = json.loads((self.audit / "plan.json").read_text())
        require(json_hash(plan) == json.loads((self.audit / "plan-sha256.json").read_text())["sha256"], "Plan checksum differs")
        require(plan["schema"] == 1 and plan["candidateWork"] == str(self.candidate) and
                plan["retainedWork"] == str(self.retained) and plan["oldPgid"] == self.pgid, "Plan roots or process group differ")
        require(not (self.audit / "applied.json").exists(), "Plan was already applied")
        require(not group_alive(self.pgid), f"Old build process group {self.pgid} is still live; no source was changed")
        require(self.validate_identity() == plan["identity"], "Preparation identity changed since plan")
        print("Rechecking pinned archives and toolchains before mutation...", flush=True)
        require(self.resource_audit(plan["identity"]["lock"]) == plan["resources"], "Resource archives changed since plan")
        require(self.platform_audit() == plan["platforms"], "Platform contents changed since plan")
        snapshots = self.snapshots()
        require(snapshots == plan["snapshots"], "Candidate or retained source changed since plan")
        require(self.symlink_audit(snapshots) == plan["unchangedDanglingSymlinks"],
                "Candidate symlink resolution changed since plan")
        protected = self.protected_metadata()
        require(not group_alive(self.pgid), "Old process group restarted during audit; no source was changed")
        for key in snapshots:
            if isinstance(snapshots[key], dict) and key not in ("candidateArgs", "retainedArgs"):
                for rel in snapshots[key]:
                    validate_relative(rel)
        print("Backing up changed source and recipe preimages...", flush=True)
        self.backup(self.rsrc, "source", snapshots["retainedSource"], snapshots["candidateSource"])
        self.backup(self.retained / "recipe", "recipe", snapshots["retainedRecipe"], snapshots["candidateRecipe"])
        if plan["changes"]["args"]:
            self.backup(self.rsrc, "args", {ARGS: snapshots["retainedArgs"]}, {ARGS: snapshots["candidateArgs"]})
        shutil.copy2(self.retained / "state.json", self.audit / "preimages/state.json")
        ninja = self.rsrc / NINJA
        if plan["platforms"]["helpers"]["removeNinjaShim"]:
            self.backup(self.rsrc, "ninja", {NINJA: node(ninja, self.candidate, self.retained)}, {})
        require(not group_alive(self.pgid), "Old process group restarted while backing up; no source was changed")
        old_state = dict(plan["identity"]["retainedState"])
        old_state["inProgress"] = "promotion"
        write_json(self.retained / "state.json", old_state)
        committed = False
        try:
            print("Synchronizing verified source changes; retaining generated output...", flush=True)
            self.synchronize(self.csrc, self.rsrc, snapshots["retainedSource"], snapshots["candidateSource"])
            self.synchronize(self.candidate / "recipe", self.retained / "recipe", snapshots["retainedRecipe"], snapshots["candidateRecipe"])
            self.synchronize(self.csrc, self.rsrc, {ARGS: snapshots["retainedArgs"]}, {ARGS: snapshots["candidateArgs"]})
            if plan["platforms"]["helpers"]["removeNinjaShim"]:
                ninja.unlink()
            print("Independently verifying promoted source and protected output...", flush=True)
            post = self.snapshots()
            require(post["candidateSource"] == snapshots["candidateSource"] and
                    post["candidateRecipe"] == snapshots["candidateRecipe"] and post["candidateArgs"] == snapshots["candidateArgs"],
                    "Candidate changed during promotion")
            for a, b in (("candidateSource", "retainedSource"), ("candidateRecipe", "retainedRecipe"), ("candidateArgs", "retainedArgs")):
                require(post[a] == post[b], f"Independent post-promotion manifest differs: {a}")
            platforms_after = self.platform_audit()
            expected_platforms = json.loads(json.dumps(plan["platforms"]))
            if plan["platforms"]["helpers"]["removeNinjaShim"]:
                expected_llvm = expected_platforms["third_party/llvm-build/Release+Asserts"]["retained"]
                expected_llvm.pop("bin/ninja")
                for rel in sorted(list(expected_llvm), key=lambda p: -len(PurePosixPath(p).parts)):
                    if expected_llvm[rel]["type"] == "dir" and not any(p.startswith(rel + "/") for p in expected_llvm):
                        del expected_llvm[rel]
                expected_platforms["helpers"]["removeNinjaShim"] = False
            require(platforms_after == expected_platforms, "Protected platform contents changed during promotion")
            require(self.protected_metadata() == protected, "Protected out/intermediate contents or mtimes changed during promotion")
            for key, base, label in (("retainedSource", self.rsrc, "source"),
                                     ("retainedRecipe", self.retained / "recipe", "recipe")):
                for rel, value in post[key].items():
                    if value["type"] == "link":
                        require(not value["target"].startswith(str(self.candidate) + os.sep), f"Candidate-root symlink remains: {rel}")
                        require((base / rel).exists() or
                                plan["unchangedDanglingSymlinks"][label].get(rel) == value,
                                f"New dangling promoted symlink: {rel}")
            require(runpy.run_path(str(self.project / "scripts/source.py"))["input_digest"]() == plan["identity"]["inputDigest"]
                    and sha(self.project / "config/source-lock.json") == plan["identity"]["lockSha256"]
                    and json.loads((self.candidate / "state.json").read_text()) == plan["identity"]["candidateState"],
                    "Frozen preparation inputs changed during promotion")
            provenance = {"audit": str(self.audit), "planSha256": json_hash(plan), "appliedAtUnixNs": time.time_ns(),
                "oldInputDigest": plan["identity"]["retainedState"]["inputDigest"],
                "newInputDigest": plan["identity"]["inputDigest"], "requiresGnGeneration": True,
                "candidateSourceManifestSha256": json_hash(post["candidateSource"]),
                "retainedSourceManifestSha256": json_hash(post["retainedSource"])}
            write_json(self.audit / "post-manifests.json", post)
            write_json(self.audit / "protected-metadata.json", protected)
            state = dict(plan["identity"]["candidateState"])
            state["promotions"] = plan["identity"]["retainedState"].get("promotions", []) + [provenance]
            write_json(self.retained / "state.json", state)
            committed = True
            write_json(self.audit / "applied.json", provenance)
            return provenance
        except BaseException as error:
            write_json(self.audit / "failed.json", {"error": str(error), "timeUnixNs": time.time_ns(),
                "stateCommitted": committed,
                "note": "Verified preparation state committed; completion audit write failed." if committed else
                    "Retained state remains inProgress=promotion. Review preimages before recovery; do not build."})
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply"))
    parser.add_argument("--candidate-work", required=True, type=Path)
    parser.add_argument("--retained-work", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--old-pgid", required=True, type=int)
    parser.add_argument("--expected-retained-version", default="155.0.8059.39")
    args = parser.parse_args()
    promotion = Promotion(args.candidate_work, args.retained_work, args.audit, args.old_pgid,
                          expected_retained_version=args.expected_retained_version)
    if args.command == "plan":
        plan = promotion.make_plan()
        print(f"Audit plan saved: {promotion.audit / 'plan.json'}")
        print(f"Source changes: {len(plan['changes']['source'])}; recipe changes: {len(plan['changes']['recipe'])}; GN args changed: {plan['changes']['args']}")
        print("No source was changed. Apply requires the old build process group to have exited.")
    else:
        promotion.apply()
        print(f"Source promotion verified; preimages and manifests: {promotion.audit}")
        print("Run the current source build driver to regenerate GN before Ninja. No compilation ran here.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Source promotion: {error}", file=sys.stderr)
        sys.exit(1)
