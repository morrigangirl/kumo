#!/usr/bin/env python3
"""Offline filesystem fixtures for promote-source.py; never use the real build."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("promote_source", Path(__file__).with_name("promote-source.py"))
promotion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(promotion)


class PromotionFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="promotion-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / "project"
        self.candidate = self.root / "candidate"
        self.retained = self.root / "retained"
        self.audit = self.retained / "audit/promotion"
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.put(self.project / "scripts/source.py", "def input_digest():\n    return 'fixture-current'\n")
        self.lock = {"chromiumVersion": "155.0.8059.84", "sourceArchive": {
            "url": "https://example.invalid/chromium-fixture.tar.xz", "sha256": self.archive("chromium-fixture.tar.xz", b"source")},
            "rustArchive": {"url": "https://example.invalid/rust.tar.xz", "sha256": self.archive("rust.tar.xz", b"rust")}}
        self.archive("llvm.tar.xz", b"llvm")
        self.archive("node.tar.xz", b"node")
        self.put(self.project / "config/source-lock.json", json.dumps(self.lock))
        config = "".join(f"[{key}]\nurl = https://example.invalid/{name}\ndownload_filename = {name}\nsha256 = {promotion.sha(self.cache / name)}\n\n"
                         for key, name in (("llvm", "llvm.tar.xz"), ("rust", "rust.tar.xz"), ("nodejs", "node.tar.xz")))
        for work, version, digest in ((self.candidate, "84", "fixture-current"), (self.retained, "39", "fixture-old")):
            self.put(work / "state.json", json.dumps({"done": ["ready"], "inputDigest": digest}))
            self.put(work / "recipe/ungoogled-chromium/chromium_version.txt", "155.0.8059." + version + "\n")
            src = work / "recipe/build/src"
            self.put(src / "chrome/VERSION", f"MAJOR=155\nMINOR=0\nBUILD=8059\nPATCH={version}\n")
            self.put(src / "out/Default/args.gn", "target_cpu = \"arm64\"\n")
            self.put(src / "tools/rust/build_bindgen.py", "BINDGEN = 'fixture'\n")
            self.put(src / "tools/clang/scripts/build.py", "# fixture\n")
            self.put(src / "tools/gn/bootstrap/bootstrap.py", "# fixture\n")
            self.put(src / "same.cc", "same bytes\n")
            self.put(src / "changed.cc", "new\n" if work == self.candidate else "old\n")
            self.put(src / "third_party/llvm-build/Release+Asserts/lib/libclang.dylib", "clang-library")
            self.put(src / "third_party/rust-toolchain/rustc/bin/rustc", "rustc")
            link = src / "third_party/rust-toolchain/bin/rustc"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(src / "third_party/rust-toolchain/rustc/bin/rustc")
            self.put(src / "third_party/node/mac_arm64/node/bin/node", "node")
            (work / "recipe/build/download_cache").symlink_to(self.cache)
            for name in promotion.PLATFORM_INPUTS:
                self.put(work / "recipe" / name, config if name == "downloads-arm64.ini" else "# identical fixture\n")
            self.put(work / "recipe/patches/series", "new-patch\n" if work == self.candidate else "old-patch\n")
        self.csrc = self.candidate / "recipe/build/src"
        self.rsrc = self.retained / "recipe/build/src"
        self.put(self.rsrc / "obsolete/old.cc", "delete me")
        self.put(self.rsrc / "obsolete/__pycache__/keep.pyc", "keep cache")
        self.put(self.csrc / "added.cc", "added")
        (self.csrc / "absolute-link").symlink_to(self.csrc / "added.cc")
        self.put(self.rsrc / "third_party/rust-toolchain/bin/bindgen", "#!/bin/sh\nprintf 'bindgen 0.73.2\\n'\n", 0o755)
        self.put(self.rsrc / "third_party/rust-toolchain/lib/libclang.dylib", "clang-library")
        self.put(self.rsrc / "out/Default/gn", "#!/bin/sh\nprintf 'gn-fixture\\n'\n", 0o755)
        self.put(self.rsrc / "out/Release/gn_build/retained.o", "compiled output")
        self.put(self.retained / "ninja-native-first.py", "ordering shim")
        (self.rsrc / promotion.NINJA).parent.mkdir(parents=True, exist_ok=True)
        (self.rsrc / promotion.NINJA).symlink_to(self.retained / "ninja-native-first.py")
        module = self.retained / "recipe/build/esbuild-node/node_modules/esbuild"
        module.mkdir(parents=True)
        (self.rsrc / promotion.ESBUILD).parent.mkdir(parents=True, exist_ok=True)
        (self.rsrc / promotion.ESBUILD).symlink_to(module)
        checkout = self.rsrc / promotion.INTERMEDIATE / "bindgen-src"
        self.put(checkout / "Cargo.toml", "# bindgen fixture\n")
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "add", "Cargo.toml"], check=True)
        subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        self.patch = mock.patch.object(promotion, "BINDGEN_COMMIT", commit)
        self.patch.start()
        self.old_time = time.time_ns() - 20_000_000_000
        for rel in ("same.cc", "changed.cc", "out/Default/args.gn", "out/Release/gn_build/retained.o"):
            os.utime(self.rsrc / rel, ns=(self.old_time, self.old_time))
        self.utility = promotion.Promotion(self.candidate, self.retained, self.audit, 2_000_000_000, self.project)

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    @staticmethod
    def put(path, text, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)

    def archive(self, name, data):
        (self.cache / name).write_bytes(data)
        return promotion.sha(self.cache / name)

    def test_apply_preserves_mtimes_outputs_and_caches(self):
        self.utility.make_plan()
        started = time.time_ns()
        self.utility.apply()
        self.assertEqual((self.rsrc / "same.cc").stat().st_mtime_ns, self.old_time)
        self.assertEqual((self.rsrc / promotion.ARGS).stat().st_mtime_ns, self.old_time)
        self.assertEqual((self.rsrc / "out/Release/gn_build/retained.o").stat().st_mtime_ns, self.old_time)
        self.assertGreaterEqual((self.rsrc / "changed.cc").stat().st_mtime_ns, started)
        self.assertGreaterEqual((self.rsrc / "added.cc").stat().st_mtime_ns, started)
        self.assertFalse((self.rsrc / "obsolete/old.cc").exists())
        self.assertEqual((self.rsrc / "obsolete/__pycache__/keep.pyc").read_text(), "keep cache")
        self.assertEqual(os.readlink(self.rsrc / "absolute-link"), str(self.rsrc / "added.cc"))
        self.assertEqual((self.audit / "preimages/source/changed.cc").read_text(), "old\n")
        self.assertEqual((self.audit / "preimages/source/obsolete/old.cc").read_text(), "delete me")
        self.assertFalse((self.rsrc / promotion.NINJA).is_symlink())
        self.assertTrue((self.audit / "preimages/ninja" / promotion.NINJA).is_symlink())
        state = json.loads((self.retained / "state.json").read_text())
        self.assertEqual(state["inputDigest"], "fixture-current")
        self.assertTrue(state["promotions"][0]["requiresGnGeneration"])
        self.assertNotIn("inProgress", state)
        self.assertEqual((self.retained / "recipe/patches/series").read_text(), "new-patch\n")

    def test_bindgen_probe_uses_only_verified_runtime_library_directory(self):
        original = subprocess.check_output
        with mock.patch.object(promotion.subprocess, "check_output", wraps=original) as calls:
            proof = self.utility.platform_audit()
        probes = [item for item in calls.call_args_list
                  if item.args[0] == [str(self.rsrc / "third_party/rust-toolchain/bin/bindgen"), "--version"]]
        self.assertEqual(len(probes), 1)
        expected = str(self.rsrc / "third_party/rust-toolchain/lib")
        self.assertEqual(probes[0].kwargs["env"]["DYLD_LIBRARY_PATH"], expected)
        self.assertEqual(proof["helpers"]["bindgenLibrarySearchPath"], expected)

    def test_late_helper_failure_keeps_successful_platform_checkpoints(self):
        self.put(self.csrc / "tools/rust/build_bindgen.py", "changed helper input\n")
        with self.assertRaisesRegex(RuntimeError, "Helper source inputs changed"):
            self.utility.make_plan()
        self.assertFalse((self.audit / "plan.json").exists())
        for rel in promotion.PLATFORM:
            path = self.audit / "checkpoints" / ("platform-" + rel.replace("/", "__") + ".json")
            checkpoint = json.loads(path.read_text())
            self.assertEqual(checkpoint["valueSha256"], promotion.json_hash(checkpoint["value"]))
            self.assertIn("Apply independently rehashes", checkpoint["note"])

    def test_active_pgid_refuses_before_source_mutation(self):
        self.utility.pgid = os.getpgrp()
        self.utility.make_plan()
        before = (self.retained / "state.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "still live"):
            self.utility.apply()
        self.assertEqual((self.retained / "state.json").read_bytes(), before)
        self.assertEqual((self.rsrc / "changed.cc").read_text(), "old\n")

    def test_corrupted_candidate_after_plan_is_rejected(self):
        self.utility.make_plan()
        self.put(self.csrc / "changed.cc", "corruption")
        with self.assertRaisesRegex(RuntimeError, "changed since plan"):
            self.utility.apply()
        self.assertEqual((self.rsrc / "changed.cc").read_text(), "old\n")

    def test_new_dangling_link_refuses_plan_before_mutation(self):
        (self.csrc / "new-broken-link").symlink_to("missing-upstream-target")
        before = (self.retained / "state.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "newly dangling symlink"):
            self.utility.make_plan()
        self.assertEqual((self.retained / "state.json").read_bytes(), before)
        self.assertFalse((self.audit / "plan.json").exists())
        self.assertFalse((self.rsrc / "new-broken-link").is_symlink())

    def test_unchanged_upstream_dangling_link_is_recorded_and_preserved(self):
        for src in (self.csrc, self.rsrc):
            (src / "upstream-broken-link").symlink_to("missing-upstream-target")
        plan = self.utility.make_plan()
        self.assertIn("upstream-broken-link", plan["unchangedDanglingSymlinks"]["source"])
        self.utility.apply()
        self.assertEqual(os.readlink(self.rsrc / "upstream-broken-link"), "missing-upstream-target")
        self.assertFalse((self.rsrc / "upstream-broken-link").exists())

    def test_changed_dangling_link_refuses_plan(self):
        (self.rsrc / "changed-broken-link").symlink_to("old-missing-target")
        (self.csrc / "changed-broken-link").symlink_to("new-missing-target")
        with self.assertRaisesRegex(RuntimeError, "newly dangling symlink"):
            self.utility.make_plan()

    def test_candidate_dangling_old_resolving_link_requires_review(self):
        self.put(self.rsrc / "old-target", "present only in old source")
        for src in (self.csrc, self.rsrc):
            (src / "formerly-valid-link").symlink_to("old-target")
        with self.assertRaisesRegex(RuntimeError, "newly dangling symlink"):
            self.utility.make_plan()

    def test_changed_destination_after_plan_is_rejected(self):
        self.utility.make_plan()
        self.put(self.rsrc / "changed.cc", "concurrent edit")
        with self.assertRaisesRegex(RuntimeError, "changed since plan"):
            self.utility.apply()

    def test_archive_corruption_is_rejected(self):
        (self.cache / "chromium-fixture.tar.xz").write_bytes(b"wrong")
        with self.assertRaisesRegex(RuntimeError, "source archive checksum failed"):
            self.utility.make_plan()

    def test_only_expected_platform_default_version_metadata_may_change(self):
        for work, version in ((self.candidate, "84"), (self.retained, "39")):
            path = work / "recipe/downloads-arm64.ini"
            path.write_text("[DEFAULT]\n_chromium_version = 155.0.8059." + version + "\n\n" + path.read_text())
        plan = self.utility.make_plan()
        self.assertTrue(plan["resources"]["downloads-arm64.ini"]["expectedVersionMetadataOnly"])
        self.utility.apply()
        self.assertIn("_chromium_version = 155.0.8059.84", (self.retained / "recipe/downloads-arm64.ini").read_text())

    def test_platform_version_exception_rejects_other_changed_bytes(self):
        for work, version in ((self.candidate, "84"), (self.retained, "39")):
            path = work / "recipe/downloads-arm64.ini"
            path.write_text("[DEFAULT]\n_chromium_version = 155.0.8059." + version + "\n\n" + path.read_text())
        path = self.candidate / "recipe/downloads-arm64.ini"
        path.write_text(path.read_text().replace("[llvm]\n", "[llvm]\nversion = unexpected\n"))
        with self.assertRaisesRegex(RuntimeError, "Platform resource inputs changed"):
            self.utility.make_plan()

    def test_unknown_platform_addition_is_rejected(self):
        self.put(self.rsrc / "third_party/rust-toolchain/bin/unexpected", "unknown")
        with self.assertRaisesRegex(RuntimeError, "Unexpected old platform additions"):
            self.utility.make_plan()

    def test_type_replacements_do_not_follow_old_symlinks(self):
        outside = self.root / "outside"
        self.put(outside / "sentinel", "never touch")
        (self.rsrc / "link-to-outside").symlink_to(outside)
        self.put(self.csrc / "link-to-outside", "regular now")
        self.put(self.rsrc / "old-directory/child", "old")
        self.put(self.csrc / "old-directory", "file now")
        self.put(self.rsrc / "old-file", "old file")
        self.put(self.csrc / "old-file/child", "directory now")
        self.utility.make_plan()
        self.utility.apply()
        self.assertEqual((outside / "sentinel").read_text(), "never touch")
        self.assertEqual((self.rsrc / "link-to-outside").read_text(), "regular now")
        self.assertEqual((self.rsrc / "old-directory").read_text(), "file now")
        self.assertEqual((self.rsrc / "old-file/child").read_text(), "directory now")

    def test_executable_mode_change_gets_fresh_mtime(self):
        (self.csrc / "same.cc").chmod(0o755)
        self.utility.make_plan()
        started = time.time_ns()
        self.utility.apply()
        self.assertEqual(stat.S_IMODE((self.rsrc / "same.cc").stat().st_mode), 0o755)
        self.assertGreaterEqual((self.rsrc / "same.cc").stat().st_mtime_ns, started)

    def test_missing_candidate_ready_digest_is_rejected(self):
        self.put(self.candidate / "state.json", json.dumps({"done": ["ready"], "inputDigest": "stale"}))
        with self.assertRaisesRegex(RuntimeError, "inputDigest differs"):
            self.utility.make_plan()

    def test_type_replacement_of_cache_parent_is_rejected(self):
        self.put(self.csrc / "obsolete", "would remove protected cache")
        with self.assertRaisesRegex(RuntimeError, "protected output/toolchain/Python cache"):
            self.utility.make_plan()

    def test_type_replacement_of_protected_toolchain_parent_is_rejected(self):
        import shutil
        shutil.rmtree(self.csrc / "third_party/node")
        self.put(self.csrc / "third_party/node", "would remove protected node output")
        # A candidate protected root with a type mismatch must fail before any mutation.
        with self.assertRaises(RuntimeError):
            self.utility.make_plan()

    def test_retained_version_must_match_expected_provenance(self):
        self.put(self.rsrc / "chrome/VERSION", "MAJOR=155\nMINOR=0\nBUILD=8059\nPATCH=79\n")
        with self.assertRaisesRegex(RuntimeError, "expected old provenance"):
            self.utility.make_plan()

    def test_candidate_common_version_must_match_lock(self):
        self.put(self.candidate / "recipe/ungoogled-chromium/chromium_version.txt", "155.0.8059.39\n")
        with self.assertRaisesRegex(RuntimeError, "common chromium_version.txt"):
            self.utility.make_plan()

    def test_args_change_does_not_replace_other_outputs(self):
        self.put(self.csrc / promotion.ARGS, "target_cpu = \"arm64\"\nsymbol_level = 0\n")
        output = self.rsrc / "out/Release/gn_build/retained.o"
        inode = output.stat().st_ino
        self.utility.make_plan()
        self.utility.apply()
        self.assertEqual((self.rsrc / promotion.ARGS).read_bytes(), (self.csrc / promotion.ARGS).read_bytes())
        self.assertEqual(output.stat().st_ino, inode)
        self.assertEqual(output.stat().st_mtime_ns, self.old_time)

    def test_interrupted_apply_leaves_build_blocking_marker(self):
        self.utility.make_plan()
        with mock.patch.object(self.utility, "synchronize", side_effect=RuntimeError("fixture interruption")):
            with self.assertRaisesRegex(RuntimeError, "fixture interruption"):
                self.utility.apply()
        state = json.loads((self.retained / "state.json").read_text())
        self.assertEqual(state["inProgress"], "promotion")
        self.assertEqual(state["inputDigest"], "fixture-old")
        self.assertTrue((self.audit / "failed.json").is_file())
        self.assertFalse((self.audit / "applied.json").exists())


if __name__ == "__main__":
    unittest.main()
