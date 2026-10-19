#!/usr/bin/env python3
"""Offline release-runner provisioning policy checks."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("kumo_release_vendor", Path(__file__).with_name("prepare-release-vendor.py"))
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)
LOCK = json.loads((vendor.ROOT / "config/source-lock.json").read_text())


class VendorPolicy(unittest.TestCase):
    def test_only_pinned_public_sources_and_fixed_relative_paths(self):
        self.assertEqual(len(vendor.pins(LOCK)), 2)
        for name, field, value in [("macosPackaging", "repository", "file:///private/keys"),
                                   ("ungoogledChromium", "commit", "main"),
                                   ("ungoogledChromium", "path", "../escape")]:
            lock = copy.deepcopy(LOCK)
            lock[name][field] = value
            with self.assertRaises(RuntimeError):
                vendor.pins(lock)

    def test_existing_dirty_vendor_is_preserved_without_fetch_checkout_or_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "vendor/ungoogled-chromium-macos"
            (directory / ".git").mkdir(parents=True)
            with patch.object(vendor, "git", side_effect=[LOCK["macosPackaging"]["repository"], " M user-change.patch"]) as runner:
                with self.assertRaisesRegex(RuntimeError, "local changes"):
                    vendor.prepare(root, LOCK)
                self.assertEqual([call.args[1] for call in runner.call_args_list], ["remote", "status"])
                self.assertTrue(directory.is_dir())

    def test_symlink_vendor_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "elsewhere"
            destination.mkdir()
            (root / "vendor").symlink_to(destination, target_is_directory=True)
            with patch.object(vendor, "git") as runner:
                with self.assertRaisesRegex(RuntimeError, "real directory"):
                    vendor.prepare(root, LOCK)
                runner.assert_not_called()

    def test_empty_runner_fetches_exact_commits_and_checks_final_clean_state(self):
        commands = []
        def git(directory, *arguments):
            commands.append(arguments)
            for name, _, relative, commit in vendor.pins(LOCK):
                if str(directory).endswith(relative) and arguments == ("rev-parse", "HEAD"):
                    return commit
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(vendor, "git", side_effect=git):
            result = vendor.prepare(Path(temporary), LOCK)
        fetches = [value for value in commands if value[0] == "fetch"]
        self.assertEqual([value[-1] for value in fetches], [LOCK["macosPackaging"]["commit"], LOCK["ungoogledChromium"]["commit"]])
        self.assertTrue(all(value["clean"] for value in result))
        self.assertFalse(any("reset" in value or "--force" in value for value in commands))
        self.assertEqual(sum(value[:2] == ("submodule", "update") for value in commands), 1)


if __name__ == "__main__":
    unittest.main()
