#!/usr/bin/env python3
"""Offline tiny-archive fixtures; never download or touch a prepared source tree."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("verified_lld", Path(__file__).with_name("verified_lld.py"))
lld = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lld)


@unittest.skipUnless(shutil.which("zstd"), "Offline fixtures require the zstd executable")
class VerifiedLldFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="verified-lld-fixture-")
        self.base = Path(self.temporary.name).resolve()
        self.root, self.src = self.base / "project", self.base / "source"
        self.root.mkdir()
        self.src.mkdir()
        self.body = b"synthetic executable bytes for offline verification\n"
        self.archive_root = "LLVM-23.1.3-macOS-ARM64"
        self.binary_name = self.archive_root + "/bin/lld"
        self.link_name = self.archive_root + "/bin/ld64.lld"
        self.filename = self.archive_root + ".tar.zst"
        self.cache = self.root / ".cache/source-downloads" / self.filename
        self.settings = {
            "version": "23.1.3",
            "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/" + self.filename,
            "sha256": "0" * 64,
            "archiveRoot": self.archive_root,
            "binarySha256": hashlib.sha256(self.body).hexdigest(),
            "binarySize": len(self.body),
        }
        self.settings["relativePath"] = self.relative()
        self.make_archive()

    def tearDown(self):
        self.temporary.cleanup()

    def relative(self):
        return "third_party/kumo-lld/23.1.3-" + self.settings["binarySha256"]

    @property
    def destination(self):
        return self.src / self.settings["relativePath"]

    def member(self, name, kind="regular", data=b"", mode=None, target=""):
        item = tarfile.TarInfo(name)
        kinds = {"regular": tarfile.REGTYPE, "symlink": tarfile.SYMTYPE,
                 "hardlink": tarfile.LNKTYPE, "directory": tarfile.DIRTYPE,
                 "fifo": tarfile.FIFOTYPE}
        item.type = kinds[kind]
        # Match the published LLVM 23.1.3 tar metadata, including its symlink.
        item.mode = mode if mode is not None else 0o755
        item.linkname = target
        item.size = len(data) if kind == "regular" else 0
        return item, data

    def members(self):
        return [self.member(self.archive_root, "directory"),
                self.member(self.archive_root + "/include/ignored.h", data=b"never extract this"),
                self.member(self.binary_name, data=self.body),
                self.member(self.link_name, "symlink", target="lld")]

    def tar_bytes(self, members):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as contents:
            for item, data in members:
                contents.addfile(item, io.BytesIO(data) if item.isreg() else None)
        return raw.getvalue()

    def make_archive(self, members=None, raw=None):
        raw = self.tar_bytes(self.members() if members is None else members) if raw is None else raw
        compressed = subprocess.run(["zstd", "--quiet", "--stdout"], input=raw,
                                    stdout=subprocess.PIPE, check=True).stdout
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_bytes(compressed)
        self.settings["sha256"] = hashlib.sha256(compressed).hexdigest()

    def ensure(self):
        return lld.ensure_linker(self.src, self.root, self.settings)

    def assert_unpublished(self):
        self.assertFalse(os.path.lexists(self.destination))
        parent = self.destination.parent
        if parent.exists():
            self.assertEqual(list(parent.glob(".staging-lld-*")), [])

    def test_installs_only_two_entries_and_verifies_existing_without_download(self):
        link = self.ensure()
        self.assertEqual(link, self.destination / "bin/ld64.lld")
        self.assertEqual(os.readlink(link), "lld")
        self.assertEqual(link.read_bytes(), self.body)
        self.assertEqual(stat.S_IMODE((link.parent / "lld").stat().st_mode), 0o755)
        self.assertEqual({str(path.relative_to(self.destination)) for path in self.destination.rglob("*")},
                         {"bin", "bin/lld", "bin/ld64.lld"})
        before = {path: path.lstat().st_mtime_ns for path in (self.destination, link.parent, link, link.parent / "lld")}
        self.cache.unlink()
        with mock.patch.object(lld.subprocess, "Popen", side_effect=AssertionError("No decompressor/download expected")):
            self.assertEqual(self.ensure(), link)
            self.assertEqual(lld.verify_linker(self.src, self.settings), link)
        self.assertEqual(before, {path: path.lstat().st_mtime_ns for path in before})

    def test_invalid_settings_refused_before_filesystem_changes(self):
        cases = [{"relativePath": "../escape"}, {"relativePath": "/tmp/escape"},
                 {"relativePath": "third_party/kumo-lld/23.1.3-shortsha"},
                 {"archiveRoot": "../LLVM"}, {"archiveRoot": "LLVM/foo"},
                 {"binarySha256": "ABCDEF"}, {"sha256": "bad"},
                 {"binarySize": True}, {"binarySize": 0}, {"version": "../23.1.3"},
                 {"url": "http://example.com/archive.tar.zst"},
                 {"url": "https://user:secret@example.com/archive.tar.zst"},
                 {"url": "https://example.com/archive.tar.zst?token=secret"},
                 {"attestationUrl": "https://example.com/proof.jsonl"}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(lld.LinkerError):
                lld.ensure_linker(self.src, self.root, {**self.settings, **changes})
        self.assertEqual(list(self.src.iterdir()), [])

    def test_archive_hash_mismatch_never_starts_decompression(self):
        self.settings["sha256"] = "f" * 64
        with mock.patch.object(lld.subprocess, "Popen", side_effect=AssertionError("Must verify archive first")):
            with self.assertRaisesRegex(lld.LinkerError, "Cached.*checksum"):
                self.ensure()
        self.assertEqual(list(self.src.iterdir()), [])

    def test_binary_hash_and_size_are_independent_of_archive_pin(self):
        self.settings["binarySha256"] = "e" * 64
        self.settings["relativePath"] = self.relative()
        with self.assertRaisesRegex(lld.LinkerError, "Extracted.*checksum"):
            self.ensure()
        self.assert_unpublished()
        self.settings["binarySha256"] = hashlib.sha256(self.body).hexdigest()
        self.settings["relativePath"] = self.relative()
        self.settings["binarySize"] += 1
        with self.assertRaisesRegex(lld.LinkerError, "locked size"):
            self.ensure()
        self.assert_unpublished()

    def test_binary_archive_modes_and_types_rejected(self):
        replacements = [self.member(self.binary_name, data=self.body, mode=mode)
                        for mode in (0o644, 0o777, 0o4755)]
        replacements += [self.member(self.binary_name, kind, target="outside")
                         for kind in ("symlink", "hardlink", "directory", "fifo")]
        for replacement in replacements:
            with self.subTest(type=replacement[0].type, mode=replacement[0].mode):
                entries = [entry for entry in self.members() if entry[0].name != self.binary_name]
                self.make_archive(entries + [replacement])
                with self.assertRaises(lld.LinkerError):
                    self.ensure()
                self.assert_unpublished()

    def test_symlink_types_modes_and_literal_targets_rejected(self):
        replacements = [self.member(self.link_name, "symlink", target=target)
                        for target in ("../lld", "/tmp/lld", "./lld", "bin/lld")]
        replacements += [self.member(self.link_name, "symlink", target="lld", mode=0o777),
                         self.member(self.link_name, data=self.body),
                         self.member(self.link_name, "hardlink", target=self.binary_name)]
        for replacement in replacements:
            with self.subTest(target=replacement[0].linkname, type=replacement[0].type):
                entries = [entry for entry in self.members() if entry[0].name != self.link_name]
                self.make_archive(entries + [replacement])
                with self.assertRaises(lld.LinkerError):
                    self.ensure()
                self.assert_unpublished()

    def test_missing_and_duplicate_selected_entries_rejected(self):
        for selected in (self.binary_name, self.link_name):
            for duplicate in (False, True):
                with self.subTest(selected=selected, duplicate=duplicate):
                    entries = self.members()
                    if duplicate:
                        entries += [next(entry for entry in entries if entry[0].name == selected)]
                    else:
                        entries = [entry for entry in entries if entry[0].name != selected]
                    self.make_archive(entries)
                    with self.assertRaisesRegex(lld.LinkerError, "Duplicate|Missing"):
                        self.ensure()
                    self.assert_unpublished()

    def test_duplicate_in_concatenated_tar_is_not_hidden_by_end_blocks(self):
        first = self.tar_bytes(self.members())
        second = self.tar_bytes([self.member(self.binary_name, data=self.body)])
        self.make_archive(raw=first + second)
        with self.assertRaisesRegex(lld.LinkerError, "Duplicate"):
            self.ensure()
        self.assert_unpublished()

    def test_unsafe_archive_paths_rejected_without_extracting_them(self):
        names = ("/tmp/lld-escape", self.archive_root + "/../escape",
                 self.archive_root + "/bin/../../escape", self.archive_root + "/./bin/lld",
                 self.archive_root + "//bin/lld", self.archive_root + "\\bin\\lld",
                 "different-root/bin/lld")
        for name in names:
            with self.subTest(name=name):
                self.make_archive(self.members() + [self.member(name, data=b"escape")])
                with self.assertRaisesRegex(lld.LinkerError, "archive path"):
                    self.ensure()
                self.assert_unpublished()
        self.assertFalse((self.src / "escape").exists())

    def test_truncated_zstd_fails_even_after_required_tar_members(self):
        self.cache.write_bytes(self.cache.read_bytes()[:-1])
        self.settings["sha256"] = hashlib.sha256(self.cache.read_bytes()).hexdigest()
        with self.assertRaises(lld.LinkerError):
            self.ensure()
        self.assert_unpublished()

    def test_existing_incomplete_destination_is_never_repaired(self):
        self.destination.mkdir(parents=True)
        sentinel = self.destination / "sentinel"
        sentinel.write_text("preserve me")
        with mock.patch.object(lld, "_archive", side_effect=AssertionError("No download or repair")):
            with self.assertRaises(lld.LinkerError):
                self.ensure()
        self.assertEqual(sentinel.read_text(), "preserve me")
        self.assertEqual(set(self.destination.iterdir()), {sentinel})

    def test_existing_binary_content_mode_extra_entries_and_link_are_checked(self):
        self.ensure()
        binary, link = self.destination / "bin/lld", self.destination / "bin/ld64.lld"
        binary.write_bytes(self.body[:-1] + b"!")
        with self.assertRaises(lld.LinkerError):
            lld.verify_linker(self.src, self.settings)
        binary.write_bytes(self.body)
        binary.chmod(0o644)
        with self.assertRaises(lld.LinkerError):
            lld.verify_linker(self.src, self.settings)
        binary.chmod(0o755)
        extra = link.parent / "unexpected"
        extra.write_text("extra")
        with self.assertRaises(lld.LinkerError):
            lld.verify_linker(self.src, self.settings)
        extra.unlink()
        link.unlink()
        link.symlink_to("./lld")
        with self.assertRaises(lld.LinkerError):
            lld.verify_linker(self.src, self.settings)

    def test_existing_symlink_ancestors_and_binary_are_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.src / "third_party").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(lld.LinkerError, "ancestor"):
            self.ensure()
        self.assertEqual(list(outside.iterdir()), [])
        (self.src / "third_party").unlink()
        self.ensure()
        binary = self.destination / "bin/lld"
        external_binary = outside / "lld"
        external_binary.write_bytes(self.body)
        external_binary.chmod(0o755)
        binary.unlink()
        binary.symlink_to(external_binary)
        with self.assertRaises(lld.LinkerError):
            lld.verify_linker(self.src, self.settings)

    def test_existing_fifo_fails_without_blocking(self):
        self.ensure()
        binary = self.destination / "bin/lld"
        binary.unlink()
        os.mkfifo(binary)
        with self.assertRaisesRegex(lld.LinkerError, "regular file"):
            lld.verify_linker(self.src, self.settings)

    def test_atomic_publication_refuses_concurrent_empty_destination(self):
        original = lld._rename_exclusive

        def create_concurrent(source, destination):
            destination.mkdir()
            original(source, destination)

        with mock.patch.object(lld, "_rename_exclusive", side_effect=create_concurrent):
            with self.assertRaisesRegex(lld.LinkerError, "already exists"):
                self.ensure()
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(list(self.destination.parent.glob(".staging-lld-*")), [])

    def test_atomic_publication_happens_only_after_complete_verification(self):
        original = lld._rename_exclusive

        def inspect_then_publish(source, destination):
            self.assertFalse(os.path.lexists(destination))
            self.assertEqual(lld._verify_destination(source, self.settings).read_bytes(), self.body)
            original(source, destination)

        with mock.patch.object(lld, "_rename_exclusive", side_effect=inspect_then_publish) as publish:
            self.ensure()
        publish.assert_called_once()

    def test_download_is_resumable_and_published_only_after_locked_checksum(self):
        compressed = self.cache.read_bytes()
        self.cache.unlink()
        partial = self.cache.with_name(self.filename + ".part")
        partial.write_bytes(compressed[:5])

        def fake_curl(command, **kwargs):
            self.assertEqual(command[0], "curl")
            self.assertIn("--continue-at", command)
            self.assertIn("--proto-redir", command)
            self.assertEqual(partial.read_bytes(), compressed[:5])
            self.assertFalse(self.cache.exists())
            partial.write_bytes(compressed)
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(lld.subprocess, "run", side_effect=fake_curl) as download:
            archive = lld._archive(self.root, lld._settings(self.settings))
        download.assert_called_once()
        self.assertEqual(archive.read_bytes(), compressed)
        self.assertFalse(partial.exists())
        self.assertFalse(self.cache.with_name(self.filename + ".download-lock").exists())

    def test_download_hash_failure_does_not_publish_cache(self):
        self.cache.unlink()

        def fake_curl(command, **kwargs):
            Path(command[command.index("--output") + 1]).write_bytes(b"wrong archive")

        with mock.patch.object(lld.subprocess, "run", side_effect=fake_curl):
            with self.assertRaisesRegex(lld.LinkerError, "Downloaded.*checksum"):
                lld._archive(self.root, lld._settings(self.settings))
        self.assertFalse(self.cache.exists())

    def test_download_rejects_hardlinked_partial_before_curl_can_write(self):
        self.cache.unlink()
        outside = self.base / "preserve"
        outside.write_bytes(b"preserve these bytes")
        os.link(outside, self.cache.with_name(self.filename + ".part"))
        with mock.patch.object(lld.subprocess, "run", side_effect=AssertionError("Do not write hardlink target")):
            with self.assertRaisesRegex(lld.LinkerError, "one link"):
                lld._archive(self.root, lld._settings(self.settings))
        self.assertEqual(outside.read_bytes(), b"preserve these bytes")

    def test_attestation_metadata_is_validated_without_claiming_verification(self):
        self.settings.update(attestationUrl="https://github.com/llvm/llvm-project/proof.jsonl",
                             attestationSha256="a" * 64)
        self.ensure()
        self.assertEqual(lld.verify_linker(self.src, self.settings), self.destination / "bin/ld64.lld")


if __name__ == "__main__":
    unittest.main()
