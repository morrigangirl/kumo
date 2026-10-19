#!/usr/bin/env python3
"""Offline source-receipt fixtures; no Chromium build, SDK, or signing access."""
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("build_receipt", Path(__file__).with_name("build_receipt.py"))
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


class BuildReceiptFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="build-receipt-fixture-")
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "project"
        self.app = self.root / "out/Chromium.app"
        self.version = "155.0.8059.84"
        self.fingerprint = hashlib.sha256(b"current fixture inputs").hexdigest()
        self.gn = self.root / "out/args.gn"
        self.put(self.gn, b'target_cpu = "arm64"\n')
        self.lock = {"schema": 1, "targetCpu": "arm64", "chromiumVersion": self.version}
        self.put(self.repo / "config/source-lock.json", json.dumps(self.lock).encode())
        self.put(self.repo / "scripts/source.py", (
            "def input_digest():\n    return " + repr(self.fingerprint) + "\n"
            "if __name__ == '__main__':\n    raise RuntimeError('build CLI must never run in receipt checks')\n").encode())
        self.info = self.app / "Contents/Info.plist"
        self.put(self.info, plistlib.dumps({"CFBundleExecutable": "Chromium", "CFBundleShortVersionString": self.version}))
        self.main = self.app / "Contents/MacOS/Chromium"
        self.put(self.main, self.macho(2, b"synthetic engine code"))
        self.framework = self.app / "Contents/Frameworks/Chromium Framework.framework"
        self.framework_version = self.framework / "Versions" / self.version
        self.framework_binary = self.framework_version / "Chromium Framework"
        self.framework_info = self.framework_version / "Resources/Info.plist"
        self.put(self.framework_binary, self.macho(6, b"synthetic framework code"))
        self.put(self.framework_info, plistlib.dumps({"CFBundleExecutable": "Chromium Framework", "CFBundleShortVersionString": self.version}))
        (self.framework / "Versions/Current").symlink_to(self.version)
        (self.framework / "Chromium Framework").symlink_to("Versions/Current/Chromium Framework")
        (self.framework / "Resources").symlink_to("Versions/Current/Resources")

    def tearDown(self):
        self.temporary.cleanup()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def macho(self, role, payload, cpu=0x0100000c):
        return struct.pack("<8I", 0xfeedfacf, cpu, 0, role, 0, 0, 0, 0) + payload

    def record(self):
        return receipt.record_build(self.app, self.repo, self.fingerprint, self.gn)

    def verify(self):
        return receipt.verify_receipt(self.app, self.repo, self.fingerprint)

    def rewrite(self, value):
        value["receiptSha256"] = receipt._checksum(value)
        receipt.default_receipt_path(self.app).write_text(json.dumps(value))

    def test_completed_build_round_trip_and_path_free_embed(self):
        local = self.record()
        embedded = self.verify()
        self.assertNotIn("engineAppPath", embedded)
        self.assertEqual(local["engineAppPath"], str(self.app))
        self.assertNotEqual(local["receiptSha256"], embedded["receiptSha256"])
        self.assertEqual(embedded["engineMachOSha256"], hashlib.sha256(self.main.read_bytes()).hexdigest())
        self.assertEqual(receipt.verify_embedded_receipt(embedded, self.repo, self.fingerprint, self.version), embedded)
        self.assertEqual(embedded["gnArgsSha256"], hashlib.sha256(self.gn.read_bytes()).hexdigest())
        self.assertEqual(embedded["frameworkExecutablePath"], str(self.framework_binary.relative_to(self.app)))
        self.assertEqual(receipt.default_receipt_path(self.app).parent, self.app.parent)

    def test_missing_receipt_rejects_arbitrary_engine(self):
        with self.assertRaisesRegex(receipt.ReceiptError, "No successful"):
            self.verify()

    def test_each_changed_source_output_is_rejected(self):
        for path in (self.main, self.framework_binary, self.info, self.framework_info):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                self.record()
                path.write_bytes(original + b" ")
                try:
                    with self.assertRaises(receipt.ReceiptError):
                        self.verify()
                finally:
                    path.write_bytes(original)

    def test_changed_source_inputs_reject_stale_build(self):
        self.record()
        with self.assertRaisesRegex(receipt.ReceiptError, "build inputs"):
            receipt.verify_receipt(self.app, self.repo, "0" * 64)

    def test_changed_lock_even_same_version_rejects_stale_build(self):
        self.record()
        self.lock["notes"] = "different source pin"
        (self.repo / "config/source-lock.json").write_text(json.dumps(self.lock))
        with self.assertRaisesRegex(receipt.ReceiptError, "build inputs"):
            self.verify()

    def test_old_binary_version_cannot_record_new_source_lock(self):
        value = plistlib.loads(self.info.read_bytes())
        value["CFBundleShortVersionString"] = "155.0.8059.39"
        self.info.write_bytes(plistlib.dumps(value))
        value["CFBundleExecutable"] = "Chromium Framework"
        self.framework_info.write_bytes(plistlib.dumps(value))
        with self.assertRaisesRegex(receipt.ReceiptError, "current source lock"):
            self.record()
        self.assertFalse(receipt.default_receipt_path(self.app).exists())

    def test_copied_app_requires_staged_hash_api_not_original_path(self):
        self.record()
        copy_app = self.root / "copy/Chromium.app"
        shutil.copytree(self.app, copy_app, symlinks=True)
        path = receipt.default_receipt_path(self.app)
        with self.assertRaisesRegex(receipt.ReceiptError, "different application path"):
            receipt.verify_receipt(copy_app, self.repo, self.fingerprint, path)
        sanitized = self.verify()
        receipt.verify_artifact_hashes(copy_app, sanitized)
        (copy_app / "Contents/MacOS/Chromium").write_bytes(self.macho(2, b"stale output"))
        with self.assertRaisesRegex(receipt.ReceiptError, "output hashes"):
            receipt.verify_artifact_hashes(copy_app, sanitized)

    def test_hash_tamper_without_checksum_rejected(self):
        value = self.record()
        value["engineMachOSha256"] = "0" * 64
        receipt.default_receipt_path(self.app).write_text(json.dumps(value))
        with self.assertRaisesRegex(receipt.ReceiptError, "checksum"):
            self.verify()

    def test_malformed_or_extra_fields_rejected_even_with_checksum(self):
        local = self.record()
        cases = [{**local, "schema": True}, {**local, "schema": "1"},
                 {**local, "sourceInputsSha256": "bad"},
                 {**local, "completedAt": "2026-02-31T00:00:00Z"},
                 {**local, "completedAt": "9999-01-01T00:00:00Z"},
                 {**local, "extraPrivatePath": "/Users/example"},
                 {**local, "frameworkExecutablePath": "../../escape"},
                 {**local, "frameworkExecutablePath": "Contents/Frameworks/Chromium Framework.framework/Versions/../Chromium Framework"},
                 {**local, "frameworkInfoPlistPath": "Contents/Frameworks/Chromium Framework.framework/Versions/B/Resources/Info.plist"},
                 {key: item for key, item in local.items() if key != "gnArgsSha256"}]
        for case in cases:
            with self.subTest(keys=set(case)):
                self.rewrite(case)
                with self.assertRaises(receipt.ReceiptError):
                    self.verify()

    def test_embedded_receipt_forbids_local_path_and_mismatched_version(self):
        local = self.record()
        with self.assertRaisesRegex(receipt.ReceiptError, "fields"):
            receipt.verify_embedded_receipt(local, self.repo, self.fingerprint, self.version)
        embedded = self.verify()
        with self.assertRaisesRegex(receipt.ReceiptError, "version"):
            receipt.verify_embedded_receipt(embedded, self.repo, self.fingerprint, "155.0.8059.39")

    def test_escaped_framework_symlink_is_rejected(self):
        outside = self.root / "outside-macho"
        outside.write_bytes(self.framework_binary.read_bytes())
        self.framework_binary.unlink()
        self.framework_binary.symlink_to(outside)
        with self.assertRaisesRegex(receipt.ReceiptError, "outside"):
            self.record()

    def test_wrong_architecture_and_binary_role_are_rejected(self):
        for role, cpu in ((6, 0x0100000c), (2, 0x01000007)):
            with self.subTest(role=role, cpu=cpu):
                self.main.write_bytes(self.macho(role, b"wrong", cpu))
                with self.assertRaisesRegex(receipt.ReceiptError, "architecture or executable role"):
                    self.record()
        self.main.write_bytes(b"arbitrary text binary")
        with self.assertRaisesRegex(receipt.ReceiptError, "Mach-O"):
            self.record()

    def test_receipt_cannot_be_written_inside_sealed_source_bundle(self):
        with self.assertRaisesRegex(receipt.ReceiptError, "outside the signed app"):
            receipt.record_build(self.app, self.repo, self.fingerprint, self.gn,
                                 receipt_path=self.app / "Contents/receipt.json")

    def test_failed_atomic_write_keeps_old_receipt(self):
        self.record()
        path = receipt.default_receipt_path(self.app)
        original = path.read_bytes()
        with mock.patch.object(receipt.os, "replace", side_effect=OSError("fixture disk failure")):
            with self.assertRaises(OSError):
                self.record()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(list(path.parent.glob(".kumo-receipt-*")), [])

    def test_invalidation_removes_old_success_before_build(self):
        self.record()
        receipt.invalidate_receipt(self.app)
        receipt.invalidate_receipt(self.app)
        with self.assertRaisesRegex(receipt.ReceiptError, "No successful"):
            self.verify()

    def test_current_fingerprint_loads_only_source_pure_function(self):
        self.assertEqual(receipt.current_input_digest(self.repo), self.fingerprint)
        (self.repo / "scripts/source.py").write_text("def input_digest():\n    return 'invalid'\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "sourceInputsSha256"):
            receipt.current_input_digest(self.repo)

    def test_bad_json_is_rejected(self):
        receipt.default_receipt_path(self.app).write_text("not json")
        with self.assertRaisesRegex(receipt.ReceiptError, "valid JSON"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
