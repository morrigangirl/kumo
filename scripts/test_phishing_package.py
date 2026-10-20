#!/usr/bin/env python3
"""Offline negative tests for sealing and probing Kumo's local phishing model.

All fixtures are tiny synthetic bytes. These tests do not load a model, execute
Core ML, copy real weights, launch a browser, or use a person's browser profile.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("kumo_phishing_package", Path(__file__).with_name("package.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class PhishingResources(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kumo-phishing-resources-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "config").mkdir()
        self.resources = self.root / "prepared"
        self.resources.mkdir()
        self.model = self.resources / "PhishLang.mlmodelc"
        (self.model / "weights").mkdir(parents=True)
        (self.model / "weights/weight.bin").write_bytes(b"synthetic compiled model weights")
        (self.model / "model.mil").write_bytes(b"synthetic model graph")
        self.vocab = self.resources / "vocab.txt"
        self.vocab.write_bytes(b"[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\nexample\n")
        self.source_weights = self.resources / "upstream/model.safetensors"
        self.source_weights.parent.mkdir()
        self.source_weights.write_bytes(b"synthetic source Safetensors data")
        self.lock_path = self.root / "config/phishlang-model-lock.json"
        self.lock = {
            "schemaVersion": 1,
            "upstream": {"commit": "1" * 40, "artifacts": [
                {"path": "src/model/model.safetensors", "sha256": sha(self.source_weights.read_bytes()), "bytes": self.source_weights.stat().st_size},
                {"path": "src/model/vocab.txt", "sha256": sha(self.vocab.read_bytes()), "bytes": self.vocab.stat().st_size},
            ]},
            "conversion": {"windowSize": 128, "stride": 64, "maxWindows": 8,
                           "classIndex": 1, "computeUnits": "CPU_ONLY", "precision": "FLOAT32"},
        }
        write_json(self.lock_path, self.lock)
        self.info = {
            "schemaVersion": 1, "sourceCommit": "1" * 40, "modelVersion": "1" * 40,
            "conversionLockSHA256": sha(self.lock_path.read_bytes()),
            "validation": {"passed": True}, "computeUnits": "cpuOnly", "precision": "FLOAT32",
            "minimumMacOS": "13.0", "windowSize": 128, "stride": 64, "maxWindows": 8, "classIndex": 1,
            "vocabSHA256": sha(self.vocab.read_bytes()),
            "upstreamSafetensorsSHA256": sha(self.source_weights.read_bytes()),
            "inputs": [{"name": name, "type": "int32", "shape": [1, 128]}
                       for name in ("input_ids", "attention_mask", "token_type_ids")],
            "output": {"name": "logits", "type": "float32", "shape": [1, 2]},
            "localDevelopmentOnly": True, "rightsStatus": "unspecified-code-and-weights",
        }
        self.refresh_manifest()
        self.write_info()
        self.root_patch = patch.object(PACKAGE, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def refresh_manifest(self):
        manifest = [{"path": path.relative_to(self.model).as_posix(), "bytes": path.stat().st_size,
                     "sha256": sha(path.read_bytes())}
                    for path in sorted(self.model.rglob("*")) if path.is_file()]
        self.info["modelFiles"] = manifest
        self.info["modelDirectorySHA256"] = sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())

    def write_info(self):
        write_json(self.resources / "model-info.json", self.info)

    def invalid(self):
        with self.assertRaisesRegex(RuntimeError, "PhishLang resources are missing or invalid"):
            PACKAGE.verified_phishing_resources(self.resources)

    def test_valid_tiny_prepared_resources_are_accepted(self):
        self.assertEqual(PACKAGE.verified_phishing_resources(self.resources), self.info)

    def test_default_path_uses_only_task_build_directory(self):
        target = self.root / "build/phishlang-model"
        target.parent.mkdir()
        self.resources.rename(target)
        self.assertEqual(PACKAGE.verified_phishing_resources(), self.info)

    def test_compiled_weight_tampering_is_rejected(self):
        (self.model / "weights/weight.bin").write_bytes(b"different compiled weights")
        self.invalid()

    def test_unexpected_compiled_file_is_rejected(self):
        (self.model / "unreviewed-extra.bin").write_bytes(b"unexpected")
        self.invalid()

    def test_missing_compiled_file_is_rejected(self):
        (self.model / "model.mil").unlink()
        self.invalid()

    def test_model_manifest_hash_tampering_is_rejected(self):
        self.info["modelDirectorySHA256"] = "0" * 64
        self.write_info()
        self.invalid()

    def test_model_manifest_entry_tampering_is_rejected(self):
        self.info["modelFiles"][0]["path"] = "../outside.bin"
        self.write_info()
        self.invalid()

    def test_compiled_file_symlink_is_rejected_even_if_bytes_match(self):
        graph = self.model / "model.mil"
        outside = self.resources / "same-graph.mil"
        graph.rename(outside)
        graph.symlink_to(outside)
        self.invalid()

    def test_compiled_directory_symlink_is_rejected(self):
        outside = self.resources / "actual-model"
        self.model.rename(outside)
        self.model.symlink_to(outside, target_is_directory=True)
        self.invalid()

    def test_vocabulary_symlink_is_rejected_even_if_bytes_match(self):
        outside = self.resources / "actual-vocab.txt"
        self.vocab.rename(outside)
        self.vocab.symlink_to(outside)
        self.invalid()

    def test_vocabulary_tampering_is_rejected(self):
        self.vocab.write_bytes(b"changed vocabulary")
        self.invalid()

    def test_vocabulary_and_info_cannot_override_pinned_vocabulary(self):
        self.vocab.write_bytes(b"changed vocabulary")
        self.info["vocabSHA256"] = sha(self.vocab.read_bytes())
        self.write_info()
        self.invalid()

    def test_source_weight_tampering_is_rejected(self):
        self.source_weights.write_bytes(b"changed source weights")
        self.invalid()

    def test_source_weights_and_info_cannot_override_pinned_weights(self):
        self.source_weights.write_bytes(b"changed source weights")
        self.info["upstreamSafetensorsSHA256"] = sha(self.source_weights.read_bytes())
        self.write_info()
        self.invalid()

    def test_conversion_lock_drift_is_rejected(self):
        self.lock["conversion"]["precision"] = "FLOAT16"
        write_json(self.lock_path, self.lock)
        self.invalid()

    def test_different_source_commit_is_rejected_after_lock_hash_refresh(self):
        self.lock["upstream"]["commit"] = "2" * 40
        write_json(self.lock_path, self.lock)
        self.info["conversionLockSHA256"] = sha(self.lock_path.read_bytes())
        self.write_info()
        self.invalid()

    def test_interface_and_provenance_mismatches_are_rejected(self):
        original = copy.deepcopy(self.info)
        for name, value in (("schemaVersion", 2), ("sourceCommit", "2" * 40),
                            ("modelVersion", "2" * 40), ("computeUnits", "all"),
                            ("windowSize", 512), ("stride", 128), ("maxWindows", 9),
                            ("classIndex", 0), ("precision", "FLOAT16")):
            with self.subTest(field=name):
                self.info = copy.deepcopy(original)
                self.info[name] = value
                self.write_info()
                self.invalid()

    def test_unvalidated_conversion_is_rejected(self):
        self.info["validation"]["passed"] = False
        self.write_info()
        self.invalid()

    def test_missing_resources_are_rejected(self):
        for relative in ("model-info.json", "vocab.txt", "upstream/model.safetensors", "PhishLang.mlmodelc/model.mil"):
            with self.subTest(resource=relative):
                path = self.resources / relative
                contents = path.read_bytes()
                path.unlink()
                self.invalid()
                path.write_bytes(contents)

    def test_oversized_compiled_model_is_rejected_without_large_fixture(self):
        weight = self.model / "weights/weight.bin"
        manifest = self.info["modelFiles"]
        for entry in manifest:
            if entry["path"] == "weights/weight.bin":
                entry["bytes"] = 150_000_001
        self.info["modelDirectorySHA256"] = sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
        self.write_info()
        original_stat = Path.stat

        def synthetic_size(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path == weight:
                values = list(result)
                values[6] = 150_000_001
                return type(result)(values)
            return result

        with patch.object(Path, "stat", synthetic_size):
            self.invalid()

    def copied_attribution(self):
        original = Path(__file__).resolve().parents[1] / "native/phishing"
        source = self.root / "native/phishing"
        source.mkdir(parents=True)
        for name in ("NOTICE.md", "LICENSE-MobileBERT.txt"):
            data = (original / name).read_bytes()
            (source / name).write_bytes(data)
            (self.resources / name).write_bytes(data)
        return source

    def test_copied_model_and_current_attribution_are_rechecked(self):
        source = self.copied_attribution()
        notice_sha = PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
        self.assertEqual(notice_sha, sha((source / "NOTICE.md").read_bytes()))
        self.assertEqual(json.loads((self.resources / "model-info.json").read_text())["localDevelopmentOnly"], True)

    def test_model_or_vocab_changed_after_source_verification_is_rejected(self):
        self.copied_attribution()
        for relative in ("PhishLang.mlmodelc/weights/weight.bin", "vocab.txt"):
            with self.subTest(relative=relative):
                path = self.resources / relative
                original = path.read_bytes()
                path.write_bytes(original + b"changed after source verification")
                with self.assertRaisesRegex(RuntimeError, "Packaged PhishLang"):
                    PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
                path.write_bytes(original)

    def test_copied_metadata_changes_and_boolean_integer_coercion_are_rejected(self):
        self.copied_attribution()
        for key, value in (("sourceCommit", "2" * 40), ("localDevelopmentOnly", 1)):
            with self.subTest(key=key):
                changed = {**self.info, key: value}
                write_json(self.resources / "model-info.json", changed)
                with self.assertRaises(RuntimeError):
                    PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
        self.write_info()

    def test_stale_attribution_from_prepared_resources_cannot_replace_current_notice(self):
        source = self.copied_attribution()
        old = (self.resources / "NOTICE.md").read_bytes()
        (source / "NOTICE.md").write_bytes(old + b"\nCurrent owner-approved distribution decision.\n")
        with self.assertRaises(RuntimeError):
            PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
        (self.resources / "NOTICE.md").write_bytes((source / "NOTICE.md").read_bytes())
        PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)

    def test_required_paper_authors_license_and_change_notice_cannot_be_omitted(self):
        source = self.copied_attribution()
        original = (source / "NOTICE.md").read_text()
        for text in ("Sayak Saha Roy", "Shirin Nilizadeh", "https://arxiv.org/abs/2408.05667",
                     "https://creativecommons.org/licenses/by/4.0/", "Kumo changes the runtime"):
            with self.subTest(missing=text):
                changed = original.replace(text, "omitted")
                (source / "NOTICE.md").write_text(changed)
                (self.resources / "NOTICE.md").write_text(changed)
                with self.assertRaisesRegex(RuntimeError, "required attribution"):
                    PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
        (source / "NOTICE.md").write_text(original)
        (self.resources / "NOTICE.md").write_text(original)

    def test_copied_model_aliases_and_hardlinks_are_rejected(self):
        self.copied_attribution()
        graph = self.model / "model.mil"
        outside = self.root / "same-model.mil"
        graph.rename(outside)
        for kind in ("symbolic", "hard"):
            with self.subTest(kind=kind):
                if kind == "symbolic": graph.symlink_to(outside)
                else: os.link(outside, graph)
                with self.assertRaises(RuntimeError):
                    PACKAGE.verify_packaged_phishing_resources(self.resources, self.info)
                graph.unlink()
        outside.rename(graph)

    def test_native_helper_or_model_build_paths_cannot_escape_packaging(self):
        self.copied_attribution()
        helper = self.root / "KumoPhishingHost"
        helper.write_bytes(b"stripped synthetic executable")
        PACKAGE.verify_phishing_portability(helper, self.resources)
        helper.write_bytes(str(self.root).encode())
        with self.assertRaisesRegex(RuntimeError, "build-machine path"):
            PACKAGE.verify_phishing_portability(helper, self.resources)
        helper.write_bytes(b"stripped synthetic executable")
        (self.resources / "model-info.json").write_text(str(Path.home()))
        with self.assertRaisesRegex(RuntimeError, "build-machine path"):
            PACKAGE.verify_phishing_portability(helper, self.resources)


class PhishingStartupProbe(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kumo-phishing-probe-test-")
        self.addCleanup(temporary.cleanup)
        self.destination = Path(temporary.name) / "Kumo.app"
        resources = self.destination / "Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang"
        resources.mkdir(parents=True)
        self.version = "1" * 40
        write_json(resources / "model-info.json", {"modelVersion": self.version})
        self.reply = {"id": "package-probe", "ok": True, "available": True, "modelVersion": self.version,
                      "probability": 0.02, "windows": 1, "tokenCount": 8}
        self.identity = patch.object(PACKAGE, "extension_id", return_value="exampleextensionid")
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def result(self, reply=None):
        body = json.dumps(self.reply if reply is None else reply).encode()
        return Mock(returncode=0, stdout=struct.pack("<I", len(body)) + body, stderr=b"")

    def test_real_native_messaging_command_is_probed_with_public_synthetic_text(self):
        with patch.object(PACKAGE.subprocess, "run", return_value=self.result()) as command:
            PACKAGE.verify_phishing_start(self.destination)
        args, kwargs = command.call_args
        self.assertEqual(args[0], [str(self.destination / "Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost"), "chrome-extension://exampleextensionid/"])
        frame = kwargs["input"]
        length = struct.unpack("<I", frame[:4])[0]
        self.assertEqual(len(frame), length + 4)
        request = json.loads(frame[4:])
        self.assertEqual(set(request), {"id", "type", "text"})
        self.assertEqual(request["id"], "package-probe")
        self.assertEqual(request["type"], "classify")
        self.assertIn("Public library", request["text"])
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 90)

    def test_failed_host_is_rejected(self):
        result = self.result()
        result.returncode = 1
        with patch.object(PACKAGE.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            PACKAGE.verify_phishing_start(self.destination)

    def test_missing_or_malformed_frames_are_rejected(self):
        for data in (b"", b"\x01\x00", struct.pack("<I", 262145) + b"{}", struct.pack("<I", 3) + b"{}", struct.pack("<I", 2) + b"{}extra"):
            with self.subTest(frame=data), patch.object(PACKAGE.subprocess, "run", return_value=Mock(returncode=0, stdout=data)), self.assertRaises(RuntimeError):
                PACKAGE.verify_phishing_start(self.destination)

    def test_status_only_reply_is_not_an_inference_probe(self):
        reply = {"id": "package-probe", "ok": True, "available": True}
        with patch.object(PACKAGE.subprocess, "run", return_value=self.result(reply)), self.assertRaises(RuntimeError):
            PACKAGE.verify_phishing_start(self.destination)

    def test_unavailable_wrong_id_and_wrong_model_are_rejected(self):
        for key, value in (("ok", False), ("available", False), ("id", "different-request"), ("modelVersion", "2" * 40)):
            reply = dict(self.reply, **{key: value})
            with self.subTest(field=key), patch.object(PACKAGE.subprocess, "run", return_value=self.result(reply)), self.assertRaises(RuntimeError):
                PACKAGE.verify_phishing_start(self.destination)

    def test_invalid_inference_values_are_rejected(self):
        for key, value in (("probability", float("nan")), ("probability", float("inf")), ("probability", -0.1),
                           ("probability", 1.1), ("probability", True), ("windows", 0), ("windows", 9),
                           ("windows", True), ("tokenCount", -1), ("tokenCount", True)):
            reply = dict(self.reply, **{key: value})
            with self.subTest(field=key, value=value), patch.object(PACKAGE.subprocess, "run", return_value=self.result(reply)), self.assertRaises(RuntimeError):
                PACKAGE.verify_phishing_start(self.destination)

    def test_host_timeout_is_not_silently_accepted(self):
        with patch.object(PACKAGE.subprocess, "run", side_effect=subprocess.TimeoutExpired("host", 45)), self.assertRaises(subprocess.TimeoutExpired):
            PACKAGE.verify_phishing_start(self.destination)

    def test_failed_probe_preserves_existing_app_and_stops_publication(self):
        self.destination.mkdir(exist_ok=True)
        sentinel = self.destination / "existing-app-sentinel"
        sentinel.write_text("previous working application")

        def failing_assembly(_engine, staged, _local_source, _installed_destination):
            PACKAGE.verify_phishing_start(staged)
            raise AssertionError("A failed host probe must abort assembly")

        failed = self.result()
        failed.returncode = 1
        with patch.object(PACKAGE, "ensure_app_closed"), \
                patch.object(PACKAGE, "ensure_no_engine_downgrade"), \
                patch.object(PACKAGE, "assemble", side_effect=failing_assembly), \
                patch.object(PACKAGE.subprocess, "run", return_value=failed), \
                patch.object(PACKAGE, "publish_preview") as publish, \
                self.assertRaises(RuntimeError):
            PACKAGE.package(Path("unused-engine"), self.destination, False)
        publish.assert_not_called()
        self.assertEqual(sentinel.read_text(), "previous working application")


if __name__ == "__main__":
    unittest.main()
