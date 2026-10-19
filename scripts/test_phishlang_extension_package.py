#!/usr/bin/env python3
"""Offline add-on package security and portable-output regressions."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("addon_package", Path(__file__).with_name("package-phishlang-extension.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
ROOT = Path(__file__).resolve().parents[1]


class ExtensionPackaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kumo-phishlang-package-tests-", dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.frontend = self.root / "frontend"
        self.frontend.mkdir()
        self.shared = self.root / "extension"
        self.shared.mkdir()
        manifest = json.loads((ROOT / "addons/phishlang/extension/manifest.json").read_text())
        for name in PACKAGE.FRONTEND:
            (self.frontend / name).write_bytes((ROOT / "addons/phishlang/extension" / name).read_bytes())
        for name in PACKAGE.SHARED:
            (self.shared / name).write_bytes((ROOT / "extension" / name).read_bytes())
        self.model = {"modelVersion": "1" * 40, "modelDirectorySHA256": "2" * 64, "vocabSHA256": "3" * 64,
                      "rightsStatus": "unspecified-code-and-weights", "localDevelopmentOnly": True}
        self.output = self.root / "copied"

    def test_extension_is_dedicated_and_copies_shared_security_code_exactly(self):
        PACKAGE.copy_extension(self.root, self.frontend, self.output, self.model)
        for name in PACKAGE.SHARED:
            self.assertEqual((self.output / name).read_bytes(), (self.shared / name).read_bytes())
        metadata = json.loads((self.output / "build-info.json").read_text())
        self.assertEqual(metadata["extensionId"], "ejmohaggcahgfhmgkdiicnmmlpnhgfmi")
        self.assertIs(metadata["phishingProtection"]["included"], True)
        self.assertIs(metadata["phishingProtection"]["enabledByDefault"], False)
        # User requested this separate package without a rights clearance gate;
        # original provenance remains truthful and is never relabeled cleared.
        self.assertIs(metadata["phishingProtection"]["localDevelopmentOnly"], True)
        self.assertEqual(metadata["phishingProtection"]["rightsStatus"], "unspecified-code-and-weights")

    def test_builtin_extension_key_cannot_be_substituted(self):
        manifest = json.loads((self.frontend / "manifest.json").read_text())
        manifest["key"] = json.loads((ROOT / "extension/manifest.json").read_text())["key"]
        (self.frontend / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, "dedicated"):
            PACKAGE.copy_extension(self.root, self.frontend, self.output, self.model)
        self.assertFalse(self.output.exists())

    def test_incognito_opt_in_cannot_be_packaged(self):
        manifest = json.loads((self.frontend / "manifest.json").read_text())
        manifest["incognito"] = "spanning"
        (self.frontend / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, "incognito"):
            PACKAGE.copy_extension(self.root, self.frontend, self.output, self.model)

    def test_symlink_and_hardlink_sources_fail_even_when_bytes_match(self):
        for kind in ("symbolic", "hard"):
            with self.subTest(kind=kind):
                file = self.frontend / "settings.js"
                outside = self.root / (kind + ".js")
                file.rename(outside)
                if kind == "symbolic": file.symlink_to(outside)
                else: os.link(outside, file)
                with self.assertRaisesRegex(RuntimeError, "regular"):
                    PACKAGE.copy_extension(self.root, self.frontend, self.output, self.model)
                self.assertTrue(outside.exists())
                file.unlink()
                outside.rename(file)

    def test_shared_source_alias_is_rejected(self):
        file = self.shared / "phishing-content.js"
        outside = self.root / "shared-content.js"
        file.rename(outside)
        file.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "regular"):
            PACKAGE.copy_extension(self.root, self.frontend, self.output, self.model)
        self.assertEqual(outside.read_bytes(), (ROOT / "extension/phishing-content.js").read_bytes())

    def test_output_cannot_replace_an_existing_directory_or_symlink(self):
        for kind in ("directory", "symlink"):
            with self.subTest(kind=kind):
                target = self.root / kind
                if kind == "directory": target.mkdir()
                else: target.symlink_to(self.frontend, target_is_directory=True)
                with self.assertRaisesRegex(RuntimeError, "Output already exists"):
                    PACKAGE.assemble(self.root, self.frontend, self.root / "missing model", target, "-", True)
                self.assertTrue(target.exists())

    def test_adhoc_signing_requires_explicit_qa_flag_before_any_build(self):
        with patch.object(PACKAGE, "native_binaries") as native:
            with self.assertRaisesRegex(RuntimeError, "QA-only"):
                PACKAGE.assemble(self.root, self.frontend, self.root / "missing model", self.output, "-")
            native.assert_not_called()

    def test_staged_model_tampering_is_detected_before_signing(self):
        compiled = self.root / "copied-model/PhishLang.mlmodelc"
        compiled.mkdir(parents=True)
        graph = compiled / "model.mil"
        graph.write_bytes(b"verified synthetic graph")
        directory = compiled.parent
        vocab = directory / "vocab.txt"
        vocab.write_bytes(b"verified synthetic vocab")
        manifest = [{"path": "model.mil", "bytes": graph.stat().st_size, "sha256": PACKAGE.digest(graph)}]
        expected = {"modelFiles": manifest, "modelDirectorySHA256": hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    "vocabSHA256": PACKAGE.digest(vocab)}
        (directory / "model-info.json").write_text(json.dumps(expected))
        PACKAGE.verify_copied_model(directory, expected)
        graph.write_bytes(b"mutated synthetic graph")
        with self.assertRaisesRegex(RuntimeError, "model bytes"):
            PACKAGE.verify_copied_model(directory, expected)
        graph.write_bytes(b"verified synthetic graph")
        vocab.write_bytes(b"mutated synthetic vocab")
        with self.assertRaisesRegex(RuntimeError, "vocabulary"):
            PACKAGE.verify_copied_model(directory, expected)
        vocab.write_bytes(b"verified synthetic vocab")
        (directory / "model-info.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "metadata changed"):
            PACKAGE.verify_copied_model(directory, expected)

    def test_model_resource_aliases_and_hardlinks_are_rejected_before_import(self):
        resources = self.root / "model"
        (resources / "upstream").mkdir(parents=True)
        for name in ("model-info.json", "vocab.txt", "upstream/model.safetensors"):
            (resources / name).write_bytes(b"synthetic")
        outside = self.root / "outside"
        os.link(resources / "model-info.json", outside)
        with self.assertRaisesRegex(RuntimeError, "regular"):
            PACKAGE.verified_model(self.root, resources)
        self.assertEqual(outside.read_bytes(), b"synthetic")


if __name__ == "__main__":
    unittest.main()
