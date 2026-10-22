#!/usr/bin/env python3
"""Offline regression checks for preventing accidental engine downgrades."""
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("kumo_package", Path(__file__).with_name("package.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class DowngradeGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kumo-package-guard-test-")
        self.addCleanup(self.temporary.cleanup)
        self.destination = Path(self.temporary.name) / "Kumo.app"
        self.contents = self.destination / "Contents"
        self.contents.mkdir(parents=True)
        self.info = self.contents / "Info.plist"
        self.write_version("155.0.8059.84")
        self.verification = patch.object(PACKAGE.subprocess, "run", return_value=Mock(returncode=0)).start()
        self.addCleanup(patch.stopall)

    def write_version(self, version):
        self.info.write_bytes(plistlib.dumps({"KumoEngineVersion": version}))

    def test_numeric_comparison_ignores_packaging_revision(self):
        self.assertLess(PACKAGE.numeric_engine_version("155.0.8059.9"),
                        PACKAGE.numeric_engine_version("155.0.8059.10"))
        self.assertEqual(PACKAGE.numeric_engine_version("155.0.8059.84-1.1"),
                         PACKAGE.numeric_engine_version("155.0.8059.84"))

    def test_malformed_version_is_rejected(self):
        for value in (None, True, "", "155.0.8059", "155.0.8059.84junk",
                      "155.0.8059.84\n", "155.0.8059.4294967296", "155.0.8059.84-beta"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                PACKAGE.numeric_engine_version(value)

    def test_existing_newer_engine_blocks_preview(self):
        with self.assertRaisesRegex(RuntimeError, "Refusing Chromium engine downgrade"):
            PACKAGE.ensure_no_engine_downgrade(self.destination, "155.0.8059.39-1.1")
        self.verification.assert_called_once_with(
            ["codesign", "--verify", "--strict", str(self.destination)],
            capture_output=True, text=True, check=True)

    def test_equal_or_newer_engine_is_allowed(self):
        PACKAGE.ensure_no_engine_downgrade(self.destination, "155.0.8059.84-1.1")
        PACKAGE.ensure_no_engine_downgrade(self.destination, "155.0.8059.85")

    def test_separate_output_does_not_inherit_other_output_version(self):
        PACKAGE.ensure_no_engine_downgrade(self.destination.parent / "preview/Kumo.app", "155.0.8059.39")
        self.verification.assert_not_called()

    def test_missing_or_malformed_installed_metadata_fails_closed(self):
        for info in ({}, {"KumoEngineVersion": "broken"}, ["not an info dictionary"]):
            self.info.write_bytes(plistlib.dumps(info))
            with self.subTest(info=info), self.assertRaisesRegex(RuntimeError, "replacement was stopped"):
                PACKAGE.ensure_no_engine_downgrade(self.destination, "155.0.8059.85")

    def test_invalid_installed_signature_fails_closed(self):
        self.verification.side_effect = subprocess.CalledProcessError(1, "codesign")
        with self.assertRaisesRegex(RuntimeError, "replacement was stopped"):
            PACKAGE.ensure_no_engine_downgrade(self.destination, "155.0.8059.85")

    def test_rejection_happens_before_assembly(self):
        with patch.object(PACKAGE, "ensure_app_closed"), patch.object(PACKAGE, "incoming_engine_version", return_value="155.0.8059.39"), patch.object(PACKAGE, "assemble") as assemble:
            with self.assertRaisesRegex(RuntimeError, "Refusing Chromium engine downgrade"):
                PACKAGE.package(Path("unused-preview-input"), self.destination, True)
            assemble.assert_not_called()

    def test_newer_app_published_during_assembly_is_preserved(self):
        self.write_version("155.0.8059.39-1.1")

        def assemble(*_arguments):
            self.write_version("155.0.8059.84")
            return {"engineVersion": "155.0.8059.39"}

        with patch.object(PACKAGE, "ensure_app_closed"), \
                patch.object(PACKAGE, "incoming_engine_version", return_value="155.0.8059.39"), \
                patch.object(PACKAGE, "assemble", side_effect=assemble), \
                patch.object(PACKAGE, "publish_preview") as publish:
            with self.assertRaisesRegex(RuntimeError, "Refusing Chromium engine downgrade"):
                PACKAGE.package(Path("unused-preview-input"), self.destination, True)
            publish.assert_not_called()
        self.assertEqual(plistlib.loads(self.info.read_bytes())["KumoEngineVersion"], "155.0.8059.84")

    def test_local_incoming_version_requires_signature_and_full_version(self):
        self.info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "155.0.8059.84"}))
        self.assertEqual(PACKAGE.incoming_engine_version(self.destination, True), "155.0.8059.84")
        self.verification.side_effect = subprocess.CalledProcessError(1, "codesign")
        with self.assertRaisesRegex(RuntimeError, "incoming source engine"):
            PACKAGE.incoming_engine_version(self.destination, True)


class AgentPayloadGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kumo-agent-payload-")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "source"
        self.source.mkdir()
        for relative in PACKAGE.AGENT_RUNTIME_FILES:
            target = self.source / relative
            target.parent.mkdir(exist_ok=True)
            target.write_text("runtime fixture\n")
        self.destination = Path(self.temporary.name) / "packaged"

    def test_local_secrets_and_extra_files_are_never_packaged(self):
        (self.source / ".env").write_text("PRIVATE_QA_SENTINEL")
        (self.source / "pairing-token").write_text("PRIVATE_QA_SENTINEL")
        PACKAGE.copy_agent_runtime(self.destination, self.source)
        files = {p.relative_to(self.destination).as_posix() for p in self.destination.rglob("*") if p.is_file()}
        self.assertEqual(files, set(PACKAGE.AGENT_RUNTIME_FILES))

    def test_symlinked_runtime_file_is_rejected(self):
        target = self.source / "cli.mjs"
        target.unlink()
        target.symlink_to(self.source / "package.json")
        with self.assertRaisesRegex(RuntimeError, "regular source files"):
            PACKAGE.copy_agent_runtime(self.destination, self.source)

    def test_upstream_binary_packaging_is_rejected_before_any_signing(self):
        with patch.object(PACKAGE, "development_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "completed local Chromium source build"):
                PACKAGE.assemble(self.source, self.destination, False, self.destination)
            identity.assert_not_called()

    def test_nested_helper_names_are_branded_without_changing_executable(self):
        import plistlib
        target = self.destination / "Contents/Frameworks/Chromium Helper (Renderer).app/Contents/Info.plist"
        target.parent.mkdir(parents=True)
        target.write_bytes(plistlib.dumps({"CFBundleExecutable": "Chromium Helper (Renderer)", "CFBundleDisplayName": "Chromium Helper (Renderer)", "CFBundleIdentifier": "app.kumo.browser.engine.helper.renderer"}))
        PACKAGE.rebrand_helper_display_names(self.destination)
        info = plistlib.loads(target.read_bytes())
        self.assertEqual(info["CFBundleExecutable"], "Chromium Helper (Renderer)")
        self.assertEqual(info["CFBundleName"], "Kumo Helper (Renderer)")
        self.assertEqual(info["CFBundleDisplayName"], "Kumo Helper (Renderer)")
        self.assertEqual(info["CFBundleIdentifier"], "app.kumo.browser.engine.helper.renderer")


class NativeStartupIsolation(unittest.TestCase):
    def test_native_broker_bootstrap_cannot_use_the_personal_home(self):
        def probe(command, **options):
            environment = options["env"]
            temporary_home = Path(environment["HOME"])
            self.assertTrue(temporary_home.is_dir())
            self.assertEqual(environment["CFFIXED_USER_HOME"], str(temporary_home))
            self.assertNotEqual(temporary_home, Path.home())
            self.assertIn("--use-mock-keychain", command)
            profile = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--user-data-dir=")))
            self.assertEqual(temporary_home.parent, profile)
            return Mock(returncode=0, stdout="<html></html>")
        with patch.object(PACKAGE.subprocess, "run", side_effect=probe):
            PACKAGE.verify_engine_start(Path("/synthetic/Kumo.app"))


if __name__ == "__main__":
    unittest.main()
