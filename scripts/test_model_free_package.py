#!/usr/bin/env python3
"""Synthetic package assembly checks for the release's optional model omission.

No real model, compiler, signing identity, browser process, or profile is used.
The real filesystem assembly runs against small fixtures; only external tools
and independently tested provenance/startup checks are replaced.
"""
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("kumo_model_free_package", Path(__file__).with_name("package.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class OptionalModelAssembly(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kumo-model-free-package-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.engine = self.root / "engine/Chromium.app"
        self.destination = self.root / "output/Kumo.app"
        self.engine_file("Contents/MacOS/Chromium")
        self.engine_file("Contents/Info.plist", plistlib.dumps({"CFBundleExecutable": "Chromium"}))
        (self.engine / "Contents/Resources").mkdir()
        self.release = {
            "schemaVersion": 1, "repository": "morrigangirl/kumo", "version": "0.1.0", "build": "202610190001",
            "feedURL": "https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml",
            "publicEDKey": "test-public-key", "signingKeyAccount": "test-account",
        }
        self.phishing_info = {
            "modelVersion": "1" * 40, "modelDirectorySHA256": "2" * 64,
            "vocabSHA256": "3" * 64, "localDevelopmentOnly": True,
            "sourceCommit": "1" * 40, "upstreamSafetensorsSHA256": "4" * 64,
            "rightsStatus": "unspecified-code-and-weights",
        }
        self.malware_info = {"version": "test-list", "domainCount": 3, "sourceCommit": "4" * 40,
                             "SHA256": "5" * 64, "modifiedAt": "2026-10-19T00:00:00Z"}
        for relative in (
            "build/updater-native/KumoUpdater", "build/sparkle/Sparkle.framework/Sparkle", "build/sparkle/LICENSE",
            "build/malware-native/KumoMalwareScanner", "build/malware-native/KumoMalwareSetup",
            "config/clamav-lock.json", "extension/manifest.json",
            "build/phishing-native/KumoPhishingHost", "build/phishlang-model/PhishLang.mlmodelc/model.mil",
            "build/phishlang-model/vocab.txt", "build/phishlang-model/model-info.json",
            "native/phishing/NOTICE.md", "native/phishing/LICENSE-MobileBERT.txt",
        ):
            self.source_file(relative)
        self.source_file("config/source-lock.json", json.dumps({"chromiumVersion": "155.0.8059.84"}).encode())
        for name in ("rules.json", "metadata.json", "source.txt", "LICENSE.txt", "NOTICE.md"):
            self.source_file("build/malware-feed/" + name)
        for relative in PACKAGE.AGENT_RUNTIME_FILES:
            self.source_file("agent-bridge/" + relative)

        replacements = {
            "ROOT": self.root, "development_identity": Mock(return_value=("test-identity", "PV65ZWXCWX")),
            "verified_phishing_resources": Mock(return_value=self.phishing_info),
            "verified_malware_resources": Mock(return_value=self.malware_info),
            "release_configuration": Mock(return_value=self.release), "run": Mock(side_effect=self.external_tool),
            "signature_policy": Mock(return_value=0x10000), "resign_nested_code": Mock(),
            "verify_engine_start": Mock(), "verify_phishing_start": Mock(), "verify_malware_start": Mock(),
            "verify_packaged_phishing_resources": Mock(return_value="5" * 64),
            "extension_id": Mock(return_value="a" * 32),
        }
        self.mocks = replacements
        for name, replacement in replacements.items():
            patcher = patch.object(PACKAGE, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Functions with path-valued defaults retain the real source directory;
        # pass explicit synthetic sources while exercising their original code.
        real_extension_copy, real_agent_copy = PACKAGE.copy_extension_resources, PACKAGE.copy_agent_runtime
        for name, replacement in (
            ("copy_extension_resources", lambda destination: real_extension_copy(destination, self.root / "extension")),
            ("copy_agent_runtime", lambda destination: real_agent_copy(destination, self.root / "agent-bridge")),
        ):
            patcher = patch.object(PACKAGE, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        for obj, name, replacement in (
            (PACKAGE.shutil, "which", Mock(return_value="/synthetic/node")),
            (PACKAGE.subprocess, "check_output", Mock(return_value="22\n")),
            (PACKAGE.subprocess, "run", Mock(side_effect=self.external_result)),
        ):
            patcher = patch.object(obj, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def source_file(self, relative, data=b"tiny synthetic fixture"):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def engine_file(self, relative, data=b"tiny synthetic engine fixture"):
        target = self.engine / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def external_tool(self, *arguments, **_kwargs):
        arguments = [str(argument) for argument in arguments]
        if arguments[0] == "ditto":
            shutil.copytree(arguments[-2], arguments[-1])
        elif arguments[0] == "swiftc":
            output = Path(arguments[arguments.index("-o") + 1])
            output.write_bytes(b"synthetic compiled executable")
        elif arguments[0] == "iconutil":
            Path(arguments[arguments.index("--output") + 1]).write_bytes(b"synthetic icon")

    def external_result(self, arguments, **_kwargs):
        if arguments[0] == "codesign":
            return subprocess.CompletedProcess(arguments, 0, plistlib.dumps({}), b"")
        if arguments[-1] == "--status":
            value = {"available": False, "reason": "release-signing-not-configured",
                     **{name: self.release[name] for name in ("repository", "version", "build")}}
            return subprocess.CompletedProcess(arguments, 0, json.dumps(value).encode(), b"")
        raise AssertionError("Unexpected external command: " + str(arguments))

    def assemble(self, **options):
        return PACKAGE.assemble(self.engine, self.destination, False, self.destination, **options)

    def test_omitted_model_is_not_validated_built_copied_signed_or_probed(self):
        self.mocks["verified_phishing_resources"].side_effect = AssertionError("Model must not be read")
        info = self.assemble(include_phishing=False)
        self.mocks["verified_phishing_resources"].assert_not_called()
        self.mocks["verify_phishing_start"].assert_not_called()
        commands = [[str(argument) for argument in call.args] for call in self.mocks["run"].call_args_list]
        self.assertFalse(any(any("phish" in argument.lower() for argument in command) for command in commands))
        self.assertFalse((self.destination / "Contents/Helpers/KumoPhishing.app").exists())
        self.assertFalse((self.destination / "Contents/Resources/phishing-host-template.json").exists())
        self.assertEqual(info["phishingProtection"], {
            "included": False, "experimental": True, "enabledByDefault": False, "reason": "omitted-from-release",
        })
        saved = json.loads((self.destination / "Contents/Resources/KumoExtension/build-info.json").read_text())
        self.assertEqual(saved["phishingProtection"], info["phishingProtection"])
        PACKAGE.ensure_no_phishing_assets(self.destination)

    def test_model_free_package_retains_domain_rules_scanner_updater_and_agent(self):
        info = self.assemble(include_phishing=False)
        for relative in (
            "Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost",
            "Contents/MacOS/KumoMalwareSetup", "Contents/Resources/malware-host-template.json",
            "Contents/Resources/KumoExtension/malware/rules.json",
            "Contents/Resources/KumoExtension/malware/LICENSE.txt",
            "Contents/Helpers/KumoUpdater.app/Contents/MacOS/KumoUpdater",
            "Contents/Resources/agent-bridge/run", "Contents/Resources/native-host-template.json",
        ):
            with self.subTest(resource=relative):
                self.assertTrue((self.destination / relative).is_file())
        self.assertIs(info["malwareProtection"]["included"], True)
        self.assertIs(info["malwareProtection"]["enabledByDefault"], True)
        self.assertEqual(info["malwareProtection"]["downloadScanner"], "ClamAV (separate official installation required)")
        self.mocks["verified_malware_resources"].assert_called_once_with()
        self.mocks["verify_malware_start"].assert_called_once_with(self.destination)

    def test_default_development_package_still_includes_model_and_startup_probe(self):
        info = self.assemble()
        self.mocks["verified_phishing_resources"].assert_called_once_with()
        self.mocks["verify_phishing_start"].assert_called_once_with(self.destination)
        self.assertIs(info["phishingProtection"]["included"], True)
        self.assertIs(info["phishingProtection"]["localDevelopmentOnly"], True)
        self.assertEqual(info["phishingProtection"]["modelVersion"], self.phishing_info["modelVersion"])
        helper = self.destination / "Contents/Helpers/KumoPhishing.app/Contents"
        self.assertTrue((helper / "MacOS/KumoPhishingHost").is_file())
        self.assertTrue((helper / "Resources/PhishLang/PhishLang.mlmodelc/model.mil").is_file())
        self.assertTrue((helper / "Resources/PhishLang/vocab.txt").is_file())
        self.assertTrue((self.destination / "Contents/Resources/phishing-host-template.json").is_file())
        commands = [[str(argument) for argument in call.args] for call in self.mocks["run"].call_args_list]
        self.assertIn(["bash", str(self.root / "scripts/build-phishing.sh")], commands)
        self.assertTrue(any(command[0] == "codesign" and "app.kumo.phishing" in command for command in commands))

    def test_inherited_model_helper_from_engine_is_rejected_in_omission_mode(self):
        self.engine_file("Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost")
        with self.assertRaisesRegex(RuntimeError, "refuses inherited PhishLang assets"):
            self.assemble(include_phishing=False)


class OmissionGuardsAndRouting(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kumo-model-routing-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_stale_model_template_and_aliases_are_rejected(self):
        for relative in ("Contents/Resources/phishing-host-template.json",
                         "Contents/Resources/PhishLang.mlmodelc/model.mil",
                         "Contents/Resources/legacy/model.safetensors"):
            with self.subTest(resource=relative):
                app = self.root / "Kumo.app"
                file = app / relative
                file.parent.mkdir(parents=True)
                file.write_bytes(b"stale asset")
                with self.assertRaisesRegex(RuntimeError, "refuses inherited PhishLang assets"):
                    PACKAGE.ensure_no_phishing_assets(app)
                shutil.rmtree(app)
        app = self.root / "Kumo.app"
        app.mkdir()
        (app / "KumoPhishing.app").symlink_to(self.root / "absent", target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "refuses inherited PhishLang assets"):
            PACKAGE.ensure_no_phishing_assets(app)

    def test_model_option_reaches_atomic_package_assembly(self):
        app = self.root / "Kumo.app"
        build = {"engineVersion": "155.0.8059.84", "extensionId": "a" * 32, "codeSigningTeamId": "PV65ZWXCWX"}
        for include in (False, True):
            with self.subTest(include=include), patch.object(PACKAGE, "ensure_app_closed"), \
                    patch.object(PACKAGE, "incoming_engine_version", return_value=build["engineVersion"]), \
                    patch.object(PACKAGE, "ensure_no_engine_downgrade"), \
                    patch.object(PACKAGE, "assemble", return_value=build) as assemble, \
                    patch.object(PACKAGE, "publish_preview"), patch("builtins.print"):
                PACKAGE.package(self.root / "Chromium.app", app, True, include_phishing=include)
                self.assertEqual(assemble.call_args.kwargs, {} if include else {"include_phishing": False})

    def test_cli_without_flag_defaults_to_model_inclusion(self):
        self.check_cli([], True)

    def test_cli_without_phishlang_selects_model_free_package(self):
        self.check_cli(["--without-phishlang"], False)

    def check_cli(self, extra, expected):
        engine, output = self.root / "Chromium.app", self.root / "Kumo.app"
        arguments = ["package.py", "--engine-app", str(engine), "--output", str(output), *extra]
        with patch.object(sys, "argv", arguments), patch.object(sys, "platform", "darwin"), \
                patch.object(PACKAGE.os, "uname", return_value=Mock(machine="arm64")), \
                patch.object(PACKAGE, "package") as package:
            PACKAGE.main()
        package.assert_called_once_with(engine.resolve(), output.resolve(), True, include_phishing=expected)


if __name__ == "__main__":
    unittest.main()
