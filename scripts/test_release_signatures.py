#!/usr/bin/env python3
"""Regression checks for codesign's inline requirement argument boundary."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("kumo_release_signatures", Path(__file__).with_name("sign-release.py"))
SIGNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SIGNER
SPEC.loader.exec_module(SIGNER)


class ReleaseSignatureVerification(unittest.TestCase):
    def setUp(self):
        self.target = Path("/synthetic/Kumo.app/Contents/Helpers/KumoUpdater.app")
        self.item = SIGNER.Item("Contents/Helpers/KumoUpdater.app", "app.kumo.browser.updater", 0x10000, {})
        self.config = {"teamId": "PV65ZWXCWX"}
        self.metadata = {
            "identifier": self.item.identifier, "flags": self.item.flags, "entitlements": {},
            "details": "TeamIdentifier=PV65ZWXCWX\nTimestamp=Oct 19, 2026 at 12:00:00 PM\n"
                       "Authority=Developer ID Application: Carson Press LLC (PV65ZWXCWX)\n",
        }

    def verify(self):
        with patch.object(SIGNER, "run") as command, \
                patch.object(SIGNER, "signing_metadata", return_value=self.metadata):
            SIGNER.verify_item(self.target, self.item, self.config)
        return command

    def test_inline_requirement_is_one_prefixed_argument_with_unchanged_trust_checks(self):
        command = self.verify()
        command.assert_called_once_with(
            "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R",
            '=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            'and certificate leaf[subject.OU] = "PV65ZWXCWX"', self.target,
        )

    def test_team_is_bound_into_the_inline_requirement(self):
        self.config["teamId"] = "AB12345678"
        self.metadata["details"] = self.metadata["details"].replace("PV65ZWXCWX", "AB12345678")
        command = self.verify()
        arguments = command.call_args.args
        requirement = arguments[arguments.index("-R") + 1]
        self.assertTrue(requirement.startswith("=anchor apple generic and "))
        self.assertIn('certificate leaf[subject.OU] = "AB12345678"', requirement)
        self.assertIn("certificate leaf[field.1.2.840.113635.100.6.1.13] exists", requirement)

    def test_inline_parser_fix_does_not_skip_metadata_verification(self):
        valid = dict(self.metadata)
        for field, value in (
            ("identifier", "another.application"), ("flags", 0),
            ("entitlements", {"com.apple.security.get-task-allow": True}),
            ("details", valid["details"].replace("Timestamp=", "Signed Time=")),
            ("details", valid["details"].replace("Authority=Developer ID Application:", "Authority=Apple Development:")),
            ("details", valid["details"].replace("TeamIdentifier=PV65ZWXCWX", "TeamIdentifier=AB12345678")),
        ):
            with self.subTest(field=field, value=value):
                self.metadata = {**valid, field: value}
                with self.assertRaisesRegex(RuntimeError, "Release signature, timestamp, flags, identity, or entitlements"):
                    self.verify()


class NotaryKeychainSelection(unittest.TestCase):
    def test_default_search_list_is_unchanged_and_no_profile_means_no_authentication(self):
        self.assertEqual(SIGNER.notary_auth_args(None), [])
        self.assertEqual(SIGNER.notary_auth_args("Synthetic Notary"),
                         ["--keychain-profile", "Synthetic Notary"])

    def test_explicit_file_with_spaces_is_one_argument_and_contents_are_never_read(self):
        with tempfile.TemporaryDirectory() as directory:
            keychain = Path(directory) / "Synthetic Login.keychain-db"
            keychain.touch()
            with patch.object(Path, "read_bytes", side_effect=AssertionError("Must not read Keychain")), \
                    patch.object(Path, "read_text", side_effect=AssertionError("Must not read Keychain")):
                self.assertEqual(SIGNER.notary_auth_args("Synthetic Notary", keychain),
                                 ["--keychain-profile", "Synthetic Notary", "--keychain", str(keychain.resolve())])

    def test_malformed_selection_fails_before_signing(self):
        for profile, keychain in [(None, Path("some.keychain-db")), ("", None), (" ", None),
                                  ("-profile", None), ("profile\n", None),
                                  ("profile", "\n"), ("profile", "/nonexistent/synthetic.keychain-db")]:
            with self.subTest(profile=profile, keychain=keychain), \
                    patch.object(SIGNER, "run") as command:
                with self.assertRaises(RuntimeError):
                    SIGNER.notary_auth_args(profile, keychain)
                command.assert_not_called()

    def test_signing_uses_selected_keychain_only_for_notary_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            keychain = directory / "Synthetic Login.keychain-db"
            keychain.touch()
            response = SimpleNamespace(returncode=0,
                                       stdout=json.dumps({"id": "synthetic-job", "status": "Accepted"}).encode())
            with patch.object(SIGNER, "run", return_value=response) as command, \
                    patch.object(SIGNER, "running_apps", return_value=[]), \
                    patch.object(SIGNER, "signing_metadata", return_value={"cdhash": "synthetic-hash"}), \
                    patch.object(SIGNER, "remove_stale_tickets"), \
                    patch.object(SIGNER, "configure_release_updater"), \
                    patch.object(SIGNER, "publish_exclusive"):
                result = SIGNER.sign_release(directory / "input/Kumo.app", directory / "output/Kumo.app", [],
                                             {"teamId": "PV65ZWXCWX"}, {"name": "Synthetic Identity"}, None,
                                             "Synthetic Notary", "synthetic-hash", keychain)
            self.assertIs(result["notarized"], True)
            calls = [call.args for call in command.call_args_list]
            submit = [arguments for arguments in calls if arguments[1:3] == ("notarytool", "submit")]
            self.assertEqual(len(submit), 1)
            self.assertEqual(submit[0][4:], ("--keychain-profile", "Synthetic Notary", "--keychain",
                                            str(keychain.resolve()), "--wait", "--output-format", "json"))
            self.assertTrue(all("--keychain" not in arguments for arguments in calls if arguments not in submit))


if __name__ == "__main__":
    unittest.main()
