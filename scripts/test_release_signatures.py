#!/usr/bin/env python3
"""Regression checks for codesign's inline requirement argument boundary."""
import importlib.util
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main()
