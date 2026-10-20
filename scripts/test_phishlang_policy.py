#!/usr/bin/env python3
"""Offline regressions for explicit owner decisions and immutable source facts."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("phishlang_policy", Path(__file__).with_name("phishlang-policy.py"))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PhishLangPolicy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kumo-phishlang-policy-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "config").mkdir()
        self.lock = {"upstream": {"repository": "https://github.com/UTA-SPRLab/phishlang", "commit": "1" * 40,
                                 "artifacts": [{"path": "src/model/model.safetensors", "sha256": "2" * 64}]}}
        (self.root / "config/phishlang-model-lock.json").write_text(json.dumps(self.lock))
        self.path = self.root / "config/phishlang-distribution.json"
        self.decision = {"schemaVersion": 1, "status": "owner-accepted-project-interpretation", "acceptedOn": "2026-10-20",
                         "scope": "kumo-browser-public-distribution", "interpretedLicense": "CC-BY-4.0",
                         "basisURL": POLICY.PAPER, "paperURL": POLICY.PAPER, "upstreamConfirmation": False,
                         "attributionRequired": True, "sourceRepository": self.lock["upstream"]["repository"],
                         "sourceCommit": "1" * 40, "upstreamSafetensorsSHA256": "2" * 64}
        self.info = {"modelVersion": "1" * 40, "sourceCommit": "1" * 40, "upstreamSafetensorsSHA256": "2" * 64,
                     "localDevelopmentOnly": True, "rightsStatus": "unspecified-code-and-weights"}
        self.write_decision()

    def write_decision(self):
        self.path.write_text(json.dumps(self.decision))

    def build(self):
        return {"phishingProtection": {"included": True, "modelVersion": self.info["modelVersion"],
                                       **POLICY.model_metadata(self.info, self.root)}}

    def validate(self, build):
        POLICY.validate_public_model_scope(build, self.root)

    def test_exact_accepted_pinned_decision_permits_production_and_keeps_original_facts(self):
        original = copy.deepcopy(self.info)
        build = self.build()
        self.validate(build)
        metadata = build["phishingProtection"]
        self.assertIs(metadata["localDevelopmentOnly"], False)
        self.assertIs(metadata["modelLocalDevelopmentOnly"], True)
        self.assertEqual(metadata["rightsStatus"], "unspecified-code-and-weights")
        self.assertIs(metadata["distributionDecision"]["upstreamConfirmation"], False)
        self.assertIs(metadata["distributionDecision"]["attributionRequired"], True)
        self.assertEqual(self.info, original)

    def test_missing_configuration_keeps_development_policy_and_cannot_release(self):
        self.path.unlink()
        metadata = POLICY.model_metadata(self.info, self.root)
        self.assertIs(metadata["localDevelopmentOnly"], True)
        self.assertNotIn("distributionDecision", metadata)
        with self.assertRaisesRegex(RuntimeError, "localDevelopmentOnly=true"):
            self.validate({"phishingProtection": {"included": True, **metadata}})
        metadata["localDevelopmentOnly"] = False
        with self.assertRaisesRegex(RuntimeError, "explicit accepted"):
            self.validate({"phishingProtection": {"included": True, **metadata}})

    def test_missing_or_modified_embedded_decision_is_rejected(self):
        for field in ("distributionDecision", "distributionDecisionSHA256", "sourceCommit", "upstreamSafetensorsSHA256"):
            with self.subTest(field=field):
                build = self.build()
                del build["phishingProtection"][field]
                with self.assertRaises(RuntimeError): self.validate(build)
        build = self.build()
        build["phishingProtection"]["distributionDecision"]["interpretedLicense"] = "rights-cleared"
        with self.assertRaises(RuntimeError): self.validate(build)

    def test_flipping_development_flag_or_claiming_cleared_rights_is_not_a_bypass(self):
        for metadata in [{"localDevelopmentOnly": False}, {"rightsStatus": "cleared"}, {"distributionDecisionSHA256": "0" * 64}]:
            with self.subTest(metadata=metadata), self.assertRaises(RuntimeError):
                self.validate({"phishingProtection": {"included": True, **metadata}})

    def test_checkpoint_substitution_is_rejected_before_packaging_and_at_release(self):
        for key, replacement in (("sourceCommit", "3" * 40), ("modelVersion", "3" * 40), ("upstreamSafetensorsSHA256", "3" * 64)):
            with self.subTest(key=key):
                info = {**self.info, key: replacement}
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    POLICY.model_metadata(info, self.root)
                build = self.build()
                build["phishingProtection"][key] = replacement
                with self.assertRaises(RuntimeError): self.validate(build)

    def test_upstream_confirmation_or_weakened_citation_condition_is_not_accepted(self):
        for key, value in (("upstreamConfirmation", True), ("attributionRequired", False),
                           ("paperURL", "https://example.com"), ("scope", "any-model")):
            with self.subTest(key=key):
                changed = {**self.decision, key: value}
                self.path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    POLICY.load_decision(self.root)
        self.write_decision()

    def test_decision_config_must_match_exact_locked_repository_commit_and_weights(self):
        for key in ("sourceRepository", "sourceCommit", "upstreamSafetensorsSHA256"):
            with self.subTest(key=key):
                self.path.write_text(json.dumps({**self.decision, key: "wrong"}))
                with self.assertRaises(RuntimeError): POLICY.load_decision(self.root)

    def test_json_boolean_integer_coercion_cannot_change_decision_semantics(self):
        for field, replacement in (("schemaVersion", True), ("upstreamConfirmation", 0), ("attributionRequired", 1)):
            with self.subTest(field=field):
                self.path.write_text(json.dumps({**self.decision, field: replacement}))
                with self.assertRaises(RuntimeError): POLICY.load_decision(self.root)
        self.write_decision()
        build = self.build()
        build["phishingProtection"]["distributionDecision"]["upstreamConfirmation"] = 0
        with self.assertRaises(RuntimeError): self.validate(build)

    def test_malformed_extra_or_aliased_decision_is_rejected(self):
        for text in ("null", "{", json.dumps({**self.decision, "newUpstreamLicense": True}),
                     json.dumps({**self.decision, "acceptedOn": "2026-99-01"})):
            self.path.write_text(text)
            with self.assertRaises(RuntimeError): POLICY.load_decision(self.root)
        self.write_decision()
        moved = self.path.with_name("actual.json")
        self.path.rename(moved)
        self.path.symlink_to(moved)
        with self.assertRaises(RuntimeError): POLICY.load_decision(self.root)

    def test_omitted_model_and_development_metadata_read_remain_compatible(self):
        self.path.write_text("invalid decision")
        self.validate({})
        self.validate({"phishingProtection": {"included": False, "localDevelopmentOnly": True}})
        with self.assertRaises(RuntimeError): self.validate([])


if __name__ == "__main__":
    unittest.main()
