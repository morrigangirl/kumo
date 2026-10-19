#!/usr/bin/env python3
"""Release policy regressions plus real pinned Sparkle signature tamper checks."""
import base64
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).with_name("github-release.py")
spec = importlib.util.spec_from_file_location("kumo_github_release", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
PUBLIC = base64.b64encode(bytes(range(32))).decode()
SIGNATURE = base64.b64encode(bytes(range(64))).decode()


def configuration():
    return {"schemaVersion": 1, "repository": "morrigangirl/kumo", "version": "0.1.0", "build": "202610190001",
            "feedURL": release.FEED_URL, "publicEDKey": PUBLIC, "signingKeyAccount": "app.kumo.browser.release"}


class ReleasePolicy(unittest.TestCase):
    def read(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            path.write_text(json.dumps(config))
            return release.load_config(path)

    def test_release_feed_and_repository_are_pinned(self):
        for key, value in [("repository", "attacker/kumo"), ("feedURL", "https://example.org/appcast.xml"),
                           ("feedURL", release.FEED_URL.replace("https:", "http:"))]:
            with self.subTest(key=key, value=value):
                config = configuration()
                config[key] = value
                with self.assertRaises(RuntimeError):
                    self.read(config)

    def test_absent_or_malformed_key_cannot_prepare_release(self):
        for key in [None, "", base64.b64encode(b"short").decode(), PUBLIC + "\n", "?" * 44]:
            with self.subTest(key=key):
                config = configuration()
                config["publicEDKey"] = key
                with self.assertRaises(RuntimeError):
                    self.read(config)

    def test_version_and_build_are_not_arbitrary_tag_or_shell_input(self):
        for field, values in [("build", [0, True, "0", "01", "-2", "1.2", "1;touch x", "9" * 19]),
                              ("version", ["1", "1.0", "1.2.3-beta", "01.0.0", "1.0.0/../../other"])]:
            for value in values:
                with self.subTest(field=field, value=value):
                    config = configuration()
                    config[field] = value
                    with self.assertRaises(RuntimeError):
                        self.read(config)
        self.assertEqual(self.read(configuration()), configuration())

    def test_assets_are_bound_to_tag_instead_of_moving_latest_download(self):
        config = configuration()
        self.assertEqual(release.asset_url(config, release.archive_name(config)),
                         "https://github.com/morrigangirl/kumo/releases/download/v0.1.0-202610190001/Kumo-0.1.0-202610190001-macos-arm64.zip")
        for name in ["../other.zip", "/tmp/other.zip", "evil.zip?token=secret", "other.zip#fragment", "$(id).zip"]:
            with self.assertRaises(RuntimeError):
                release.asset_url(config, name)

    def test_monotonicity_includes_drafts_and_all_pages(self):
        config = configuration()
        old = {"tag_name": "v0.1.0-202610180001", "draft": False}
        self.assertIsNone(release.check_monotonic(config, [old]))
        for build in [config["build"], "202610190002"]:
            with self.assertRaises(RuntimeError):
                release.check_monotonic(config, [old, {"tag_name": "v0.0.9-" + build, "draft": True}])
        with self.assertRaises(RuntimeError):
            release.check_monotonic(config, [{"tag_name": "v0.2.0-1", "draft": False}])

    def test_same_tag_resume_requires_one_draft_and_never_overwrites_public(self):
        draft = {"tag_name": release.release_tag(configuration()), "draft": True}
        self.assertIs(release.check_monotonic(configuration(), [draft]), draft)
        for inventory in [[{**draft, "draft": False}], [draft, draft], [{"tag_name": "v0.1.0", "draft": False}], None]:
            with self.assertRaises(RuntimeError):
                release.check_monotonic(configuration(), inventory)

    def test_github_inventory_flattens_pagination_and_refuses_malformed_pages(self):
        with patch.object(release, "run", return_value=b'[[{"tag_name":"v0.1.0-1","draft":false}],[]]') as runner:
            self.assertEqual(len(release.github_releases(configuration())), 1)
            self.assertIn("--paginate", runner.call_args.args)
            self.assertIn("--slurp", runner.call_args.args)
        with patch.object(release, "run", return_value=b'[{"tag_name":"v0.1.0-1"}]'):
            with self.assertRaises(RuntimeError):
                release.github_releases(configuration())

    def test_remote_annotated_and_lightweight_tags_must_resolve_to_commit(self):
        commit, tag = "a" * 40, "b" * 40
        with patch.object(release, "run", return_value=json.dumps({"object": {"type": "commit", "sha": commit}}).encode()):
            self.assertEqual(release.remote_tag_commit(configuration()), commit)
        with patch.object(release, "run", side_effect=[json.dumps({"object": {"type": "tag", "sha": tag}}).encode(),
                                                       json.dumps({"object": {"type": "commit", "sha": commit}}).encode()]) as runner:
            self.assertEqual(release.remote_tag_commit(configuration()), commit)
            self.assertEqual(runner.call_args.args[-1], "repos/morrigangirl/kumo/git/tags/" + tag)
        for object_type in ["tree", "blob", "tag"]:
            with patch.object(release, "run", return_value=json.dumps({"object": {"type": object_type, "sha": tag}}).encode()):
                with self.assertRaises(RuntimeError):
                    release.remote_tag_commit(configuration())

    def test_notes_are_escaped_plain_text_and_os_architecture_are_explicit(self):
        notes = '<script>alert("x")</script> & notes\n'
        xml = release.appcast(configuration(), {"minimumSystemVersion": "13.0.0"}, 123, SIGNATURE, notes,
                              dt.datetime(2026, 10, 19, 12, 0, tzinfo=dt.timezone.utc))
        self.assertNotIn(b"<script>", xml)
        root = ET.fromstring(xml)
        item = root.find("./channel/item")
        self.assertEqual(item.find("description").text, notes)
        self.assertEqual(item.find("description").get(f"{{{release.SPARKLE}}}format"), "plain-text")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}hardwareRequirements"), "arm64")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}minimumSystemVersion"), "13.0.0")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}version"), configuration()["build"])

    def test_keychain_public_key_must_match_committed_key(self):
        with patch.object(release, "run", side_effect=[b'{"verified":true}', b"a-different-key\n"]):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                release.tools(configuration())

    def test_no_archive_can_be_signed_without_successful_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "app.zip"
            archive.write_bytes(b"fixture")
            with patch.object(release, "run", side_effect=[SIGNATURE.encode(), RuntimeError("bad signature")]):
                with self.assertRaisesRegex(RuntimeError, "bad signature"):
                    release.sign_archive(Path("sign_update"), configuration(), archive)

    def test_dirty_checkout_cannot_be_released(self):
        with patch.object(release, "run", return_value=b" M native/launcher/main.swift\n"):
            with self.assertRaisesRegex(RuntimeError, "clean"):
                release.git_commit()

    def test_unnotarized_prepare_never_signs_or_creates_output(self):
        from argparse import Namespace
        with patch.object(release.sys, "platform", "darwin"), patch.object(release, "run") as runner:
            with self.assertRaisesRegex(RuntimeError, "notarytool"):
                release.prepare(Namespace(notary_profile=None), configuration())
            runner.assert_not_called()

    def test_public_model_scope_enforces_only_explicit_included_development_flag(self):
        for build in [{}, {"phishingProtection": {"included": False, "localDevelopmentOnly": True}},
                      {"phishingProtection": {"included": True, "localDevelopmentOnly": False}},
                      {"phishingProtection": {"included": True, "rightsStatus": "unverified"}}]:
            with self.subTest(build=build):
                release.validate_public_model_scope(build)
        with self.assertRaisesRegex(RuntimeError, "localDevelopmentOnly=true"):
            release.validate_public_model_scope({"phishingProtection": {"included": True, "localDevelopmentOnly": True}})

    def test_development_only_model_prepare_stops_before_signing_tools_or_notarization(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Kumo.app"
            metadata = app / "Contents/Resources/KumoExtension/build-info.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({"phishingProtection": {"included": True, "localDevelopmentOnly": True}}))
            with patch.object(release.sys, "platform", "darwin"), \
                    patch.object(release, "git_commit", return_value="a" * 40), \
                    patch.object(release, "app_metadata", return_value={}), \
                    patch.object(release, "tools") as signer, patch.object(release, "run") as runner:
                with self.assertRaisesRegex(RuntimeError, "development-only model"):
                    release.prepare(Namespace(notary_profile="unused-profile", app=app), configuration())
                signer.assert_not_called()
                runner.assert_not_called()

    def test_doctor_reports_bundled_development_only_model_without_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Kumo.app"
            metadata = app / "Contents/Resources/KumoExtension/build-info.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({"phishingProtection": {"included": True, "localDevelopmentOnly": True}}))
            output = io.StringIO()
            with patch.object(release.sys, "argv", [str(SCRIPT), "doctor", "--app", str(app)]), \
                    patch.object(release, "load_config", return_value=configuration()), \
                    patch.object(release, "run") as runner, redirect_stdout(output):
                self.assertEqual(release.main(), 0)
                runner.assert_not_called()
            self.assertTrue(any("localDevelopmentOnly=true" in value
                                for value in json.loads(output.getvalue())["blockersOrRequiredChecks"]))


class ActualSparkleTamperCheck(unittest.TestCase):
    @unittest.skipUnless((release.ROOT / "build/sparkle/bin/sign_update").is_file(), "Run prepare-sparkle.py first")
    def test_pinned_official_tool_signs_whole_feed_and_rejects_tampering(self):
        # An ephemeral QA seed is never put in Keychain, tracked, logged or used
        # in a production config. The public production key is not needed here.
        subprocess.run(["python3", str(release.ROOT / "scripts/prepare-sparkle.py"), "--verify"],
                       capture_output=True, check=True)
        signer = release.ROOT / "build/sparkle/bin/sign_update"
        with tempfile.TemporaryDirectory(prefix="kumo-sparkle-signature-test-") as directory:
            directory = Path(directory)
            seed = directory / "ephemeral-seed"
            seed.write_bytes(base64.b64encode(os.urandom(32)))
            seed.chmod(0o600)
            archive = directory / "fixture.zip"
            archive.write_bytes(b"Synthetic update-signature fixture; not an application.\n")
            command = [str(signer), "--ed-key-file", str(seed)]
            signature = subprocess.run([*command, "-p", str(archive)], capture_output=True, check=True).stdout.decode().strip()
            release.base64_value(signature, 64, "QA signature")
            subprocess.run([*command, "--verify", str(archive), signature], capture_output=True, check=True)
            feed = directory / "appcast.xml"
            feed.write_bytes(release.appcast(configuration(), {"minimumSystemVersion": "13.0.0"},
                                            archive.stat().st_size, signature, "Synthetic QA fixture.\n"))
            subprocess.run([*command, str(feed)], capture_output=True, check=True)
            subprocess.run([*command, "--verify", str(feed)], capture_output=True, check=True)
            signed_bytes = feed.read_bytes()
            self.assertIn(b"edSignature", signed_bytes)
            feed.write_bytes(signed_bytes.replace(b"Synthetic QA fixture.", b"Tampered QA fixture."))
            self.assertNotEqual(subprocess.run([*command, "--verify", str(feed)], capture_output=True).returncode, 0)
            archive.write_bytes(archive.read_bytes() + b"tampered")
            self.assertNotEqual(subprocess.run([*command, "--verify", str(archive), signature], capture_output=True).returncode, 0)


class ArchivedAppPolicy(unittest.TestCase):
    def fixture(self, directory):
        config = configuration()
        app = Path(directory) / "Kumo.app"
        resources = app / "Contents/Resources"
        (resources / "KumoExtension").mkdir(parents=True)
        info = {"CFBundleIdentifier": "app.kumo.browser", "CFBundleExecutable": "Kumo",
                "CFBundleShortVersionString": config["version"], "CFBundleVersion": config["build"],
                "SUFeedURL": config["feedURL"], "SUPublicEDKey": config["publicEDKey"],
                "SURequireSignedFeed": True, "SUVerifyUpdateBeforeExtraction": True,
                "SUSignedFeedFailureExpirationInterval": 0, "SUEnableSystemProfiling": False,
                "SUAllowsAutomaticUpdates": False, "LSMinimumSystemVersion": "13.0"}
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        (resources / "kumo-update-config.json").write_text(json.dumps({**config, "enabled": True}))
        build = {"sourceCompiledLocally": True, "sourceBuildReceipt": {"receiptSha256": "c" * 64},
                 "engineVersion": "155.0.8059.84", "appUpdates": {"ready": True}}
        (resources / "KumoExtension/build-info.json").write_text(json.dumps(build))
        return app, info, build

    def receipt_api(self):
        return {"verify_embedded_receipt": lambda *args: None, "current_input_digest": lambda *args: "fixture"}

    def test_production_requires_the_signed_release_ready_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=self.receipt_api()):
            app, _, build = self.fixture(directory)
            self.assertEqual(release.app_metadata(app, configuration(), production=True)["minimumSystemVersion"], "13.0.0")
            build["appUpdates"]["ready"] = False
            (app / "Contents/Resources/KumoExtension/build-info.json").write_text(json.dumps(build))
            with self.assertRaisesRegex(RuntimeError, "production updater"):
                release.app_metadata(app, configuration(), production=True)
            release.app_metadata(app, configuration(), production=False)

    def test_archived_production_model_development_scope_is_rechecked(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=self.receipt_api()):
            app, _, build = self.fixture(directory)
            build["phishingProtection"] = {"included": True, "localDevelopmentOnly": True}
            path = app / "Contents/Resources/KumoExtension/build-info.json"
            path.write_text(json.dumps(build))
            with self.assertRaisesRegex(RuntimeError, "localDevelopmentOnly=true"):
                release.app_metadata(app, configuration(), production=True)
            # Reading metadata for a local development app remains permitted.
            release.app_metadata(app, configuration(), production=False)
            build["phishingProtection"]["included"] = False
            path.write_text(json.dumps(build))
            release.app_metadata(app, configuration(), production=True)

    def test_any_weak_feed_policy_or_legacy_bundle_version_is_refused(self):
        for key, value in [("SURequireSignedFeed", False), ("SUVerifyUpdateBeforeExtraction", False),
                           ("SUSignedFeedFailureExpirationInterval", 1728000), ("SUEnableSystemProfiling", True),
                           ("CFBundleVersion", "155.0.8059.84"), ("SUAllowsAutomaticUpdates", True)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                app, info, _ = self.fixture(directory)
                info[key] = value
                (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
                with self.assertRaisesRegex(RuntimeError, key):
                    release.app_metadata(app, configuration(), production=True)

    def test_embedded_updater_configuration_must_match_public_release_key_and_feed(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=self.receipt_api()):
            app, _, _ = self.fixture(directory)
            runtime = {**configuration(), "enabled": True, "feedURL": "https://attacker.example/appcast.xml"}
            (app / "Contents/Resources/kumo-update-config.json").write_text(json.dumps(runtime))
            with self.assertRaisesRegex(RuntimeError, "feedURL"):
                release.app_metadata(app, configuration(), production=True)

    def test_invalid_source_receipt_is_propagated_instead_of_trusting_boolean(self):
        api = self.receipt_api()
        def reject(*args):
            raise RuntimeError("source input fingerprint mismatch")
        api["verify_embedded_receipt"] = reject
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=api):
            app, _, _ = self.fixture(directory)
            with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
                release.app_metadata(app, configuration(), production=True)


class GitHubPublicationBoundary(unittest.TestCase):
    def exercise(self, present=(), corrupt_existing=False, corrupt_final=False, publish=False, tag_changes=False):
        from argparse import Namespace
        config = configuration()
        commit = "a" * 40
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            for name in [release.archive_name(config), "appcast.xml", "release.json", "release-notes.md", "SHA256SUMS"]:
                (assets / name).write_bytes(b"fixture " + name.encode() + b"\n")
            existing = {"tag_name": release.release_tag(config), "draft": True} if present else None
            remote = {"isDraft": True, "isPrerelease": False, "tagName": release.release_tag(config),
                      "name": "Kumo 0.1.0", "body": (assets / "release-notes.md").read_text(),
                      "assets": [{"name": name} for name in present]}

            def runner(*args, **kwargs):
                args = tuple(map(str, args))
                commands.append(args)
                if args[:3] == ("git", "-C", str(release.ROOT)):
                    return (commit + "\n").encode()
                if args[:3] == ("gh", "release", "view"):
                    return json.dumps(remote).encode()
                if args[:3] == ("gh", "release", "download"):
                    output = Path(args[args.index("--dir") + 1])
                    if "--pattern" in args:
                        names = [args[args.index("--pattern") + 1]]
                        corrupt = corrupt_existing
                    else:
                        names = [path.name for path in assets.iterdir()]
                        corrupt = corrupt_final
                    for name in names:
                        (output / name).write_bytes((assets / name).read_bytes() + (b"tampered" if corrupt else b""))
                return b""

            manifest = {"commit": commit, "tag": release.release_tag(config)}
            remote_commits = [commit, "b" * 40 if tag_changes else commit]
            with (patch.object(release, "verify_assets", return_value=manifest),
                  patch.object(release, "git_commit", return_value=commit),
                  patch.object(release, "remote_tag_commit", side_effect=remote_commits),
                  patch.object(release, "github_releases", return_value=[existing] if existing else []),
                  patch.object(release, "run", side_effect=runner)):
                try:
                    result = release.upload(Namespace(artifacts=assets, publish=publish), config)
                except RuntimeError as error:
                    return commands, error
                return commands, result

    def test_default_upload_creates_draft_and_never_publishes(self):
        commands, result = self.exercise()
        self.assertIsInstance(result, dict)
        self.assertFalse(result["published"])
        create = next(command for command in commands if command[:3] == ("gh", "release", "create"))
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)
        self.assertNotIn("--clobber", sum((list(value) for value in commands), []))
        self.assertFalse(any(command[:3] == ("gh", "release", "edit") for command in commands))

    def test_explicit_publish_happens_after_draft_download_verification(self):
        commands, result = self.exercise(publish=True)
        self.assertTrue(result["published"])
        self.assertEqual(commands[-1][:3], ("gh", "release", "edit"))
        self.assertIn("--draft=false", commands[-1])
        self.assertIn("--latest", commands[-1])
        self.assertTrue(any(command[:3] == ("gh", "release", "download") for command in commands[:-1]))

    def test_matching_partial_draft_uploads_only_missing_assets(self):
        commands, result = self.exercise(present=("appcast.xml",))
        self.assertIsInstance(result, dict)
        self.assertFalse(any(command[:3] == ("gh", "release", "create") for command in commands))
        uploaded = next(command for command in commands if command[:3] == ("gh", "release", "upload"))
        self.assertFalse(any(value.endswith("/appcast.xml") for value in uploaded))
        self.assertEqual(sum(value.endswith("/release.json") for value in uploaded), 1)

    def test_changed_existing_or_downloaded_asset_never_publishes(self):
        for options in [{"present": ("appcast.xml",), "corrupt_existing": True}, {"corrupt_final": True}, {"tag_changes": True}]:
            with self.subTest(options=options):
                commands, error = self.exercise(publish=True, **options)
                self.assertIsInstance(error, RuntimeError)
                self.assertFalse(any(command[:3] == ("gh", "release", "edit") for command in commands))


class WorkflowSyntax(unittest.TestCase):
    def test_release_shell_and_embedded_python_compile(self):
        workflow = (release.ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request", workflow.replace("pull requests", ""))
        self.assertIn("clean: false", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        lines = workflow.splitlines()
        blocks = []
        for index, line in enumerate(lines):
            if line == "        run: |":
                block = []
                for body in lines[index + 1:]:
                    if body and not body.startswith("          "):
                        break
                    block.append(body[10:] if body else "")
                blocks.append("\n".join(block) + "\n")
        self.assertGreaterEqual(len(blocks), 5)
        python_blocks = 0
        for block in blocks:
            subprocess.run(["/bin/bash", "-n"], input=block.encode(), capture_output=True, check=True)
            if "python3 - <<'PY'\n" in block:
                python_code = block.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
                compile(python_code, "<workflow release validation>", "exec")
                self.assertIn('Path(notes).is_file()', python_code)
                python_blocks += 1
        self.assertEqual(python_blocks, 1)


if __name__ == "__main__":
    unittest.main()
