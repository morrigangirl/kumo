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
from contextlib import contextmanager, redirect_stdout
from unittest.mock import Mock, patch
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

    def test_prepare_forwards_optional_notary_keychain_as_one_argument(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            app = directory / "Kumo.app"
            metadata = app / "Contents/Resources/kumo-build-info.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text("{}")
            notes = directory / "notes.md"
            notes.write_text("Synthetic release notes.\n")
            for keychain in (None, directory / "Synthetic Login.keychain-db"):
                with self.subTest(keychain=keychain), \
                        patch.object(release.sys, "platform", "darwin"), \
                        patch.object(release, "git_commit", return_value="a" * 40), \
                        patch.object(release, "app_metadata", return_value={}), \
                        patch.object(release, "tools", return_value=Path("synthetic-sign-update")), \
                        patch.object(release, "run", side_effect=RuntimeError("Stopped before Apple")) as runner:
                    args = Namespace(app=app, output=directory / "output", notes=notes, identity=None,
                                     profile=None, notary_profile="Synthetic Notary", notary_keychain=keychain)
                    with self.assertRaisesRegex(RuntimeError, "Stopped before Apple"):
                        release.prepare(args, configuration())
                    runner.assert_called_once()
                    command = runner.call_args.args
                    if keychain is None:
                        self.assertNotIn("--notary-keychain", command)
                    else:
                        self.assertEqual(command[-2:], ("--notary-keychain", keychain))

    def test_public_model_scope_requires_explicit_pinned_owner_decision_for_included_models(self):
        for build in [{}, {"phishingProtection": {"included": False, "localDevelopmentOnly": True}}]:
            release.validate_public_model_scope(build)
        for metadata in ({"included": True, "localDevelopmentOnly": False},
                         {"included": True, "rightsStatus": "unverified"}):
            with self.subTest(metadata=metadata), self.assertRaises(RuntimeError):
                release.validate_public_model_scope({"phishingProtection": metadata})
        with self.assertRaisesRegex(RuntimeError, "localDevelopmentOnly=true"):
            release.validate_public_model_scope({"phishingProtection": {"included": True, "localDevelopmentOnly": True}})

    def test_public_model_scope_accepts_exact_configured_decision_without_claiming_upstream_confirmation(self):
        lock = json.loads((release.ROOT / "config/phishlang-model-lock.json").read_text())
        weights = next(item["sha256"] for item in lock["upstream"]["artifacts"] if item["path"] == "src/model/model.safetensors")
        info = {"sourceCommit": lock["upstream"]["commit"], "modelVersion": lock["upstream"]["commit"],
                "upstreamSafetensorsSHA256": weights, "localDevelopmentOnly": True,
                "rightsStatus": lock["rights"]["status"]}
        metadata = {"included": True, "modelVersion": info["modelVersion"],
                    **release._PHISHLANG_POLICY["model_metadata"](info, release.ROOT)}
        release.validate_public_model_scope({"phishingProtection": metadata})
        self.assertIs(metadata["modelLocalDevelopmentOnly"], True)
        self.assertIs(metadata["distributionDecision"]["upstreamConfirmation"], False)
        metadata["distributionDecision"]["sourceCommit"] = "0" * 40
        with self.assertRaises(RuntimeError):
            release.validate_public_model_scope({"phishingProtection": metadata})

    def test_development_only_model_prepare_stops_before_signing_tools_or_notarization(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Kumo.app"
            metadata = app / "Contents/Resources/kumo-build-info.json"
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
            metadata = app / "Contents/Resources/kumo-build-info.json"
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
        resources.mkdir(parents=True)
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
        lock = json.loads((release.ROOT / "config/node-runtime-lock.json").read_bytes())
        build["nativeIntegration"] = {"included": True, "extensionRequired": False, "settingsURL": "chrome://settings/kumo"}
        build["agentRuntime"] = {"included": True, "jitless": True, "version": lock["version"]}
        for name in ("bin/node", "LICENSE.node", "runtime.json", "cli.mjs", "desktop.mjs", "run"):
            path = resources / "agent-bridge" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic regular payload")
        (resources / "agent-bridge/runtime.json").write_text(json.dumps(lock))
        (resources / "kumo-build-info.json").write_text(json.dumps(build))
        return app, info, build

    def test_native_release_refuses_product_extension_and_host_templates(self):
        with tempfile.TemporaryDirectory() as directory:
            app, _, build = self.fixture(directory)
            for name in ("KumoExtension", "native-host-template.json", "phishing-host-template.json", "malware-host-template.json", "setup-agent"):
                path = app / "Contents/Resources" / name
                path.write_bytes(b"retired integration")
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "retired product extension"):
                    release.validate_native_browser(app, build)
                path.unlink()
            release.validate_native_browser(app, build)

    def test_native_release_requires_bundled_node_and_manifest_but_allows_signed_node_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            app, _, build = self.fixture(directory)
            node = app / "Contents/Resources/agent-bridge/bin/node"
            node.write_bytes(b"different final signed executable bytes")
            release.validate_native_browser(app, build)
            node.unlink()
            with self.assertRaisesRegex(RuntimeError, "complete, regular files"):
                release.validate_native_browser(app, build)

    def receipt_api(self):
        return {"verify_embedded_receipt": lambda *args: None, "current_input_digest": lambda *args: "fixture"}

    def test_production_requires_the_signed_release_ready_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=self.receipt_api()):
            app, _, build = self.fixture(directory)
            self.assertEqual(release.app_metadata(app, configuration(), production=True)["minimumSystemVersion"], "13.0.0")
            build["appUpdates"]["ready"] = False
            (app / "Contents/Resources/kumo-build-info.json").write_text(json.dumps(build))
            with self.assertRaisesRegex(RuntimeError, "production updater"):
                release.app_metadata(app, configuration(), production=True)
            release.app_metadata(app, configuration(), production=False)

    def test_archived_production_model_development_scope_is_rechecked(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release.runpy, "run_path", return_value=self.receipt_api()):
            app, _, build = self.fixture(directory)
            build["phishingProtection"] = {"included": True, "localDevelopmentOnly": True}
            path = app / "Contents/Resources/kumo-build-info.json"
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
    def exercise(self, present=(), corrupt_existing=False, corrupt_final=False, publish=False, tag_changes=False,
                 installer=False, version=None):
        from argparse import Namespace
        config = configuration()
        if version:
            config["version"] = version
        commit = "a" * 40
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            for name in [release.archive_name(config), "appcast.xml", "release.json", "release-notes.md", "SHA256SUMS"]:
                (assets / name).write_bytes(b"fixture " + name.encode() + b"\n")
            if installer:
                (assets / release.installer_name(config)).write_bytes(b"synthetic package fixture")
            existing = {"tag_name": release.release_tag(config), "draft": True} if present else None
            remote = {"isDraft": True, "isPrerelease": False, "tagName": release.release_tag(config),
                      "name": f'Kumo {config["version"]}', "body": (assets / "release-notes.md").read_text(),
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
            if installer:
                manifest["installer"] = {"fixture": "verification mocked at publication transport boundary"}
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


    def test_native_release_without_installer_stops_before_any_github_or_git_operation(self):
        from argparse import Namespace
        config = {**configuration(), "version": "0.2.0"}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(release, "verify_assets", return_value={"commit": "a" * 40}), \
                patch.object(release, "git_commit") as checkout, patch.object(release, "run") as runner:
            with self.assertRaisesRegex(RuntimeError, "complete notarized Apple installer"):
                release.upload(Namespace(artifacts=Path(directory), publish=True), config)
            checkout.assert_not_called()
            runner.assert_not_called()

    def test_complete_native_release_uploads_and_download_verifies_all_six_before_publish(self):
        commands, result = self.exercise(installer=True, version="0.2.0", publish=True)
        self.assertTrue(result["published"])
        upload = next(command for command in commands if command[:3] == ("gh", "release", "upload"))
        self.assertEqual(sum(value.endswith(".pkg") for value in upload), 1)
        self.assertEqual(sum(value.endswith(".zip") for value in upload), 1)
        self.assertEqual(commands[-1][:3], ("gh", "release", "edit"))


class CompleteInstallerAssets(unittest.TestCase):
    commit = "a" * 40
    cdhash = "b" * 40

    def config(self):
        return {**configuration(), "version": "0.2.0", "build": "202610210004"}

    def metadata(self):
        return {"bundleIdentifier": "app.kumo.browser", "signingTeamId": "PV65ZWXCWX",
                "minimumSystemVersion": "13.0.0", "engineVersion": "156.0.8078.47",
                "sourceBuildReceiptSha256": "c" * 64}

    def identity(self):
        config = self.config()
        return {"appVersion": config["version"], "appBuild": config["build"],
                "appCDHash": self.cdhash, "teamId": "PV65ZWXCWX", "notarized": True}

    def checksums(self, assets):
        names = sorted(path.name for path in assets.iterdir() if path.name != "SHA256SUMS")
        (assets / "SHA256SUMS").write_text("".join(f"{release.digest(assets / name)}  {name}\n" for name in names))

    def fixture(self, directory, installer=False):
        config = self.config()
        assets = Path(directory) / "base"
        assets.mkdir()
        archive = assets / release.archive_name(config)
        archive.write_bytes(b"Synthetic signed ZIP; cryptographic boundary is independently mocked.\n")
        notes = "Synthetic complete installer release notes.\n"
        (assets / "release-notes.md").write_text(notes)
        app = {**self.metadata(), "codeDirectoryHash": self.cdhash, "notarized": True}
        (assets / "appcast.xml").write_bytes(release.appcast(config, app, archive.stat().st_size, SIGNATURE, notes))
        manifest = {"schemaVersion": 1, "repository": release.REPOSITORY, "tag": release.release_tag(config),
                    "version": config["version"], "build": config["build"], "feedURL": config["feedURL"],
                    "publicEDKey": config["publicEDKey"], "commit": self.commit, "app": app,
                    "archive": {"name": archive.name, "url": release.asset_url(config, archive.name),
                                "length": archive.stat().st_size, "sha256": release.digest(archive), "edSignature": SIGNATURE},
                    "appcast": {"name": "appcast.xml", "sha256": release.digest(assets / "appcast.xml")},
                    "releaseNotes": {"name": "release-notes.md", "sha256": release.digest(assets / "release-notes.md")}}
        if installer:
            package = assets / release.installer_name(config)
            package.write_bytes(b"Synthetic authenticated notarized complete package.\n")
            manifest["installer"] = {"name": package.name, "url": release.asset_url(config, package.name),
                                     "length": package.stat().st_size, "sha256": release.digest(package), **self.identity()}
        (assets / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        self.checksums(assets)
        return assets

    @contextmanager
    def platform_verifiers(self):
        # Filesystem layout, manifest/feed validation and all checksums are real.
        # Only macOS/Sparkle authentication and extracted app inspection are
        # mocked; signed PKG authentication has its own independent test suite.
        with (patch.object(release, "tools", return_value=Path("synthetic-sign-update")),
              patch.object(release, "run", return_value=b""),
              patch.object(release, "app_metadata", side_effect=lambda *args, **kwargs: self.metadata()),
              patch.object(release, "verify_developer_id", return_value=self.cdhash),
              patch.object(release, "verify_installer", side_effect=lambda *args: self.identity()) as package):
            yield package

    def original_bytes(self, assets):
        return {p.name: p.read_bytes() for p in assets.iterdir()}

    def test_five_base_assets_and_exact_six_declared_assets_are_supported(self):
        for included in [False, True]:
            with self.subTest(included=included), tempfile.TemporaryDirectory() as directory, self.platform_verifiers() as verifier:
                assets = self.fixture(directory, included)
                manifest = release.verify_assets(assets, self.config())
                self.assertEqual("installer" in manifest, included)
                self.assertEqual(verifier.call_count, int(included))
                if included:
                    self.assertEqual(verifier.call_args.args[2]["codeDirectoryHash"], self.cdhash)

    def test_extra_package_receipt_or_undeclared_package_is_rejected(self):
        for extra in ["receipt.json", "installer.pkg-receipt.json", release.installer_name(self.config())]:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
                assets = self.fixture(directory)
                (assets / extra).write_bytes(b"An adjacent receipt is not authority.")
                with self.assertRaisesRegex(RuntimeError, "exactly"):
                    release.verify_assets(assets, self.config())

    def test_missing_package_links_and_directory_are_rejected(self):
        for mode in ["missing", "symlink", "hardlink", "directory"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
                assets = self.fixture(directory, True)
                package = assets / release.installer_name(self.config())
                data = package.read_bytes(); package.unlink()
                if mode in ["symlink", "hardlink"]:
                    target = Path(directory) / "outside.pkg"; target.write_bytes(data)
                    if mode == "symlink": package.symlink_to(target)
                    else: os.link(target, package)
                elif mode == "directory": package.mkdir()
                with self.assertRaises(RuntimeError):
                    release.verify_assets(assets, self.config())

    def test_package_byte_tampering_and_every_identity_field_are_bound(self):
        fields = [("url", "https://example.invalid/installer.pkg"), ("name", "other.pkg"),
                  ("length", True), ("sha256", "0" * 64), ("appVersion", "0.1.0"),
                  ("appBuild", "1"), ("appCDHash", "d" * 40), ("teamId", "OTHERTEAM"),
                  ("notarized", False), ("privatePath", "/private/should-not-be-public")]
        for key, value in fields:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
                assets = self.fixture(directory, True)
                manifest = json.loads((assets / "release.json").read_text())
                manifest["installer"][key] = value
                (assets / "release.json").write_text(json.dumps(manifest))
                self.checksums(assets)
                with self.assertRaisesRegex(RuntimeError, "Installer metadata"):
                    release.verify_assets(assets, self.config())
        with tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
            assets = self.fixture(directory, True)
            with (assets / release.installer_name(self.config())).open("ab") as package: package.write(b"TAMPERED")
            self.checksums(assets)
            with self.assertRaisesRegex(RuntimeError, "Installer metadata"):
                release.verify_assets(assets, self.config())

    def test_package_verifier_receives_actual_archived_browser_cdhash_and_rejects_false_identity(self):
        config = self.config(); app = {**self.metadata(), "codeDirectoryHash": self.cdhash}
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "synthetic.pkg"; package.write_bytes(b"Synthetic signed package")
            for wrong in [{**self.identity(), "appCDHash": "d" * 40}, {**self.identity(), "notarized": 1},
                          {**self.identity(), "path": "/private/receipt"}, {**self.identity(), "teamId": "OTHERTEAM"}]:
                with self.subTest(wrong=wrong), patch.object(release.runpy, "run_path", return_value={"verify_public_package": lambda *args: wrong}):
                    with self.assertRaisesRegex(RuntimeError, "Installer identity"):
                        release.verify_installer(package, config, app)
            authenticate = Mock(return_value=self.identity())
            with patch.object(release.runpy, "run_path", return_value={"verify_public_package": authenticate}) as loader:
                self.assertEqual(release.verify_installer(package, config, app), self.identity())
                self.assertEqual(loader.call_args.args, (str(release.ROOT / "scripts/build-installer-pkg.py"),))
                authenticate.assert_called_once_with(package, config["version"], config["build"], self.cdhash)

    def test_package_changes_during_authentication_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "synthetic.pkg"; package.write_bytes(b"Synthetic package")
            def authenticate(*args):
                package.write_bytes(b"Different bytes after authenticated snapshot")
                return self.identity()
            with patch.object(release.runpy, "run_path", return_value={"verify_public_package": authenticate}):
                with self.assertRaisesRegex(RuntimeError, "changed during authentication"):
                    release.verify_installer(package, self.config(), {**self.metadata(), "codeDirectoryHash": self.cdhash})

    def test_manifest_cannot_substitute_a_different_browser_identity_before_package_verification(self):
        with tempfile.TemporaryDirectory() as directory, self.platform_verifiers() as package:
            assets = self.fixture(directory, True)
            manifest = json.loads((assets / "release.json").read_text())
            manifest["app"]["codeDirectoryHash"] = "d" * 40
            manifest["installer"]["appCDHash"] = "d" * 40
            (assets / "release.json").write_text(json.dumps(manifest)); self.checksums(assets)
            with self.assertRaisesRegex(RuntimeError, "Archived app identity"):
                release.verify_assets(assets, self.config())
            package.assert_not_called()

    def test_with_installer_preserves_original_five_and_zip_feed_bytes(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory, self.platform_verifiers(), patch.object(release, "git_commit", return_value=self.commit):
            directory = Path(directory); assets = self.fixture(directory); before = self.original_bytes(assets)
            package = directory / "input.pkg"; package.write_bytes(b"Synthetic independently authenticated package")
            output = directory / "complete"
            result = release.with_installer(Namespace(artifacts=assets, installer=package, output=output), self.config())
            self.assertTrue(result["installerIncluded"]); self.assertFalse(result["uploaded"])
            self.assertEqual(self.original_bytes(assets), before)
            self.assertEqual(len(list(output.iterdir())), 6)
            for name in [release.archive_name(self.config()), "appcast.xml", "release-notes.md"]:
                self.assertEqual((output / name).read_bytes(), before[name])
            self.assertEqual((output / release.installer_name(self.config())).read_bytes(), package.read_bytes())
            release.verify_assets(output, self.config())

    def test_failed_authentication_or_atomic_publish_leaves_original_and_no_partial_output(self):
        from argparse import Namespace
        for failure in ["authentication", "publish", "changed-checkout"]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
                directory = Path(directory); assets = self.fixture(directory); before = self.original_bytes(assets)
                package = directory / "input.pkg"; package.write_bytes(b"Synthetic package")
                output = directory / "complete"; args = Namespace(artifacts=assets, installer=package, output=output)
                with patch.object(release, "git_commit", side_effect=[self.commit, "d" * 40] if failure == "changed-checkout" else lambda:self.commit):
                    if failure == "authentication":
                        context = patch.object(release, "verify_installer", side_effect=RuntimeError("Package authentication failed"))
                    elif failure == "publish":
                        context = patch.object(release, "publish_directory", side_effect=RuntimeError("Exclusive publish failed"))
                    else:
                        context = patch.object(release, "publish_directory", wraps=release.publish_directory)
                    with context, self.assertRaises(RuntimeError): release.with_installer(args, self.config())
                self.assertEqual(self.original_bytes(assets), before); self.assertFalse(output.exists())
                self.assertFalse(any(p.name.startswith(".kumo-installer-release-") for p in directory.iterdir()))

    def test_preexisting_output_wrong_checkout_and_nested_output_are_rejected(self):
        from argparse import Namespace
        for mode in ["existing", "wrong-checkout", "nested"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, self.platform_verifiers():
                directory = Path(directory); assets = self.fixture(directory); before = self.original_bytes(assets)
                output = assets / "nested" if mode == "nested" else directory / "complete"
                if mode == "existing": output.mkdir(); (output / "keep").write_bytes(b"Do not replace")
                with patch.object(release, "git_commit", return_value="d" * 40 if mode == "wrong-checkout" else self.commit), self.assertRaises(RuntimeError):
                    release.with_installer(Namespace(artifacts=assets, installer=directory / "never-read.pkg", output=output), self.config())
                self.assertEqual(self.original_bytes(assets), before)
                if mode == "existing": self.assertEqual((output / "keep").read_bytes(), b"Do not replace")

    def test_nonregular_linked_empty_and_oversized_package_inputs_are_rejected_without_copying(self):
        for mode in ["symlink", "hardlink", "fifo", "empty", "oversized"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                directory = Path(directory); source = directory / "input.pkg"; output = directory / "copy.pkg"
                if mode in ["symlink", "hardlink"]:
                    target = directory / "target.pkg"; target.write_bytes(b"Leave target unchanged")
                    if mode == "symlink": source.symlink_to(target)
                    else: os.link(target, source)
                elif mode == "fifo": os.mkfifo(source, 0o600)
                else:
                    source.write_bytes(b"")
                    if mode == "oversized":
                        with source.open("r+b") as stream: stream.truncate(2 * 1024 ** 3)
                with self.assertRaises((RuntimeError, OSError)): release.copy_regular_asset(source, output)
                self.assertFalse(output.exists())

    def test_with_installer_cli_dispatches_only_local_adapter(self):
        output = io.StringIO()
        with (patch.object(release.sys, "argv", [str(SCRIPT), "with-installer", "--artifacts", "base", "--installer", "signed.pkg", "--output", "complete"]),
              patch.object(release.sys, "platform", "darwin"),
              patch.object(release, "load_config", return_value=self.config()),
              patch.object(release, "with_installer", return_value={"prepared": True, "uploaded": False}) as adapter,
              patch.object(release, "run") as runner, redirect_stdout(output)):
            self.assertEqual(release.main(), 0)
            args = adapter.call_args.args[0]
            self.assertEqual((args.artifacts,args.installer,args.output), (Path("base"),Path("signed.pkg"),Path("complete")))
            runner.assert_not_called()


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
