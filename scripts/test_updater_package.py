#!/usr/bin/env python3
"""Updater trust metadata, release activation, and pinned dependency regressions."""
import base64
import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = load('updater_package', 'package.py')
signing = load('updater_release_signing', 'sign-release.py')
sparkle = load('updater_prepare_sparkle', 'prepare-sparkle.py')
release = load('updater_github_release', 'github-release.py')


class ReleaseActivation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kumo-update-package-')
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / 'Kumo.app'
        self.resources = self.app / 'Contents/Resources'
        (self.resources / 'KumoExtension').mkdir(parents=True)
        self.config = {
            'schemaVersion': 1, 'repository': 'morrigangirl/kumo', 'version': '0.1.0', 'build': '202610190001',
            'feedURL': 'https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml',
            'publicEDKey': base64.b64encode(bytes(range(32))).decode(), 'signingKeyAccount': 'app.kumo.browser.release',
        }
        self.info = package.updater_plist(self.config)
        self.policy = {**self.config, 'enabled': False, 'teamId': 'PV65ZWXCWX'}
        self.build = {'signingMode': 'apple-development', 'appUpdates': {
            'included': True, 'ready': False, **{key: self.config[key] for key in ['repository', 'version', 'build', 'feedURL']},
        }}
        self.write_fixture()

    def write_fixture(self):
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))
        (self.resources / 'kumo-update-config.json').write_text(json.dumps(self.policy))
        (self.resources / 'KumoExtension/build-info.json').write_text(json.dumps(self.build))

    def activate(self, notarize):
        with patch.object(signing.runpy, 'run_path', return_value={
                'load_config': lambda: self.config, 'validate_public_model_scope': release.validate_public_model_scope}):
            signing.configure_release_updater(self.app, notarize)
        return (json.loads((self.resources / 'kumo-update-config.json').read_text()),
                json.loads((self.resources / 'KumoExtension/build-info.json').read_text()))

    def test_developer_id_without_notarization_keeps_updates_disabled(self):
        policy, build = self.activate(False)
        self.assertIs(policy['enabled'], False)
        self.assertIs(build['appUpdates']['ready'], False)
        self.assertEqual(build['signingMode'], 'developer-id')

    def test_only_notarized_staging_enables_release_status(self):
        policy, build = self.activate(True)
        self.assertIs(policy['enabled'], True)
        self.assertIs(build['appUpdates']['ready'], True)
        self.assertEqual(policy['publicEDKey'], self.config['publicEDKey'])

    def test_development_only_included_model_cannot_activate_or_mutate_staging(self):
        self.build['phishingProtection'] = {'included': True, 'localDevelopmentOnly': True}
        self.write_fixture()
        paths = [self.app / 'Contents/Info.plist', self.resources / 'kumo-update-config.json',
                 self.resources / 'KumoExtension/build-info.json']
        before = [path.read_bytes() for path in paths]
        for notarize in [False, True]:
            with self.subTest(notarize=notarize), self.assertRaisesRegex(RuntimeError, 'localDevelopmentOnly=true'):
                self.activate(notarize)
            self.assertEqual([path.read_bytes() for path in paths], before)

    def test_explicitly_omitted_model_does_not_block_production_activation(self):
        self.build['phishingProtection'] = {'included': False, 'localDevelopmentOnly': True}
        self.write_fixture()
        policy, build = self.activate(True)
        self.assertIs(policy['enabled'], True)
        self.assertIs(build['appUpdates']['ready'], True)

    def test_version_key_and_feed_mismatches_reject_without_mutation(self):
        for key, value in [('CFBundleVersion', '1'), ('SUFeedURL', 'https://example.org/update.xml'),
                           ('SUPublicEDKey', base64.b64encode(b'x' * 32).decode()),
                           ('SURequireSignedFeed', False), ('SUSignedFeedFailureExpirationInterval', 86400),
                           ('SUAllowsAutomaticUpdates', True), ('SUVerifyUpdateBeforeExtraction', 1)]:
            with self.subTest(key=key):
                saved = self.info[key]
                self.info[key] = value
                self.write_fixture()
                before = (self.resources / 'kumo-update-config.json').read_bytes()
                with self.assertRaises(RuntimeError):
                    self.activate(True)
                self.assertEqual((self.resources / 'kumo-update-config.json').read_bytes(), before)
                self.info[key] = saved

    def test_staged_policy_and_ui_must_both_match_selected_release(self):
        self.policy['repository'] = 'other/browser'
        self.write_fixture()
        with self.assertRaises(RuntimeError):
            self.activate(True)
        self.policy['repository'] = self.config['repository']
        self.build['appUpdates']['build'] = '1'
        self.write_fixture()
        with self.assertRaises(RuntimeError):
            self.activate(True)

    def test_no_silent_install_no_profile_and_strict_feed_by_default(self):
        self.assertIs(self.info['SUEnableSystemProfiling'], False)
        self.assertIs(self.info['SUAllowsAutomaticUpdates'], False)
        self.assertIs(self.info['SUAutomaticallyUpdate'], False)
        self.assertIs(self.info['SURequireSignedFeed'], True)
        self.assertIs(self.info['SUVerifyUpdateBeforeExtraction'], True)
        self.assertEqual(self.info['SUSignedFeedFailureExpirationInterval'], 0)
        self.assertEqual(self.info['CFBundleVersion'], self.config['build'])


class PreparedDependency(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kumo-sparkle-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'config').mkdir()
        self.directory = self.root / 'build/sparkle'
        self.directory.mkdir(parents=True)
        self.lock = {'version': '2.10.0', 'archiveSHA256': 'a' * 64}
        (self.root / 'config/sparkle-lock.json').write_text(json.dumps(self.lock))
        for name in ['Sparkle.framework/Sparkle', 'bin/sign_update', 'bin/generate_keys', 'bin/generate_appcast']:
            p = self.directory / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'owned fixture')
        self.record()

    def record(self):
        receipt = {**self.lock, 'files': sparkle.inventory(self.directory)}
        (self.directory / 'preparation-receipt.json').write_text(json.dumps(receipt))

    def verify(self):
        return sparkle.verify_prepared(self.root, self.directory)

    def test_exact_prepared_files_are_accepted(self):
        self.assertEqual(self.verify()['version'], '2.10.0')

    def test_tampered_missing_or_extra_payload_is_rejected(self):
        binary = self.directory / 'bin/sign_update'
        binary.write_bytes(b'changed')
        with self.assertRaises(RuntimeError): self.verify()
        binary.unlink()
        with self.assertRaises(RuntimeError): self.verify()
        binary.write_bytes(b'owned fixture')
        (self.directory / 'unexpected').write_text('extra')
        with self.assertRaises(RuntimeError): self.verify()

    def test_dependency_version_and_archive_pin_cannot_drift(self):
        for field in ['version', 'archiveSHA256']:
            lock = {**self.lock, field: 'changed'}
            (self.root / 'config/sparkle-lock.json').write_text(json.dumps(lock))
            with self.assertRaises(RuntimeError): self.verify()

    def test_external_symlinks_and_hardlinks_are_rejected(self):
        external = self.root / 'outside'
        external.write_text('outside')
        link = self.directory / 'link'
        link.symlink_to(external)
        with self.assertRaises(RuntimeError): sparkle.inventory(self.directory)
        link.unlink()
        link.hardlink_to(external)
        with self.assertRaises(RuntimeError): sparkle.inventory(self.directory)


if __name__ == '__main__':
    unittest.main()
