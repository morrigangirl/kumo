#!/usr/bin/env python3
"""Real compiled launcher fixtures: native UI, fixed arguments, no personal profile."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeLauncher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kumo-launcher-native-', dir='/private/tmp')
        cls.directory = Path(cls.temp.name).resolve()
        cls.launcher = cls.directory / 'Kumo'
        # Inject only the OS home-directory lookup. Foundation canonicalizes
        # /private/tmp to the /tmp symlink, which the real safety guard rightly
        # refuses. All production launch, argument, lease and retirement code
        # remains unchanged, and no fixture can consult the personal home.
        source = cls.directory / 'launcher.swift'
        production = (ROOT / 'native/launcher/main.swift').read_text()
        lookup = 'try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)'
        if production.count(lookup) != 1: raise AssertionError('Launcher home lookup changed; review fixture seam')
        source.write_text(production.replace(lookup, 'URL(fileURLWithPath: ProcessInfo.processInfo.environment["KUMO_TEST_HOME"]!).appendingPathComponent("Library/Application Support")'))
        result = subprocess.run(['swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'),
            str(source), '-o', str(cls.launcher), '-framework', 'AppKit'], capture_output=True, text=True, timeout=90)
        if result.returncode: raise AssertionError(result.stderr)
        source = cls.directory / 'engine.swift'
        source.write_text('import Foundation\nFileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: Array(CommandLine.arguments.dropFirst())))\n')
        cls.engine = cls.directory / 'SyntheticEngine'
        subprocess.run(['swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'), str(source), '-o', str(cls.engine)], check=True, capture_output=True, timeout=90)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix='case-', dir=self.directory); self.addCleanup(self.case.cleanup)
        self.base = Path(self.case.name); self.home = self.base / 'owned home'; self.home.mkdir(mode=0o700)
        self.app = self.base / "moved folder with spaces ' $ literal/Kumo.app"; self.contents = self.app / 'Contents'
        self.macos = self.contents / 'MacOS'; self.resources = self.contents / 'Resources'; self.macos.mkdir(parents=True); self.resources.mkdir()
        self.executable = self.macos / 'Kumo'; shutil.copyfile(self.launcher, self.executable); self.executable.chmod(0o700)
        (self.contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'app.kumo.launcher-test','CFBundleExecutable':'Kumo','CFBundlePackageType':'APPL'}))
        self.environment = {**os.environ, 'HOME':str(self.home), 'CFFIXED_USER_HOME':str(self.home), 'KUMO_TEST_HOME':str(self.home), 'KUMO_SETUP_NONINTERACTIVE':'1'}
        # Validate Foundation's disposable profile location BEFORE any normal run.
        result = self.launch('--kumo-print-config'); self.assertEqual(result.returncode, 0, result.stderr)
        self.config = json.loads(result.stdout); self.profile = Path(self.config['profile'])
        self.assertTrue(self.profile.is_relative_to(self.home), self.profile)

    def launch(self, *arguments):
        return subprocess.run([str(self.executable), *arguments], env=self.environment, capture_output=True, text=True, timeout=15)

    def prepare_engine(self):
        shutil.copyfile(self.engine, self.macos / 'Chromium'); (self.macos / 'Chromium').chmod(0o700)
        (self.resources / 'kumo-update-lock').write_bytes(b'Kumo update coordination v1\n')
        helper = self.contents / 'Helpers/KumoUpdater.app/Contents/MacOS/KumoUpdater'; helper.parent.mkdir(parents=True)
        helper.write_text('#!/bin/sh\nexit 99\n'); helper.chmod(0o700)
        (self.resources / 'kumo-update-config.json').write_text('{"enabled":false}')

    def test_print_config_advertises_native_settings_without_loading_any_product_extension(self):
        self.assertFalse(self.config['productExtensionLoaded'])
        self.assertEqual(self.config['nativeSettings'], 'chrome://settings/kumo')
        self.assertNotIn('extension', self.config); self.assertNotIn('bundledExtension', self.config)
        self.assertFalse(self.profile.exists())
        flags = ' '.join(self.config['flags'])
        self.assertNotIn('--load-extension', flags); self.assertNotIn('--disable-extensions', flags)
        self.assertNotIn('ExtensionRuntime', flags)

    def test_old_product_setup_commands_are_rejected_without_running_helpers_or_creating_profile(self):
        for option in ['--kumo-connect-codex-desktop','--kumo-connect-claude-desktop','--kumo-scanner-setup','--kumo-scanner-update','--kumo-unknown']:
            with self.subTest(option=option):
                result = self.launch(option); self.assertEqual(result.returncode,1); self.assertEqual(result.stdout,''); self.assertIn('Settings',result.stderr); self.assertFalse(self.profile.exists())

    def test_only_web_and_file_urls_reach_the_engine_after_fixed_security_flags(self):
        self.prepare_engine(); addresses = ['https://example.invalid/a?q=value','http://localhost:1234/','file:///private/tmp/owned.txt']
        result = self.launch(*addresses); self.assertEqual(result.returncode,0,result.stderr)
        arguments = json.loads(result.stdout); self.assertEqual(arguments[-3:], addresses)
        self.assertEqual(arguments[:len(self.config['flags'])], self.config['flags'])
        self.assertEqual(sum(x.startswith('--user-data-dir=') for x in arguments),1)
        self.assertFalse((self.profile / 'ExtensionRuntime').exists())

    def test_external_flags_other_schemes_and_mixed_update_requests_fail_before_engine(self):
        self.prepare_engine()
        for option in ['--no-sandbox','--disable-web-security','--remote-debugging-port=9222','--user-data-dir=/tmp/other','javascript:alert(1)','data:text/html,hello','chrome://settings','not-a-url']:
            with self.subTest(option=option):
                result=self.launch(option); self.assertEqual(result.returncode,1,result.stdout); self.assertEqual(result.stdout,'')
        result=self.launch('--kumo-check-for-updates','https://example.invalid');self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,'')

    def test_launch_preserves_custom_plugin_hosts_and_existing_profile_preferences(self):
        self.prepare_engine(); hosts=self.profile/'NativeMessagingHosts'; hosts.mkdir(parents=True,mode=0o700)
        custom=hosts/'com.owner.icloud.json';custom.write_bytes(b'OWNER CUSTOM PASSWORD PLUGIN')
        storage=self.profile/'Default/Local Extension Settings/custom-plugin';storage.mkdir(parents=True);(storage/'data').write_bytes(b'PRESERVE PLUGIN DATA')
        prefs=self.profile/'Default/Preferences';prefs.write_bytes(b'{"owner":"keep existing"}')
        for name in ['com.kumo.agent_bridge.json','com.kumo.phishing.json','com.kumo.malware.json']:(hosts/name).write_bytes(b'legacy')
        result=self.launch('https://example.invalid/');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(custom.read_bytes(),b'OWNER CUSTOM PASSWORD PLUGIN');self.assertEqual((storage/'data').read_bytes(),b'PRESERVE PLUGIN DATA');self.assertEqual(prefs.read_bytes(),b'{"owner":"keep existing"}')
        self.assertEqual({p.name for p in hosts.iterdir()},{custom.name})


if __name__ == '__main__': unittest.main(verbosity=2)
