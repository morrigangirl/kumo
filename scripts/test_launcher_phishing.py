#!/usr/bin/env python3
"""Compile the production launcher host-registration code in owned fixtures."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LauncherPhishing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kumo-launcher-phishing-', dir='/private/tmp')
        cls.directory = Path(cls.temporary.name)
        native = (ROOT / 'native/launcher/main.swift').read_text()
        prefix, separator, _ = native.partition('// Fixed setup actions run relative to this app.')
        if not separator:
            raise AssertionError('Production launcher function boundary is missing')
        source = cls.directory / 'host-test.swift'
        source.write_text(prefix + r'''
do {
    let contents = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    let hosts = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    try ensureOwnedRuntimeDirectory(hosts)
    try preparePhishingNativeHost(contents: contents, profileHosts: hosts)
} catch {
    fputs("host-test: \(error.localizedDescription)\n", stderr)
    exit(1)
}
''')
        cls.helper = cls.directory / 'host-test'
        result = subprocess.run(['swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'),
                                 str(source), '-o', str(cls.helper), '-framework', 'AppKit'],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='case-', dir=self.directory)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.contents = self.base / 'moved app with spaces.app/Contents'
        self.resources = self.contents / 'Resources'
        self.extension = self.resources / 'KumoExtension'
        self.extension.mkdir(parents=True)
        self.hosts = self.base / 'owned profile/NativeMessagingHosts'
        self.hosts.mkdir(parents=True, mode=0o700)
        self.manifest = self.hosts / 'com.kumo.phishing.json'
        self.metadata = self.extension / 'build-info.json'
        self.executable = self.contents / 'Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost'
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text('#!/bin/sh\nexit 0\n')
        self.executable.chmod(0o700)
        self.template = self.resources / 'phishing-host-template.json'
        self.template.write_text(json.dumps({'name': 'com.kumo.phishing', 'type': 'stdio',
                                             'allowed_origins': ['chrome-extension://owned-fixture/']}))

    def invoke(self):
        return subprocess.run([str(self.helper), str(self.contents), str(self.hosts)],
                              capture_output=True, text=True, timeout=15)

    def test_included_model_registers_current_app_path(self):
        self.metadata.write_text(json.dumps({'phishingProtection': {'included': True}}))
        self.manifest.write_text('{"path":"/stale/app"}')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.manifest.read_text())['path'], str(self.executable))

    def test_omitted_model_retires_stale_manifest_even_with_leftover_template_and_helper(self):
        self.metadata.write_text(json.dumps({'phishingProtection': {'included': False}}))
        self.manifest.write_text('{"path":"/stale/app"}')
        other = self.hosts / 'com.kumo.malware.json'
        other.write_bytes(b'unchanged malware host')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(other.read_bytes(), b'unchanged malware host')
        self.assertEqual(self.invoke().returncode, 0)

    def test_missing_or_malformed_metadata_and_missing_helper_do_not_register(self):
        fixtures = [None, 'invalid JSON', {}, {'phishingProtection': {'included': 'true'}},
                    {'phishingProtection': {'included': 1}}, {'phishingProtection': {'included': True}}]
        for index, value in enumerate(fixtures):
            with self.subTest(metadata=value):
                if self.metadata.exists(): self.metadata.unlink()
                if isinstance(value, str): self.metadata.write_text(value)
                elif value is not None: self.metadata.write_text(json.dumps(value))
                if index == len(fixtures) - 1 and self.executable.exists(): self.executable.unlink()
                self.manifest.write_text('{"path":"/stale/app"}')
                result = self.invoke()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.manifest.exists())

    def test_stale_symlink_is_unlinked_without_touching_target(self):
        self.metadata.write_text('{"phishingProtection":{"included":false}}')
        target = self.base / 'owned target'
        target.write_bytes(b'must survive')
        self.manifest.symlink_to(target)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.manifest.is_symlink())
        self.assertEqual(target.read_bytes(), b'must survive')

    def test_retired_manifest_directory_is_rejected_without_recursive_deletion(self):
        self.metadata.write_text('{"phishingProtection":{"included":false}}')
        self.manifest.mkdir()
        child = self.manifest / 'preserve'
        child.write_bytes(b'must survive')
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn('cannot be removed safely', result.stderr)
        self.assertEqual(child.read_bytes(), b'must survive')


if __name__ == '__main__':
    unittest.main()
