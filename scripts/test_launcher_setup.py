#!/usr/bin/env python3
"""Exercise real native setup dispatch after moving a synthetic app bundle."""
import importlib.util
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kumo_package_setup', ROOT / 'scripts/package.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PortableLauncher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kumo-launcher-setup-')
        cls.directory = Path(cls.temporary.name)
        cls.initial = cls.directory / 'original.app'
        contents = cls.initial / 'Contents'
        (contents / 'MacOS').mkdir(parents=True)
        (contents / 'Resources').mkdir()
        (contents / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'app.kumo.launcher-test', 'CFBundleExecutable': 'Kumo',
            'CFBundlePackageType': 'APPL', 'CFBundleName': 'KumoLauncherTest'}))
        subprocess.run(['swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'),
                        str(ROOT / 'native/launcher/main.swift'), '-o', str(contents / 'MacOS/Kumo'),
                        '-framework', 'AppKit'], check=True, capture_output=True)
        for relative, label in [('Resources/setup-agent', 'agent'), ('MacOS/KumoMalwareSetup', 'scanner')]:
            helper = contents / relative
            helper.write_text('#!/bin/sh\nprintf "' + label + '\\n"\nif [ "$#" -gt 0 ]; then printf "%s\\n" "$@"; fi\nexit "${KUMO_TEST_HELPER_EXIT:-0}"\n')
            helper.chmod(0o700)
        cls.app = cls.directory / "moved folder with spaces ' $ literal" / 'Kumo.app'
        cls.app.parent.mkdir()
        shutil.move(cls.initial, cls.app)
        cls.executable = cls.app / 'Contents/MacOS/Kumo'

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def launch(self, *arguments, **extra_env):
        return subprocess.run([str(self.executable), *arguments], capture_output=True, text=True,
                              timeout=15, env={**os.environ, 'KUMO_SETUP_NONINTERACTIVE': '1', **extra_env})

    def test_packaged_commands_dispatch_correct_helper_after_move(self):
        expected = {
            'codexSetupCommand': ['agent', '--provider', 'codex-desktop'],
            'claudeSetupCommand': ['agent', '--provider', 'claude-desktop'],
            'downloadScannerSetupCommand': ['scanner'],
            'downloadScannerUpdateCommand': ['scanner', '--update'],
        }
        for key, command in PACKAGE.portable_setup_commands().items():
            tokens = shlex.split(command)
            self.assertEqual(tokens[:-1], ['open', '-n', '-b', 'app.kumo.browser', '--args'])
            self.assertNotIn(str(ROOT), command)
            with self.subTest(key=key):
                result = self.launch(tokens[-1])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), expected[key])

    def test_setup_rejects_extra_arguments_without_invoking_helper(self):
        result = self.launch('--kumo-connect-codex-desktop', '--disable-web-security')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('one Kumo setup action', result.stderr)

    def test_helper_failure_is_reported_without_starting_browser(self):
        result = self.launch('--kumo-connect-claude-desktop', KUMO_TEST_HELPER_EXIT='7')
        self.assertEqual(result.returncode, 1)
        self.assertIn('agent', result.stderr)


class PrivateExtensionRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kumo-extension-runtime-', dir='/private/tmp')
        cls.directory = Path(cls.temporary.name).resolve()
        helper = cls.directory / 'runtime-test.swift'
        # Exercise the exact production implementation without executing run(),
        # obtaining a real home directory, or touching a person's browser data.
        native = (ROOT / 'native/launcher/main.swift').read_text()
        functions = native.split('// Fixed setup actions run relative to this app.', 1)[0]
        helper.write_text(functions + '''
do {
    let args = CommandLine.arguments
    let source = URL(fileURLWithPath: args[2], isDirectory: true)
    let profile = URL(fileURLWithPath: args[3], isDirectory: true)
    let snapshot = try extensionSnapshot(source)
    let result = args[1] == "plan" ? extensionRuntimeURL(profile: profile, snapshot: snapshot) : try prepareExtensionRuntime(source: source, profile: profile, snapshot: snapshot)
    print(result.path)
} catch { fputs("runtime-test: \\(error.localizedDescription)\\n", stderr); exit(1) }
''')
        cls.executable = cls.directory / 'runtime-test'
        subprocess.run(['swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'), str(helper),
                        '-o', str(cls.executable), '-framework', 'AppKit'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.directory, prefix='case-')
        self.addCleanup(self.case.cleanup)
        self.base = Path(self.case.name)
        self.source = self.base / "sealed source ' $ with spaces"
        self.source.mkdir(mode=0o700)
        (self.source / 'assets').mkdir()
        (self.source / 'malware').mkdir()
        (self.source / 'manifest.json').write_text('{"manifest_version":3,"name":"Synthetic runtime fixture","version":"1"}')
        (self.source / 'background.js').write_text('// synthetic browser-owned code\n')
        (self.source / 'assets/icon.bin').write_bytes(b'\x00\x01\xfffixture')
        (self.source / 'malware/rules.json').write_text('[{"id":1,"priority":1}]')
        self.profile = self.base / 'owned disposable profile'

    def invoke(self, mode='prepare', source=None, profile=None):
        return subprocess.run([str(self.executable), mode, str(source or self.source), str(profile or self.profile)],
                              capture_output=True, text=True, timeout=15)

    def prepared(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(result.stdout.strip())

    def test_plan_hashes_only_sealed_source_without_reading_or_creating_profile(self):
        result = self.invoke('plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.profile.exists())
        target = Path(result.stdout.strip())
        self.assertEqual(target.parent, self.profile / 'ExtensionRuntime')
        self.assertRegex(target.name, r'^[0-9a-f]{64}$')

    def test_atomic_private_copy_preserves_every_asset_and_reuses_without_rewriting(self):
        source_before = {str(p.relative_to(self.source)): p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        target = self.prepared()
        self.assertEqual({str(p.relative_to(target)): p.read_bytes() for p in target.rglob('*') if p.is_file()}, source_before)
        for path in [self.profile, target.parent, *target.rglob('*'), target]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        before = (target / 'background.js').stat().st_mtime_ns
        self.assertEqual(self.prepared(), target)
        self.assertEqual((target / 'background.js').stat().st_mtime_ns, before)
        self.assertEqual({str(p.relative_to(self.source)): p.read_bytes() for p in self.source.rglob('*') if p.is_file()}, source_before)
        self.assertFalse(any(p.name.startswith('.stage-') for p in target.parent.iterdir()))

    def test_chromium_generated_index_is_allowed_only_in_private_runtime(self):
        target = self.prepared()
        cache = target / '_metadata/generated_indexed_rulesets'
        cache.mkdir(parents=True, mode=0o700)
        (target / '_metadata').chmod(0o700)
        indexed = cache / '_ruleset1'; indexed.write_bytes(b'synthetic compiled DNR index'); indexed.chmod(0o600)
        self.assertEqual(self.prepared(), target)
        self.assertFalse((self.source / '_metadata').exists())
        extra = target / '_metadata/unexpected.json'; extra.write_text('{}'); extra.chmod(0o600)
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertIn('Unexpected', result.stderr)

    def test_default_umask_cache_permissions_are_accepted_below_private_version_root(self):
        target = self.prepared(); cache = target / '_metadata/generated_indexed_rulesets'
        cache.mkdir(parents=True); (target / '_metadata').chmod(0o755); cache.chmod(0o755)
        indexed = cache / '_ruleset1'; indexed.write_bytes(b'synthetic index'); indexed.chmod(0o644)
        self.assertEqual(self.prepared(), target)
        indexed.chmod(0o666)
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertIn('writable', result.stderr)

    def test_code_mutation_or_missing_asset_is_rejected_and_not_silently_repaired(self):
        target = self.prepared(); changed = target / 'background.js'; changed.write_text('modified code')
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertIn('modified', result.stderr)
        self.assertEqual(changed.read_text(), 'modified code')
        changed.write_bytes((self.source / 'background.js').read_bytes())
        (target / 'assets/icon.bin').unlink()
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertIn('incomplete', result.stderr)

    def test_changed_source_uses_new_version_without_modifying_running_old_version(self):
        old = self.prepared(); original = (old / 'background.js').read_bytes()
        (self.source / 'background.js').write_text('// new source version\n')
        new = self.prepared(); self.assertNotEqual(new, old)
        self.assertEqual((old / 'background.js').read_bytes(), original)
        self.assertEqual((new / 'background.js').read_bytes(), (self.source / 'background.js').read_bytes())
        (self.source / 'background.js').rename(self.source / 'renamed.js')
        self.assertNotEqual(self.prepared(), new)

    def test_source_symlink_rejected_before_any_profile_write(self):
        (self.source / 'assets/link').symlink_to(self.source / 'background.js')
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertFalse(self.profile.exists())
        self.assertIn('symlink', result.stderr)

    def test_symlink_profile_parent_and_existing_destination_are_rejected(self):
        external = self.base / 'external'; external.mkdir(mode=0o700)
        linked = self.base / 'linked'; linked.symlink_to(external, target_is_directory=True)
        result = self.invoke(profile=linked / 'profile'); self.assertEqual(result.returncode, 1)
        self.assertEqual(list(external.iterdir()), [])
        planned = self.invoke('plan'); target = Path(planned.stdout.strip())
        target.parent.mkdir(parents=True, mode=0o700); self.profile.chmod(0o700)
        target.symlink_to(external, target_is_directory=True)
        result = self.invoke(); self.assertEqual(result.returncode, 1); self.assertEqual(list(external.iterdir()), [])

    def test_cache_symlinks_and_hardlinked_code_are_rejected(self):
        target = self.prepared()
        cache = target / '_metadata/generated_indexed_rulesets'; cache.mkdir(parents=True, mode=0o700); (target / '_metadata').chmod(0o700)
        link = cache / '_ruleset1'; link.symlink_to(self.source / 'background.js')
        result = self.invoke(); self.assertEqual(result.returncode, 1)
        link.unlink()
        (target / 'background.js').unlink(); os.link(self.source / 'background.js', target / 'background.js')
        result = self.invoke(); self.assertEqual(result.returncode, 1)

    def test_concurrent_preparation_publishes_one_complete_version(self):
        children = [subprocess.Popen([str(self.executable), 'prepare', str(self.source), str(self.profile)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
        outputs = [child.communicate(timeout=15) for child in children]
        targets = []
        for child, (stdout, stderr) in zip(children, outputs):
            self.assertEqual(child.returncode, 0, stderr); targets.append(stdout.strip())
        self.assertEqual(len(set(targets)), 1)
        target = Path(targets[0]); self.assertEqual(self.prepared(), target)
        self.assertEqual([p.name for p in target.parent.iterdir()], [target.name])


if __name__ == '__main__':
    unittest.main()
