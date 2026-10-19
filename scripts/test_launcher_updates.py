#!/usr/bin/env python3
"""Exercise the real Swift launcher update lease and early dispatch in owned fixtures."""
import fcntl
import json
import os
from pathlib import Path
import plistlib
import select
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOCK_CONTENT = b'Kumo update coordination v1\n'


class LauncherUpdates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kumo-launcher-updates-', dir='/private/tmp')
        cls.directory = Path(cls.temporary.name).resolve()
        native = (ROOT / 'native/launcher/main.swift').read_text()
        prefix, separator, _ = native.partition('// Fixed setup actions run relative to this app.')
        if not separator:
            raise AssertionError('Production launcher function boundary is missing')
        source = cls.directory / 'lease-test.swift'
        source.write_text(prefix + r'''
do {
    let args = CommandLine.arguments
    let contents = URL(fileURLWithPath: args[2], isDirectory: true)
    if args[1] == "background" {
        try launchUpdater(contents: contents, manual: false)
        FileHandle.standardOutput.write(Data("background-returned\n".utf8))
    } else {
        let descriptor = try acquireBrowserUpdateLock(contents: contents)
        if args[1] == "exec" {
            FileHandle.standardOutput.write(Data("locked\n".utf8))
            let command: [String] = ["/bin/sleep", "30"]
            let arguments = command.map { strdup($0) } + [nil]
            _ = arguments.withUnsafeBufferPointer { execv("/bin/sleep", $0.baseAddress!) }
            close(descriptor)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        FileHandle.standardOutput.write(Data("locked\n".utf8))
        close(descriptor)
    }
} catch {
    fputs("lease-test: \(error.localizedDescription)\n", stderr)
    exit(1)
}
''')
        cls.helper = cls.directory / 'lease-test'
        cls.launcher = cls.directory / 'launcher'
        full_source = cls.directory / 'main.swift'
        full_source.write_text(native)
        for swift_source, executable in [(source, cls.helper), (full_source, cls.launcher)]:
            result = subprocess.run([
                'swiftc', '-O', '-module-cache-path', str(cls.directory / 'modules'),
                str(swift_source), '-o', str(executable), '-framework', 'AppKit',
            ], capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temporary_case = tempfile.TemporaryDirectory(dir=self.directory, prefix='case-')
        self.addCleanup(self.temporary_case.cleanup)
        self.base = Path(self.temporary_case.name)
        self.app = self.base / "moved folder ' $ with spaces" / 'Kumo.app'
        self.contents = self.app / 'Contents'
        self.resources = self.contents / 'Resources'
        self.resources.mkdir(parents=True)
        self.lock = self.resources / 'kumo-update-lock'
        self.lock.write_bytes(LOCK_CONTENT)
        self.lock.chmod(0o644)
        self.home = self.base / 'owned home'
        self.home.mkdir(mode=0o700)
        self.environment = {
            **os.environ, 'HOME': str(self.home), 'CFFIXED_USER_HOME': str(self.home),
            'KUMO_SETUP_NONINTERACTIVE': '1',
        }

    def invoke(self, mode='probe'):
        return subprocess.run([str(self.helper), mode, str(self.contents)],
                              capture_output=True, text=True, timeout=15, env=self.environment)

    def install_launcher(self):
        macos = self.contents / 'MacOS'
        macos.mkdir()
        executable = macos / 'Kumo'
        shutil.copyfile(self.launcher, executable)
        executable.chmod(0o700)
        (self.contents / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'app.kumo.launcher-updates-test',
            'CFBundleExecutable': 'Kumo', 'CFBundlePackageType': 'APPL',
            'CFBundleName': 'KumoLauncherUpdateTest',
        }))
        return executable

    def launch(self, executable, *arguments):
        return subprocess.run([str(executable), *arguments], capture_output=True, text=True,
                              timeout=15, env=self.environment)

    def open_lock(self):
        descriptor = os.open(self.lock, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_shared_lease_survives_exec_and_releases_only_after_child_exit(self):
        child = subprocess.Popen([str(self.helper), 'exec', str(self.contents)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=self.environment)
        def stop_owned_child():
            if child.poll() is None:
                child.terminate()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        self.addCleanup(stop_owned_child)
        self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'Swift helper did not become ready')
        self.assertEqual(child.stdout.readline(), 'locked\n')
        deadline = time.monotonic() + 5
        while True:
            self.assertIsNone(child.poll(), 'Owned lease child exited before exec verification')
            command = subprocess.run(['ps', '-p', str(child.pid), '-o', 'comm='],
                                     capture_output=True, text=True, timeout=5).stdout.strip()
            if command == '/bin/sleep':
                break
            self.assertLess(time.monotonic(), deadline, f'Owned helper did not exec /bin/sleep: {command}')
            time.sleep(0.02)
        descriptor = self.open_lock()
        with self.assertRaises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        other_reader = self.open_lock()
        fcntl.flock(other_reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(other_reader, fcntl.LOCK_UN)
        child.terminate()
        child.communicate(timeout=5)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)

    def test_exclusive_updater_lease_fails_closed_without_waiting(self):
        descriptor = self.open_lock()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('installing an update', result.stderr)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.assertEqual(self.invoke().returncode, 0)

    def test_unsafe_or_tampered_coordination_files_are_rejected(self):
        fixtures = ['same-size-tamper', 'short', 'long', 'symlink', 'hardlink',
                    'world-writable', 'group-writable', 'directory', 'missing']
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                if self.lock.exists() or self.lock.is_symlink():
                    if self.lock.is_dir(): self.lock.rmdir()
                    else: self.lock.unlink()
                self.lock.write_bytes(LOCK_CONTENT)
                self.lock.chmod(0o644)
                if fixture == 'same-size-tamper': self.lock.write_bytes(b'X' + LOCK_CONTENT[1:])
                elif fixture == 'short': self.lock.write_bytes(LOCK_CONTENT[:-1])
                elif fixture == 'long': self.lock.write_bytes(LOCK_CONTENT + b'X')
                elif fixture in ['symlink', 'hardlink']:
                    target = self.base / fixture
                    target.write_bytes(LOCK_CONTENT); target.chmod(0o644)
                    self.lock.unlink()
                    if fixture == 'symlink': self.lock.symlink_to(target)
                    else: os.link(target, self.lock)
                elif fixture == 'world-writable': self.lock.chmod(0o666)
                elif fixture == 'group-writable': self.lock.chmod(0o664)
                elif fixture == 'directory': self.lock.unlink(); self.lock.mkdir()
                elif fixture == 'missing': self.lock.unlink()
                result = self.invoke()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(result.stdout, '')
                self.assertRegex(result.stderr, 'coordination file|coordination')

    def test_readonly_single_link_coordination_file_is_accepted(self):
        self.lock.chmod(0o444)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'locked\n')

    def test_disabled_background_update_returns_without_opening_missing_app(self):
        # Executable existence is checked before config. A deliberately non-app
        # fixture cannot be opened successfully if this early return regresses.
        helper = self.contents / 'Helpers/KumoUpdater.app/Contents/MacOS/KumoUpdater'
        helper.parent.mkdir(parents=True)
        helper.write_text('#!/bin/sh\nexit 99\n'); helper.chmod(0o700)
        config = self.resources / 'kumo-update-config.json'
        for value in [{'enabled': False}, {}, {'enabled': 'true'}, None]:
            with self.subTest(config=value):
                if value is None:
                    config.write_text('not valid JSON')
                else:
                    config.write_text(json.dumps(value))
                result = self.invoke('background')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'background-returned\n')
        config.unlink()
        self.assertEqual(self.invoke('background').returncode, 0)

    def test_print_config_avoids_update_lock_and_updater_dispatch(self):
        executable = self.install_launcher()
        extension = self.resources / 'KumoExtension'
        extension.mkdir()
        (extension / 'manifest.json').write_text('{"manifest_version":3,"name":"Owned fixture","version":"1"}')
        # An enabled config with no helper would fail before /usr/bin/open if
        # launchUpdater were called. An EX lease likewise makes lock use fail.
        (self.resources / 'kumo-update-config.json').write_text('{"enabled":true}')
        descriptor = self.open_lock()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*'))
        result = self.launch(executable, '--kumo-print-config')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        self.assertEqual(config['bundledExtension'], str(extension))
        self.assertTrue(Path(config['profile']).resolve().is_relative_to(self.home), config['profile'])
        self.assertFalse(Path(config['profile']).exists())
        self.assertEqual(sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*')), before)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.lock.unlink()
        result = self.launch(executable, '--kumo-print-config')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manual_update_with_extra_argument_is_rejected_before_engine_or_profile(self):
        executable = self.install_launcher()
        self.lock.unlink()
        for arguments in [('--kumo-check-for-updates', '--disable-web-security'),
                          ('https://example.invalid/', '--kumo-check-for-updates'),
                          ('--kumo-check-for-updates', '--kumo-print-config')]:
            with self.subTest(arguments=arguments):
                result = self.launch(executable, *arguments)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertIn('one Kumo setup action', result.stderr)
                self.assertEqual(list(self.home.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
