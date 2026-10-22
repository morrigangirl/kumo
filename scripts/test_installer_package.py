#!/usr/bin/env python3
"""Fail-closed tests for the self-contained macOS setup payload.

All payloads and trust responses are synthetic. No installer, administrator
prompt, real scanner, launch agent, or user profile is invoked by this suite.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kumo_build_installer', ROOT / 'scripts/build-installer.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALLER
SPEC.loader.exec_module(INSTALLER)


class PayloadFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kumo-installer-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.lock = json.loads((ROOT / 'config/clamav-lock.json').read_text())


class LockedInstallPolicy(PayloadFixture):
    def test_repository_lock_is_accepted(self):
        value = INSTALLER.load_lock(ROOT / 'config/clamav-lock.json')
        self.assertEqual(value['installPrefix'], '/usr/local/clamav')
        self.assertEqual(value['version'], '1.5.4')

    def test_wrong_prefix_identity_and_unbounded_database_age_are_rejected(self):
        path = self.directory / 'clamav-lock.json'
        for field, value in [('installPrefix', '/tmp/clamav'), ('installerTeamID', 'OTHERTEAM1'),
                             ('codeTeamID', 'OTHERTEAM1'), ('databaseMaxAgeHours', 73),
                             ('schemaVersion', 2), ('files', [])]:
            with self.subTest(field=field):
                modified = {**self.lock, field: value}
                path.write_text(json.dumps(modified))
                with self.assertRaises(RuntimeError):
                    INSTALLER.load_lock(path)


class PinnedVendorTrust(PayloadFixture):
    def setUp(self):
        super().setUp()
        self.package = self.directory / 'ClamAV package with spaces.pkg'
        self.package.write_bytes(b'Synthetic vendor installer: never executable')
        self.lock['packageBytes'] = self.package.stat().st_size
        self.lock['packageSHA256'] = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.trusted = (
            'Package "clamav.pkg":\n'
            '   Status: signed by a developer certificate issued by Apple for distribution\n'
            '   Notarization: trusted by the Apple notary service\n'
            '    1. Developer ID Installer: Cisco (DE8Y96K9QP)\n'
            '       SHA256 Fingerprint:\n           ' +
            ' '.join(self.lock['installerLeafSHA256'][i:i + 2] for i in range(0, 64, 2)) + '\n'
        )

    def verify(self, status=None):
        with patch.object(INSTALLER, 'run', return_value=self.trusted if status is None else status) as run:
            result = INSTALLER.validate_vendor(self.package, self.lock)
        return result, run

    def test_exact_hash_size_and_trusted_cisco_leaf_are_accepted(self):
        _, run = self.verify()
        self.assertTrue(any('pkgutil' in str(call) and '--check-signature' in str(call)
                            and str(self.package) in str(call) for call in run.call_args_list))

    def test_pkgutil_exit_zero_with_invalid_signature_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify('Package "clamav.pkg":\n   Status: invalid signature\n')

    def test_matching_name_and_leaf_without_trusted_status_are_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(self.trusted.replace(
                'Status: signed by a developer certificate issued by Apple for distribution',
                'Status: invalid signature'))

    def test_different_installer_team_or_leaf_is_rejected(self):
        for old, new in [('Cisco (DE8Y96K9QP)', 'Cisco (OTHERTEAM1)'),
                         (' '.join(self.lock['installerLeafSHA256'][i:i + 2] for i in range(0, 64, 2)),
                          '00 ' * 32)]:
            with self.subTest(value=old), self.assertRaises(RuntimeError):
                self.verify(self.trusted.replace(old, new))

    def test_tampered_same_size_package_and_truncated_package_are_rejected_before_trust_probe(self):
        original = self.package.read_bytes()
        for data in [bytes([original[0] ^ 1]) + original[1:], original[:-1]]:
            self.package.write_bytes(data)
            with self.subTest(length=len(data)), patch.object(INSTALLER, 'run') as run:
                with self.assertRaises(RuntimeError):
                    INSTALLER.validate_vendor(self.package, self.lock)
                run.assert_not_called()

    def test_symlinked_vendor_package_is_rejected(self):
        link = self.directory / 'symlink.pkg'
        link.symlink_to(self.package)
        with patch.object(INSTALLER, 'run', return_value=self.trusted), self.assertRaises(RuntimeError):
            INSTALLER.validate_vendor(link, self.lock)


class CurrentSignedDefinitions(PayloadFixture):
    def setUp(self):
        super().setUp()
        self.database = self.directory / 'definitions'
        self.database.mkdir()
        self.runtime = self.directory / 'vendor runtime'
        (self.runtime / 'bin').mkdir(parents=True)
        (self.runtime / 'etc/certs').mkdir(parents=True)
        (self.runtime / 'bin/sigtool').write_text('synthetic, never executed')
        (self.runtime / 'etc/certs/clamav.crt').write_text('synthetic certificate')
        for name, version in [('main', 63), ('daily', 28160), ('bytecode', 339)]:
            self.definition(name, version=version)
            (self.database / f'{name}-{version}.cvd.sign').write_bytes(b'synthetic detached signature')

    def definition(self, name, *, version=28160, epoch=None):
        epoch = int(time.time()) if epoch is None else epoch
        header = f'ClamAV-VDB:21 Oct 2026 06-26 +0000:{version}:12345:90:unused:signature:builder:{epoch}:1'
        (self.database / (name + '.cvd')).write_bytes(header.encode().ljust(512, b' ') + b'owned fixture')

    def collect(self):
        with patch.object(INSTALLER, 'run', return_value='Verification succeeded') as run:
            result = INSTALLER.collect_definitions(self.database, self.runtime, self.lock)
        return result, run

    def test_all_three_databases_use_vendor_signature_verification(self):
        _, run = self.collect()
        calls = [str(call) for call in run.call_args_list]
        for name in ['main', 'daily', 'bytecode']:
            self.assertTrue(any('sigtool' in call and '--verify' in call and name + '.cvd' in call
                                for call in calls), (name, calls))

    def test_missing_or_truncated_database_cannot_produce_a_setup_payload(self):
        daily = self.database / 'daily.cvd'
        for data in [None, b'ClamAV-VDB:truncated']:
            with self.subTest(data=data):
                if data is None:
                    daily.unlink(missing_ok=True)
                else:
                    daily.write_bytes(data)
                with self.assertRaises(RuntimeError):
                    self.collect()

    def test_stale_future_and_malformed_daily_headers_are_rejected(self):
        for epoch in [time.time() - 73 * 3600, time.time() + 3600, 0, 'not-a-number']:
            with self.subTest(epoch=epoch):
                self.definition('daily', epoch=epoch)
                with self.assertRaises(RuntimeError):
                    self.collect()
        (self.database / 'daily.cvd').write_bytes(b'not a CVD'.ljust(512, b' '))
        with self.assertRaises(RuntimeError):
            self.collect()

    def test_verification_failure_cannot_be_replaced_by_a_fresh_header(self):
        with patch.object(INSTALLER, 'run', side_effect=RuntimeError('sigtool rejected signature')):
            with self.assertRaises(RuntimeError):
                INSTALLER.collect_definitions(self.database, self.runtime, self.lock)

    def test_symlinked_database_or_signature_is_rejected(self):
        for name in ['daily.cvd', 'daily-28160.cvd.sign']:
            with self.subTest(name=name):
                path = self.database / name
                contents = path.read_bytes()
                outside = self.directory / ('outside-' + name)
                outside.write_bytes(contents)
                path.unlink()
                path.symlink_to(outside)
                with self.assertRaises(RuntimeError):
                    self.collect()
                path.unlink()
                path.write_bytes(contents)


class CompleteBrowserPayload(PayloadFixture):
    def setUp(self):
        super().setUp()
        self.app = self.directory / 'Kumo.app'
        self.info = {'CFBundleIdentifier': 'app.kumo.browser', 'CFBundleExecutable': 'Kumo',
                     'CFBundleShortVersionString': '0.1.2', 'CFBundleVersion': '202610210003'}
        self.build = {'sourceCompiledLocally': True, 'sourceBuildReceipt': {'schema': 1},
                      'malwareProtection': {'downloadAntivirusIncluded': True},
                      'phishingProtection': {'included': True}}
        for name in ['Contents/MacOS/Chromium', 'Contents/MacOS/KumoMalwareSetup',
                     'Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost',
                     'Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost',
                     'Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/vocab.txt',
                     'Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/NOTICE.md',
                     'Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/model-info.json',
                     'Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/PhishLang.mlmodelc/weights/weight.bin']:
            file = self.app / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b'owned browser payload fixture')
        self.write_metadata()

    def write_metadata(self):
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))
        file = self.app / 'Contents/Resources/KumoExtension/build-info.json'
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(self.build))

    @staticmethod
    def tool_result(*arguments, **kwargs):
        arguments = [str(argument) for argument in arguments]
        if arguments[0] == '/usr/bin/lipo':
            return 'arm64\n'
        if arguments[0] == '/usr/bin/codesign' and '-d' in arguments:
            return ('Identifier=app.kumo.browser\nTeamIdentifier=PV65ZWXCWX\n'
                    'Authority=Developer ID Application: Fixture\nCDHash=' + 'a' * 40 + '\n')
        return ''

    def validate(self, tool_result=None):
        with patch.object(INSTALLER, 'run', side_effect=tool_result or self.tool_result) as run:
            result = INSTALLER.validate_app(self.app)
        return result, run

    def test_app_identity_scanner_phishlang_architecture_signature_and_notary_are_checked(self):
        result, run = self.validate()
        self.assertEqual(result['appBundleId'], 'app.kumo.browser')
        self.assertEqual(result['architecture'], 'arm64')
        self.assertIs(result['phishLangIncluded'], True)
        calls = [str(call) for call in run.call_args_list]
        for marker in ['--verify', '--all-architectures', 'stapler', 'spctl']:
            self.assertTrue(any(marker in call for call in calls), marker)

    def test_other_app_bundle_or_missing_protection_is_rejected_before_external_tools(self):
        for target, key, value in [(self.info, 'CFBundleIdentifier', 'org.other.browser'),
                                   (self.build, 'sourceCompiledLocally', False),
                                   (self.build, 'sourceBuildReceipt', {}),
                                   (self.build['malwareProtection'], 'downloadAntivirusIncluded', False),
                                   (self.build['phishingProtection'], 'included', False)]:
            original = target[key]
            target[key] = value
            self.write_metadata()
            with self.subTest(key=key), patch.object(INSTALLER, 'run') as run:
                with self.assertRaises(RuntimeError):
                    INSTALLER.validate_app(self.app)
                run.assert_not_called()
            target[key] = original
        self.write_metadata()

    def test_flags_cannot_substitute_for_actual_model_or_scanner(self):
        for relative in ['Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/PhishLang.mlmodelc/weights/weight.bin',
                         'Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost']:
            path = self.app / relative
            contents = path.read_bytes()
            path.unlink()
            with self.subTest(path=relative), self.assertRaises(RuntimeError):
                self.validate()
            path.write_bytes(contents)

    def test_security_metadata_requires_real_booleans_and_receipt_object(self):
        for target, key, value in [(self.build, 'sourceCompiledLocally', 'true'),
                                   (self.build, 'sourceBuildReceipt', 'present'),
                                   (self.build['malwareProtection'], 'downloadAntivirusIncluded', 'true'),
                                   (self.build['phishingProtection'], 'included', 1)]:
            original = target[key]
            target[key] = value
            self.write_metadata()
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate()
            target[key] = original
        self.write_metadata()

    def test_wrong_team_identifier_or_intel_only_engine_is_rejected(self):
        for old, new in [('PV65ZWXCWX', 'OTHERTEAM1'), ('app.kumo.browser', 'org.other.browser'),
                         ('arm64', 'x86_64')]:
            def changed(*arguments, **kwargs):
                return self.tool_result(*arguments, **kwargs).replace(old, new)
            with self.subTest(replacement=(old, new)), self.assertRaises(RuntimeError):
                self.validate(changed)

    def test_any_code_signature_or_notarization_tool_failure_is_fatal(self):
        for marker in ['--verify', 'stapler', 'spctl']:
            def rejected(*arguments, **kwargs):
                if any(marker == str(argument) or marker == Path(str(argument)).name for argument in arguments):
                    raise RuntimeError('synthetic trust rejection')
                return self.tool_result(*arguments, **kwargs)
            with self.subTest(tool=marker), self.assertRaises(RuntimeError):
                self.validate(rejected)


class PinnedDefinitionVerifier(PayloadFixture):
    def setUp(self):
        super().setUp()
        self.runtime = self.directory / 'ClamAV runtime'
        self.runtime.mkdir()
        self.lock['files'] = []
        for name in ['bin/clamscan', 'bin/freshclam', 'bin/sigtool', 'bin/clamav-config',
                     'lib/libclamav.1.dylib', 'etc/certs/clamav.crt']:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('owned runtime fixture ' + name).encode())
            self.lock['files'].append({'path': name, 'bytes': path.stat().st_size,
                                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        (self.runtime / 'lib/libclamav.dylib').symlink_to('libclamav.1.dylib')
        self.lock['files'].append({'path': 'lib/libclamav.dylib', 'symlink': 'libclamav.1.dylib'})

    def test_all_launchable_executables_and_libraries_require_cisco_signatures(self):
        with patch.object(INSTALLER, 'run', return_value='') as run:
            INSTALLER.validate_runtime(self.runtime, self.lock)
        calls = [call.args for call in run.call_args_list]
        self.assertEqual(len(calls), 4)
        for arguments in calls:
            self.assertIn('--all-architectures', arguments)
            self.assertIn('--strict', arguments)
            self.assertTrue(any('DE8Y96K9QP' in str(argument) for argument in arguments))
        self.assertFalse(any('clamav-config' in str(call) for call in calls))

    def test_changed_runtime_bytes_are_rejected_before_their_execution(self):
        target = self.runtime / 'bin/sigtool'
        target.write_bytes(bytes(target.stat().st_size))
        with patch.object(INSTALLER, 'run', return_value='') as run:
            with self.assertRaises(RuntimeError):
                INSTALLER.validate_runtime(self.runtime, self.lock)
        self.assertFalse(any(str(target) == str(call.args[0]) for call in run.call_args_list))

    def test_wrong_alias_and_symlinked_regular_runtime_file_are_rejected(self):
        for name in ['lib/libclamav.dylib', 'bin/sigtool']:
            path = self.runtime / name
            path.unlink()
            path.symlink_to('../wrong-target')
            with self.subTest(name=name), patch.object(INSTALLER, 'run', return_value=''):
                with self.assertRaises(RuntimeError):
                    INSTALLER.validate_runtime(self.runtime, self.lock)
            if name == 'lib/libclamav.dylib':
                path.unlink()
                path.symlink_to('libclamav.1.dylib')

    def test_absolute_or_traversing_policy_path_cannot_be_used(self):
        for path in ['/tmp/sigtool', '../sigtool']:
            modified = {**self.lock, 'files': [{'path': path, 'bytes': 0, 'sha256': '0' * 64}]}
            with self.subTest(path=path), patch.object(INSTALLER, 'run') as run:
                with self.assertRaises(RuntimeError):
                    INSTALLER.validate_runtime(self.runtime, modified)
                run.assert_not_called()

    def test_signature_failure_is_fatal_even_when_every_hash_matches(self):
        with patch.object(INSTALLER, 'run', side_effect=RuntimeError('Cisco requirement rejected')):
            with self.assertRaises(RuntimeError):
                INSTALLER.validate_runtime(self.runtime, self.lock)

    def test_library_alias_pin_cannot_point_outside_its_vendor_directory(self):
        alias = self.runtime / 'lib/libclamav.dylib'
        original = self.lock['files'][-1]
        for target in ['/tmp/outside.dylib', '../outside.dylib', 'nested/alias.dylib']:
            alias.unlink()
            alias.symlink_to(target)
            modified = {**self.lock, 'files': [*self.lock['files'][:-1], {**original, 'symlink': target}]}
            with self.subTest(target=target), patch.object(INSTALLER, 'run', return_value=''):
                with self.assertRaises(RuntimeError):
                    INSTALLER.validate_runtime(self.runtime, modified)


class SealedPayloadManifest(PayloadFixture):
    def setUp(self):
        super().setUp()
        self.staged = self.directory / 'Kumo Setup.app'
        self.resources = self.staged / 'Contents/Resources'
        self.payload = self.resources / 'payload'
        self.payload.mkdir(parents=True)
        self.metadata = {'appBundleId': 'app.kumo.browser', 'appVersion': '0.1.2',
                         'appBuild': '202610210003', 'appCDHash': 'a' * 40,
                         'phishLangIncluded': True, 'architecture': 'arm64'}
        for name in ['Kumo.app/Contents/Info.plist', 'Kumo.app/Contents/MacOS/Kumo',
                     'clamav.pkg', 'clamav-source.tar.gz']:
            path = self.payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('owned ' + name).encode())
        definitions = self.payload / 'definitions'
        definitions.mkdir()
        for name, version in [('main', 63), ('daily', 28160), ('bytecode', 339)]:
            header = f'ClamAV-VDB:build:{version}:12345:90:unused:signature:builder:{int(time.time())}:1'
            (definitions / (name + '.cvd')).write_bytes(header.encode().ljust(512, b' '))
            (definitions / f'{name}-{version}.cvd.sign').write_bytes(b'synthetic signature')

    def manifest(self):
        return INSTALLER.write_manifest(self.staged, self.metadata, self.lock)

    def test_every_real_file_is_bound_by_hash_and_source_and_signature_sidecars_are_present(self):
        result = self.manifest()
        expected = {str(path.relative_to(self.resources)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in self.payload.rglob('*') if path.is_file()}
        self.assertEqual(result['files'], expected)
        self.assertIn('payload/clamav-source.tar.gz', result['files'])
        self.assertIn('payload/definitions/daily-28160.cvd.sign', result['files'])
        self.assertEqual(json.loads((self.resources / 'installer-manifest.json').read_text()), result)

    def test_missing_definitions_source_archive_or_required_signature_cannot_be_sealed(self):
        for name in ['definitions/daily.cvd', 'definitions/daily-28160.cvd.sign', 'clamav-source.tar.gz']:
            path = self.payload / name
            data = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.manifest()
            self.assertFalse((self.resources / 'installer-manifest.json').exists())
            path.write_bytes(data)

    def test_normal_framework_style_relative_app_symlink_is_accepted(self):
        link = self.payload / 'Kumo.app/Contents/current'
        link.symlink_to('MacOS')
        self.manifest()

    def test_escaping_absolute_broken_and_nonapp_symlinks_are_rejected(self):
        outside = self.directory / 'outside'
        outside.write_bytes(b'outside data')
        for relative, target in [('Kumo.app/Contents/escape', '../../clamav.pkg'),
                                 ('Kumo.app/Contents/absolute', str(outside)),
                                 ('Kumo.app/Contents/broken', 'missing'),
                                 ('definitions/alias', 'daily.cvd')]:
            link = self.payload / relative
            link.symlink_to(target)
            with self.subTest(link=relative), self.assertRaises(RuntimeError):
                self.manifest()
            self.assertFalse((self.resources / 'installer-manifest.json').exists())
            link.unlink()


if __name__ == '__main__':
    unittest.main()
