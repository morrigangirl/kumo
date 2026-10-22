#!/usr/bin/env python3
"""Standard package policy/provenance tests; never run Installer or its scripts."""
from pathlib import Path
import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kumo_standard_pkg', ROOT / 'scripts/build-installer-pkg.py')
PKG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PKG)


class PackagePolicy(unittest.TestCase):
    def test_archive_name_comes_from_signed_bundle_version_and_build(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'Kumo Setup.app'; (app / 'Contents').mkdir(parents=True)
            info = app / 'Contents/Info.plist'
            info.write_bytes(plistlib.dumps({'CFBundleShortVersionString': '0.2.0', 'CFBundleVersion': '202610210004'}))
            self.assertEqual(PKG.PAYLOAD.setup_archive_name(app), 'Kumo-Setup-0.2.0-202610210004-Apple-Silicon.zip')
            info.write_bytes(plistlib.dumps({'CFBundleShortVersionString': '../escape', 'CFBundleVersion': '4'}))
            with self.assertRaises(RuntimeError): PKG.PAYLOAD.setup_archive_name(app)

    def test_component_policy_disables_relocation_for_parent_and_nested_apps(self):
        policy = [{'RootRelativeBundlePath': 'Kumo Setup.app', 'BundleIsRelocatable': True,
                   'ChildBundles': [{'RootRelativeBundlePath': 'Kumo Setup.app/Contents/Resources/payload/Kumo.app', 'BundleIsRelocatable': True}]}]
        result = PKG.configure_component_policy(policy)
        self.assertEqual(result[0]['BundlePostInstallScriptPath'], 'publish-kumo')
        self.assertEqual(result[0]['BundleInstallScriptTimeout'], 3600)
        self.assertFalse(result[0]['BundleIsRelocatable'])
        self.assertFalse(result[0]['ChildBundles'][0]['BundleIsRelocatable'])
        for value in [[], [{'RootRelativeBundlePath': '../escape'}], [{'RootRelativeBundlePath': 'Other.app'}]]:
            with self.assertRaises(RuntimeError): PKG.configure_component_policy(value)

    def test_public_verifier_rejects_unsigned_package_before_archive_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'unsigned.pkg'; package.write_bytes(b'synthetic unsigned package')
            with patch.object(PKG, 'run', return_value='Status: no signature') as command:
                with self.assertRaisesRegex(RuntimeError, 'Installer signature'):
                    PKG.verify_public_package(package, '0.2.0', '202610210004', 'a' * 40)
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[:2], ('/usr/sbin/pkgutil', '--check-signature'))
            with self.assertRaises(RuntimeError): PKG.verify_public_package(package, '0.2.0', '../build', 'a' * 40)

    def test_postinstall_has_fixed_trusted_snapshot_and_no_nested_installer(self):
        pre, post = PKG.scripts_for_build('202610220001')
        self.assertIn('[ "${3:-}" = / ]', pre)
        self.assertIn('/usr/bin/codesign --verify --deep --strict', post)
        self.assertIn('kumo-setup-XXXXXXXX', post)
        self.assertIn('--install-package-root', post)
        self.assertNotIn('/usr/sbin/installer', post)
        self.assertNotIn(' --install-root', post)
        self.assertNotIn('sudo', post)
        self.assertNotIn('$1', post)
        self.assertNotIn('$2', post)
        for value in ['../a', '1\n/bin/id', '1$(id)', '1;id', '', '0', '9' * 19]:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                PKG.scripts_for_build(value)

    def test_vendor_choices_and_refs_precede_browser_and_only_startup_disk_is_allowed(self):
        components = [{'id': identifier, 'version': '1.5.4', 'file': kind + '.pkg'} for kind, identifier in PKG.COMPONENTS]
        xml = ET.fromstring(PKG.distribution_xml(components, {'appVersion': '0.1.3'}))
        self.assertEqual([ref.attrib['id'] for ref in xml.findall('pkg-ref')], [c['id'] for c in components] + [PKG.PACKAGE_ID])
        self.assertEqual([x.attrib['choice'] for x in xml.find('choices-outline')], ['antivirus', 'browser'])
        self.assertEqual(xml.find('domains').attrib, {'enable_localSystem': 'true', 'enable_currentUserHome': 'false', 'enable_anywhere': 'false'})
        self.assertEqual(xml.find('options').attrib['hostArchitectures'], 'arm64')
        self.assertEqual([x.attrib['id'] for x in xml.findall('pkg-ref')[-1].find('must-close')], ['app.kumo.browser', 'app.kumo.browser.updater'])

    def test_metadata_uses_exactly_one_canonical_or_historical_record(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'Kumo.app'; resources = app / 'Contents/Resources'; resources.mkdir(parents=True)
            canonical = resources / 'kumo-build-info.json'; legacy = resources / 'KumoExtension/build-info.json'
            with self.assertRaises(RuntimeError): PKG.PAYLOAD.load_build_metadata(app)
            canonical.write_text('{"native":true}')
            self.assertEqual(PKG.PAYLOAD.load_build_metadata(app), {'native': True})
            legacy.parent.mkdir(); legacy.write_text(canonical.read_text())
            with self.assertRaisesRegex(RuntimeError, 'unambiguous'): PKG.PAYLOAD.load_build_metadata(app)
            canonical.unlink(); self.assertEqual(PKG.PAYLOAD.load_build_metadata(app), {'native': True})
            legacy.unlink(); legacy.symlink_to(resources / 'elsewhere.json')
            with self.assertRaises(RuntimeError): PKG.PAYLOAD.load_build_metadata(app)

    def test_reviewable_unsigned_package_does_not_claim_distribution_readiness(self):
        source = (ROOT / 'scripts/build-installer-pkg.py').read_text()
        self.assertIn("'signed': bool(args.identity), 'notarized': False", source)
        self.assertIn("'readyForPublicDistribution': False", source)
        self.assertIn("Developer ID Installer:", source)
        self.assertNotIn("--type', 'execute', output", source)


class SetupSafetyPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.setup = Path(self.temp.name) / 'Kumo Setup.app'
        (self.setup / 'Contents/MacOS').mkdir(parents=True)
        (self.setup / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'app.kumo.setup', 'CFBundleExecutable': 'KumoSetup',
            'CFBundleVersion': '202610210004', 'CFBundleShortVersionString': '0.2.0'}))
        self.executable = self.setup / 'Contents/MacOS/KumoSetup'
        self.executable.write_bytes(b'synthetic helper; never executed')
        self.policy = {'ok': True, 'packageMode': 1, 'nestedInstaller': False,
                       'rollbackUntilUserReady': True, 'standaloneInstaller': False,
                       'definitionRollbackUntilUserReady': True}
        self.calls = []

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('/usr/bin/codesign', '--verify'): return ''
        if args[:2] == ('/usr/bin/codesign', '--display'):
            return 'Authority=Developer ID Application: Carson Press LLC (PV65ZWXCWX)\nCDHash=' + 'b' * 40
        if args == (self.executable, '--package-policy'): return json.dumps(self.policy)
        if args == (self.executable, '--verify-payloads'):
            return json.dumps({'ok': True, 'status': 'payloads-verified'})
        raise AssertionError('Unexpected policy-verification command: ' + repr(args))

    def verify(self):
        metadata = {'appVersion': '0.2.0', 'appBuild': '202610210004', 'appCDHash': 'a' * 40}
        with patch.object(PKG, 'run', side_effect=self.command), patch.object(PKG.PAYLOAD, 'validate_app', return_value=metadata), patch.object(PKG, 'strict_native_metadata'):
            return PKG.validate_setup(self.setup)

    def test_current_safety_policy_passes_after_signature_verification(self):
        self.assertEqual(self.verify()['appBuild'], '202610210004')
        self.assertEqual(self.calls[0][:2], ('/usr/bin/codesign', '--verify'))
        self.assertIn((self.executable, '--verify-payloads'), self.calls)

    def test_old_or_nonboolean_policy_is_rejected_before_payload_execution(self):
        valid = dict(self.policy)
        for field, invalid in [('standaloneInstaller', None), ('standaloneInstaller', True),
                               ('standaloneInstaller', 0), ('definitionRollbackUntilUserReady', None),
                               ('definitionRollbackUntilUserReady', False), ('definitionRollbackUntilUserReady', 1)]:
            with self.subTest(field=field, invalid=invalid):
                self.policy = dict(valid)
                if invalid is None: self.policy.pop(field)
                else: self.policy[field] = invalid
                self.calls.clear()
                with self.assertRaisesRegex(RuntimeError, 'safe package-publication'): self.verify()
                self.assertNotIn((self.executable, '--verify-payloads'), self.calls)


class AuthenticatedVendorComponents(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.package = self.base / 'source.pkg'; self.package.write_bytes(b'authenticated synthetic original')
        self.work = self.base / 'work'; self.work.mkdir()
        self.calls = []; self.authenticated = False; self.tamper = False; self.traversal = False

    def authenticate(self, package, lock):
        self.assertEqual(Path(package).read_bytes(), self.package.read_bytes())
        self.assertNotEqual(Path(package), self.package)
        self.authenticated = True

    def command(self, *args, **kwargs):
        self.calls.append(args); self.assertTrue(self.authenticated, 'No archive tool may run before original-package authentication')
        if args[0] == '/usr/bin/xar':
            return '../escape\n' if self.traversal else '\n'.join([f'clamav-1.5.4.macos.universal-{kind}.pkg' for kind, _ in PKG.COMPONENTS] + ['Distribution', 'Resources'])
        if args[0] == '/usr/sbin/pkgutil' and args[1] == '--expand':
            src, dest = Path(args[2]), Path(args[3]); dest.mkdir()
            if src.name == 'authenticated-cisco.pkg':
                for kind, identifier in PKG.COMPONENTS:
                    d = dest / f'clamav-1.5.4.macos.universal-{kind}.pkg'; d.mkdir()
                    for name in ['Bom', 'Payload', 'Scripts']: (d / name).write_bytes((kind + name).encode())
                    (d / 'PackageInfo').write_text(f'<pkg-info identifier="{identifier}" version="1.5.4"/>')
            else:
                original = self.work / 'vendor-expanded' / src.name
                for p in original.iterdir(): shutil.copy2(p, dest / p.name)
                if self.tamper: (dest / 'Scripts').write_bytes(b'changed script')
            return ''
        if args[0] == '/usr/sbin/pkgutil' and args[1] == '--flatten':
            Path(args[3]).write_bytes(b'synthetic flat component'); return ''
        raise AssertionError(args)

    def verify(self):
        with patch.object(PKG.PAYLOAD, 'validate_vendor', side_effect=self.authenticate), patch.object(PKG, 'run', side_effect=self.command):
            return PKG.authenticate_and_flatten_vendor(self.package, self.work, {})

    def test_component_scripts_payload_bom_and_info_are_byte_preserved(self):
        result = self.verify()
        self.assertEqual([r['id'] for r in result], [x[1] for x in PKG.COMPONENTS])
        self.assertTrue(all(set(r['sourceComponentFiles']) == {'Bom', 'Payload', 'Scripts', 'PackageInfo'} for r in result))
        self.assertTrue(all('independently' not in r['authentication'] for r in result))

    def test_unsafe_archive_members_are_rejected_before_extraction(self):
        self.traversal = True
        with self.assertRaisesRegex(RuntimeError, 'unsafe member'): self.verify()
        self.assertFalse(any(a[0] == '/usr/sbin/pkgutil' for a in self.calls))

    def test_reflattened_component_tampering_is_rejected(self):
        self.tamper = True
        with self.assertRaisesRegex(RuntimeError, 'changed'): self.verify()


class PublicPackageVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / 'review.pkg'; self.package.write_bytes(b'synthetic signature fixture')
        self.components = [{'id': identifier, 'version': '1.5.4', 'file': f'clamav-1.5.4.macos.universal-{kind}.pkg'} for kind, identifier in PKG.COMPONENTS]
        self.metadata = {'appVersion': '0.2.0', 'appBuild': '202610210004', 'appCDHash': 'a' * 40}
        self.calls = []; self.bad_ticket = False; self.extra_script = False; self.expanded = None

    def command(self, *arguments, **kwargs):
        self.calls.append(arguments)
        if arguments[:2] == ('/usr/sbin/pkgutil', '--check-signature'):
            return PKG.PAYLOAD.TRUSTED_PACKAGE + '\n' + PKG.INSTALLER_IDENTITY
        if arguments[:3] == ('/usr/bin/xcrun', 'stapler', 'validate'):
            if self.bad_ticket: raise RuntimeError('synthetic missing stapled ticket')
            return 'validated'
        if arguments[0] == '/usr/sbin/spctl': return 'accepted'
        if arguments[:2] == ('/usr/bin/xar', '-tf'):
            return '\n'.join(['Distribution', 'Resources', 'Kumo-Payload.pkg'] + [c['file'] for c in self.components])
        if arguments[:2] == ('/usr/sbin/pkgutil', '--expand'):
            self.expanded = d = Path(arguments[3]); d.mkdir(); (d / 'Resources').mkdir()
            distribution = ET.fromstring(PKG.distribution_xml(self.components, self.metadata))
            for ref in distribution.findall('pkg-ref'): ET.SubElement(ref, 'bundle-version')
            (d / 'Distribution').write_text(ET.tostring(distribution, encoding='unicode'))
            for item in self.components + [{'id': PKG.PACKAGE_ID, 'version': '0.2.0', 'file': 'Kumo-Payload.pkg'}]:
                component = d / item['file']; component.mkdir()
                for name in ['Bom', 'Payload']: (component / name).write_bytes(b'fixed synthetic data')
                scripts = component / 'Scripts'; scripts.mkdir()
                attrs = {'identifier': item['id'], 'version': item['version'], 'relocatable': 'false'}
                if item['id'] == PKG.PACKAGE_ID:
                    attrs['install-location'] = '/Library/Application Support/Kumo/Setup/202610210004'
                info = ET.Element('pkg-info', attrs); ET.SubElement(info, 'bundle-version'); ET.SubElement(info, 'relocate')
                if item['id'] == PKG.PACKAGE_ID:
                    declarations = ET.SubElement(info, 'scripts')
                    ET.SubElement(declarations, 'preinstall', {'file': './preinstall', 'timeout': '600'})
                    ET.SubElement(declarations, 'postinstall', {'file': './publish-kumo', 'component-id': 'app.kumo.setup', 'timeout': '3600'})
                    for name, text in zip(('preinstall', 'publish-kumo'), PKG.scripts_for_build('202610210004')):
                        (scripts / name).write_text(text); (scripts / name).chmod(0o755)
                    if self.extra_script: (scripts / 'unreviewed').write_text('exit 1')
                (component / 'PackageInfo').write_text(ET.tostring(info, encoding='unicode'))
            return ''
        if arguments[:2] == ('/usr/sbin/pkgutil', '--expand-full'):
            (Path(arguments[3]) / 'Kumo-Payload.pkg/Payload/Kumo Setup.app').mkdir(parents=True)
            return ''
        raise AssertionError('No other command may run in the public verifier: ' + repr(arguments))

    def authenticated_vendor(self, *args):
        return [{**c, 'sourceComponentFiles': PKG.component_hashes(self.expanded / c['file'])} for c in self.components]

    def verify(self):
        with patch.object(PKG, 'run', side_effect=self.command), patch.object(PKG, 'validate_setup', return_value=self.metadata), patch.object(PKG, 'authenticate_and_flatten_vendor', side_effect=self.authenticated_vendor):
            return PKG.verify_public_package(self.package, '0.2.0', '202610210004', 'a' * 40)

    def test_independent_verification_returns_only_identity_and_never_runs_installer_scripts(self):
        self.assertEqual(self.verify(), {**self.metadata, 'teamId': PKG.TEAM, 'notarized': True})
        self.assertFalse(any(c[0] in ['/usr/sbin/installer', '/bin/sh', '/usr/bin/sudo'] for c in self.calls))

    def test_missing_notarization_stops_before_extraction(self):
        self.bad_ticket = True
        with self.assertRaisesRegex(RuntimeError, 'stapled ticket'): self.verify()
        self.assertIsNone(self.expanded)

    def test_extra_script_is_rejected_before_inner_helper_inspection(self):
        self.extra_script = True
        with self.assertRaisesRegex(RuntimeError, 'unexpected Setup scripts'): self.verify()

    def test_other_browser_cdhash_is_rejected(self):
        self.metadata['appCDHash'] = 'b' * 40
        with self.assertRaisesRegex(RuntimeError, 'release app identity'): self.verify()


class PublicPackageSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / 'source.pkg'; self.source.write_bytes(b'bounded synthetic package')
        self.destination = self.directory / 'private.pkg'

    def test_one_regular_descriptor_creates_private_complete_snapshot(self):
        proof = PKG.snapshot_package(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assertEqual(proof, {'sha256': PKG.digest(self.destination), 'bytes': self.source.stat().st_size})
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)

    def test_symlink_and_hardlink_sources_are_rejected(self):
        link = self.directory / 'link.pkg'; link.symlink_to(self.source)
        with self.assertRaises(RuntimeError): PKG.snapshot_package(link, self.destination)
        link.unlink(); os.link(self.source, link)
        for path in [link, self.source]:
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'non-hardlinked'):
                PKG.snapshot_package(path, self.destination)
        self.assertFalse(self.destination.exists())

    def test_symlink_replacement_at_open_cannot_be_followed(self):
        original_open = os.open; backing = self.directory / 'backing.pkg'
        def race(path, flags, *args):
            if Path(path) == self.source:
                self.source.rename(backing); self.source.symlink_to(backing)
            return original_open(path, flags, *args)
        with patch.object(PKG.os, 'open', side_effect=race):
            with self.assertRaisesRegex(RuntimeError, 'without following a link'):
                PKG.snapshot_package(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def assert_race_rejected(self, mutate, message):
        original_read = os.read; changed = False
        def race(descriptor, count):
            nonlocal changed
            if not changed:
                changed = True; mutate()
            return original_read(descriptor, count)
        with patch.object(PKG.os, 'read', side_effect=race):
            with self.assertRaisesRegex(RuntimeError, message):
                PKG.snapshot_package(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_truncation_is_rejected_and_partial_snapshot_removed(self):
        self.assert_race_rejected(lambda: self.source.write_bytes(b''), 'changed')

    def test_growth_is_rejected_and_partial_snapshot_removed(self):
        original = self.source.read_bytes()
        self.assert_race_rejected(lambda: self.source.write_bytes(original + b'grew'), 'grew')

    def test_same_size_mutation_is_rejected(self):
        size = self.source.stat().st_size
        self.assert_race_rejected(lambda: self.source.write_bytes(b'x' * size), 'changed')

    def test_path_replacement_after_open_is_rejected(self):
        def replace():
            original = self.source.read_bytes(); self.source.rename(self.directory / 'old.pkg'); self.source.write_bytes(original)
        self.assert_race_rejected(replace, 'changed')

    def test_empty_oversized_and_fifo_sources_fail_before_copy(self):
        with self.assertRaisesRegex(RuntimeError, 'bounded'):
            PKG.snapshot_package(self.source, self.destination, maximum=3)
        self.source.write_bytes(b'')
        with self.assertRaisesRegex(RuntimeError, 'bounded'): PKG.snapshot_package(self.source, self.destination)
        self.source.unlink(); os.mkfifo(self.source)
        with self.assertRaisesRegex(RuntimeError, 'regular'): PKG.snapshot_package(self.source, self.destination)
        self.assertFalse(self.destination.exists())


@unittest.skipUnless(sys.platform == 'darwin' and Path('/usr/bin/pkgbuild').exists(), 'Apple package tools required')
class AppleToolsStructureFixture(unittest.TestCase):
    def test_real_unsigned_distribution_expands_without_running_any_script(self):
        with tempfile.TemporaryDirectory(prefix='kumo-pkg-structure-') as directory:
            d = Path(directory); packages = d / 'packages'; packages.mkdir(); resources = d / 'resources'; resources.mkdir()
            (resources / 'Welcome.html').write_text('<html><body>NONINSTALLABLE SYNTHETIC STRUCTURE FIXTURE</body></html>')
            shutil.copy2(resources / 'Welcome.html', resources / 'Conclusion.html')
            root = d / 'empty-root'; root.mkdir(); scripts = d / 'scripts'; scripts.mkdir()
            # If someone deliberately opens this temporary fixture, refuse to
            # install. This test only builds/expands the package, never runs it.
            (scripts / 'preinstall').write_text('#!/bin/sh\nexit 78\n'); (scripts / 'preinstall').chmod(0o755)
            components = []
            for i, kind in enumerate(['libraries', 'programs', 'documentation']):
                identifier = 'example.kumo.noninstallable.fixture.' + kind
                file = kind + '.pkg'
                subprocess.run(['/usr/bin/pkgbuild', '--root', str(root), '--identifier', identifier, '--version', '1.5.4', '--scripts', str(scripts), str(packages / file)], capture_output=True, check=True, timeout=60)
                components.append({'id': identifier, 'version': '1.5.4', 'file': file})
            bundle = root / 'Kumo Setup.app'; (bundle / 'Contents/MacOS').mkdir(parents=True)
            (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'app.kumo.setup', 'CFBundleExecutable': 'KumoSetup', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '202610210004', 'CFBundleShortVersionString': '0.2.0'}))
            executable = bundle / 'Contents/MacOS/KumoSetup'; executable.write_text('#!/bin/sh\nexit 78\n'); executable.chmod(0o755)
            publish = scripts / 'publish-kumo'; publish.write_text('#!/bin/sh\nexit 78\n'); publish.chmod(0o755)
            policy_file = d / 'component-policy.plist'
            subprocess.run(['/usr/bin/pkgbuild', '--analyze', '--root', str(root), str(policy_file)], capture_output=True, check=True, timeout=60)
            policy_file.write_bytes(plistlib.dumps(PKG.configure_component_policy(plistlib.loads(policy_file.read_bytes()))))
            subprocess.run(['/usr/bin/pkgbuild', '--root', str(root), '--identifier', PKG.PACKAGE_ID, '--version', '0.2.0', '--scripts', str(scripts), '--component-plist', str(policy_file), str(packages / 'Kumo-Payload.pkg')], capture_output=True, check=True, timeout=60)
            distribution = PKG.distribution_xml(components, {'appVersion': '0.2.0'}); (d / 'Distribution.xml').write_text(distribution)
            output = d / 'NONINSTALLABLE-structure-fixture.pkg'
            subprocess.run(['/usr/bin/productbuild', '--distribution', str(d / 'Distribution.xml'), '--resources', str(resources), '--package-path', str(packages), str(output)], capture_output=True, check=True, timeout=60)
            expanded = d / 'expanded'
            subprocess.run(['/usr/sbin/pkgutil', '--expand', str(output), str(expanded)], capture_output=True, check=True, timeout=60)
            proof = PKG.verify_distribution(expanded, distribution)
            self.assertTrue(proof['behaviorVerified'])
            self.assertEqual(proof['componentOrder'], [c['id'] for c in components] + [PKG.PACKAGE_ID])
            self.assertEqual(ET.parse(expanded / 'Distribution').getroot().find('options').attrib['hostArchitectures'], 'arm64')
            declarations = [(e.tag, e.attrib) for e in ET.parse(expanded / 'Kumo-Payload.pkg/PackageInfo').getroot().find('scripts')]
            self.assertEqual(declarations, [('preinstall', {'file': './preinstall', 'timeout': '600'}), ('postinstall', {'file': './publish-kumo', 'component-id': 'app.kumo.setup', 'timeout': '3600'})])
            for name in [c['file'] for c in components] + ['Kumo-Payload.pkg']:
                original_component = d / ('before-' + name)
                subprocess.run(['/usr/sbin/pkgutil', '--expand', str(packages / name), str(original_component)], capture_output=True, check=True, timeout=60)
                self.assertEqual(PKG.component_hashes(expanded / name), PKG.component_hashes(original_component))
            original = (expanded / 'Distribution').read_text()
            for old, replacement in [('enable_currentUserHome="false"', 'enable_currentUserHome="true"'),
                                     ('onConclusion="none"', 'onConclusion="RequireRestart"'),
                                     ('#libraries.pkg', 'https://example.invalid/remote.pkg'),
                                     ('app.kumo.browser.updater', 'example.unreviewed.app')]:
                with self.subTest(replacement=replacement):
                    (expanded / 'Distribution').write_text(original.replace(old, replacement, 1))
                    with self.assertRaises(RuntimeError): PKG.verify_distribution(expanded, distribution)
            (expanded / 'Distribution').write_text(original)


if __name__ == '__main__': unittest.main()
