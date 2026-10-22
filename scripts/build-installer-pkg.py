#!/usr/bin/env python3
"""Build a standard Apple Installer distribution. Never installs it.

The authenticated Cisco product contains three component directories. Their
Bom/Payload/Scripts/PackageInfo bytes are retained exactly, re-flattened, and
ordered before Kumo's component. The intact Cisco-signed original remains in
the signed Setup payload. A new outer signature requires Developer ID Installer.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kumo_setup_payload', ROOT / 'scripts/build-installer.py')
PAYLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAYLOAD)
TEAM = 'PV65ZWXCWX'
COMPONENTS = (
    ('libraries', 'com.cisco.ClamAV.libraries'),
    ('programs', 'com.cisco.ClamAV.programs'),
    ('documentation', 'com.cisco.ClamAV.documentation'),
)
PACKAGE_ID = 'app.kumo.setup.payload'
SETUP_REQUIREMENT = 'anchor apple generic and identifier "app.kumo.setup" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "PV65ZWXCWX"'
INSTALLER_IDENTITY = 'Developer ID Installer: Carson Press LLC (PV65ZWXCWX)'


def run(*arguments, timeout=600):
    return PAYLOAD.run(*arguments, timeout=timeout)


def regular(path):
    return PAYLOAD.regular(path)


def digest(path):
    return PAYLOAD.digest(path)


def write_new(path, value, mode=0o644):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(value)


def strict_native_metadata(app):
    app = Path(app)
    metadata = PAYLOAD.load_build_metadata(app)
    native, agent = metadata.get('nativeIntegration', {}), metadata.get('agentRuntime', {})
    if (not (app / 'Contents/Resources/kumo-build-info.json').is_file()
            or native.get('included') is not True or native.get('extensionRequired') is not False
            or agent.get('included') is not True or agent.get('jitless') is not True
            or metadata.get('phishingProtection', {}).get('enabledByDefault') is not True):
        raise RuntimeError('Standard packages require the native browser and bundled agent runtime.')
    resources = app / 'Contents/Resources/agent-bridge'
    for name in ['bin/node', 'LICENSE.node', 'runtime.json']:
        regular(resources / name)
    lock = json.loads(regular(ROOT / 'config/node-runtime-lock.json').read_text())
    runtime = json.loads((resources / 'runtime.json').read_text())
    if (agent.get('version') != lock['version'] or runtime.get('version') != lock['version']
            or digest(resources / 'LICENSE.node') != lock['licenseSHA256']):
        raise RuntimeError('The bundled agent runtime or complete upstream license differs from its pin.')
    if run('/usr/bin/lipo', '-archs', resources / 'bin/node').strip().split() != ['arm64']:
        raise RuntimeError('The bundled agent runtime must be Apple Silicon native.')
    requirement = 'anchor apple generic and identifier "app.kumo.agent.runtime" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "PV65ZWXCWX"'
    run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures',
        '--test-requirement', '=' + requirement, resources / 'bin/node', timeout=180)
    return metadata


def validate_setup(setup):
    setup = Path(setup)
    if setup.is_symlink() or not setup.is_dir() or setup.name != 'Kumo Setup.app':
        raise RuntimeError('Select a signed Kumo Setup.app built with standard-package support.')
    info = plistlib.loads(regular(setup / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'app.kumo.setup' or info.get('CFBundleExecutable') != 'KumoSetup':
        raise RuntimeError('Unexpected setup identity.')
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures',
        '--test-requirement', '=' + SETUP_REQUIREMENT, setup, timeout=300)
    details = run('/usr/bin/codesign', '--display', '--verbose=4', setup)
    code = re.search(r'^CDHash=([0-9a-fA-F]{40})$', details, re.M)
    if not code or 'Authority=Developer ID Application:' not in details:
        raise RuntimeError('Kumo Setup needs a Developer ID Application signature.')
    executable = regular(setup / 'Contents/MacOS/KumoSetup')
    # These two modes are read-only. Verify signed code before executing either.
    policy = json.loads(run(executable, '--package-policy', timeout=30).splitlines()[-1])
    if (policy.get('ok') is not True or policy.get('packageMode') != 1
            or policy.get('nestedInstaller') is not False
            or policy.get('rollbackUntilUserReady') is not True
            or policy.get('standaloneInstaller') is not False
            or policy.get('definitionRollbackUntilUserReady') is not True):
        raise RuntimeError('The setup helper lacks the required safe package-publication mode.')
    verified = json.loads(run(executable, '--verify-payloads', timeout=900).splitlines()[-1])
    if verified.get('ok') is not True or verified.get('status') != 'payloads-verified':
        raise RuntimeError('The signed setup payload did not verify.')
    app = setup / 'Contents/Resources/payload/Kumo.app'
    app_metadata = PAYLOAD.validate_app(app)
    strict_native_metadata(app)
    build = app_metadata['appBuild']
    if (not re.fullmatch(r'[1-9][0-9]{0,17}', build)
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', app_metadata['appVersion'])
            or info.get('CFBundleVersion') != build
            or info.get('CFBundleShortVersionString') != app_metadata['appVersion']):
        raise RuntimeError('Setup, package and browser versions disagree.')
    return {**app_metadata, 'setupCDHash': code[1].lower(),
            'nativeIntegration': True, 'bundledAgentRuntime': True,
            'phishLangDefaultEnabled': True}


def authenticate_and_flatten_vendor(package, work, lock):
    package, work = Path(package), Path(work)
    # The authenticated original is copied to an owned private staging folder
    # and revalidated there before any archive extraction or component use.
    original = work / 'authenticated-cisco.pkg'
    shutil.copy2(regular(package), original)
    PAYLOAD.validate_vendor(original, lock)
    members = run('/usr/bin/xar', '-tf', original).splitlines()
    allowed_roots = {f'clamav-1.5.4.macos.universal-{kind}.pkg' for kind, _ in COMPONENTS}
    allowed_roots |= {'Resources', 'Distribution'}
    if (not members or len(members) != len(set(members)) or len(members) > 1000
            or any(not path or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/'))
                   or path.split('/')[0] not in allowed_roots for path in members)):
        raise RuntimeError('Unexpected or unsafe member in the authenticated Cisco distribution.')
    expanded = work / 'vendor-expanded'
    run('/usr/sbin/pkgutil', '--expand', original, expanded, timeout=300)
    package_directory = work / 'components'
    package_directory.mkdir()
    evidence = []
    for kind, expected_id in COMPONENTS:
        name = f'clamav-1.5.4.macos.universal-{kind}.pkg'
        component = expanded / name
        if component.is_symlink() or not component.is_dir():
            raise RuntimeError('A required Cisco component is missing.')
        if {p.name for p in component.iterdir()} != {'Bom', 'Payload', 'Scripts', 'PackageInfo'}:
            raise RuntimeError('Unexpected Cisco component structure.')
        hashes = component_hashes(component)
        info = ET.fromstring((component / 'PackageInfo').read_bytes())
        if (info.tag != 'pkg-info' or info.attrib.get('identifier') != expected_id
                or info.attrib.get('version') != '1.5.4'):
            raise RuntimeError('Cisco component identity or version differs from the pinned distribution.')
        output = package_directory / name
        run('/usr/sbin/pkgutil', '--flatten', component, output, timeout=300)
        # Roundtrip verifies original scripts, payload, BOM and metadata bytes.
        checked = work / ('verify-' + kind)
        run('/usr/sbin/pkgutil', '--expand', output, checked, timeout=300)
        if component_hashes(checked) != hashes:
            raise RuntimeError('Re-flattening changed a Cisco component.')
        evidence.append({'id': expected_id, 'version': '1.5.4', 'file': name,
                         'sourceComponentFiles': hashes, 'sha256': digest(output),
                         'authentication': 'Extracted from the exact hash-pinned and Cisco-signature-verified product distribution; inner component bytes unchanged.'})
    return evidence


def component_hashes(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError('A package component is missing or is a symbolic link.')
    paths = list(directory.iterdir())
    if {p.name for p in paths} != {'Bom', 'Payload', 'Scripts', 'PackageInfo'}:
        raise RuntimeError('Unexpected final package component structure.')
    result = {}
    for path in paths:
        if path.name == 'Scripts' and path.is_dir() and not path.is_symlink():
            # pkgutil expands pkgbuild's script archive into a directory, but
            # retains some vendor script archives as a file. Bind either form
            # exactly, including executable permission bits for real scripts.
            entries = {}
            for item in path.rglob('*'):
                relative = str(item.relative_to(path))
                if item.is_symlink() or len(entries) >= 512:
                    raise RuntimeError('Unsafe or oversized component script directory.')
                if item.is_dir():
                    entries[relative] = {'type': 'directory', 'mode': item.stat().st_mode & 0o777}
                else:
                    entries[relative] = {'type': 'file', 'mode': item.stat().st_mode & 0o777, 'sha256': digest(regular(item))}
            result[path.name] = {'type': 'directory', 'entries': entries}
        else:
            result[path.name] = digest(regular(path))
    return result


def normalize_kumo_component_scripts(component, scripts, output, work):
    """Rearchive only Kumo's two new unsigned scripts without AppleDouble.

    pkgbuild records source-file metadata as additional script members, while
    pkgutil --flatten rearchives a Scripts FILE as a nested member. Build the
    standard four-member flat component with Apple's xar instead, preserving
    the original BOM, compressed payload and PackageInfo bytes exactly.
    """
    component, scripts, output, work = map(Path, (component, scripts, output, work))
    names = ('preinstall', 'publish-kumo')
    if (scripts.is_symlink() or not scripts.is_dir()
            or {p.name for p in scripts.iterdir()} != set(names)
            or output.exists() or output.is_symlink()):
        raise RuntimeError('Choose two fixed scripts and a new unsigned component output.')
    expected_scripts = {}
    for name in names:
        file = regular(scripts / name)
        if stat.S_IMODE(file.stat().st_mode) != 0o755:
            raise RuntimeError('The fixed unsigned package scripts must have mode 0755.')
        expected_scripts[name] = digest(file)
    work.mkdir(mode=0o700)
    expanded = work / 'original-expanded'
    run('/usr/sbin/pkgutil', '--expand', regular(component), expanded, timeout=600)
    before = component_hashes(expanded)
    old_scripts = expanded / 'Scripts'
    if (old_scripts.is_symlink() or not old_scripts.is_dir()
            or not set(names) <= {p.name for p in old_scripts.iterdir()}
            or {p.name for p in old_scripts.iterdir()} - set(names)
               - {'._' + name for name in names}):
        raise RuntimeError('The unsigned Kumo component has unexpected script members.')
    for name in names:
        file = regular(old_scripts / name)
        if digest(file) != expected_scripts[name] or stat.S_IMODE(file.stat().st_mode) != 0o755:
            raise RuntimeError('pkgbuild changed a fixed unsigned package script.')
    old_scripts.rename(work / 'original-scripts')
    archive = work / 'Scripts.cpio'
    run('/usr/bin/tar', '--format', 'cpio', '--disable-copyfile', '--no-xattrs', '--no-acls',
        '--uid', '0', '--gid', '0', '-cf', archive, '-C', scripts, *names, timeout=120)
    with (expanded / 'Scripts').open('xb') as compressed:
        subprocess.run(['/usr/bin/gzip', '-n', '-c', str(archive)], stdout=compressed,
                       stderr=subprocess.PIPE, check=True, timeout=120)
    members = ('Bom', 'Payload', 'PackageInfo', 'Scripts')
    raw_hashes = {name: digest(regular(expanded / name)) for name in members}
    subprocess.run(['/usr/bin/xar', '-cf', str(output.absolute()), '--compression', 'none', *members],
                   cwd=expanded, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=600)
    listed = run('/usr/bin/xar', '-tf', output).splitlines()
    if len(listed) != 4 or set(listed) != set(members):
        raise RuntimeError('The normalized unsigned component has unexpected XAR members.')
    raw_checked = work / 'raw-checked'; raw_checked.mkdir(mode=0o700)
    run('/usr/bin/xar', '-xf', output, '-C', raw_checked, timeout=600)
    if ({p.name for p in raw_checked.iterdir()} != set(members)
            or {name: digest(regular(raw_checked / name)) for name in members} != raw_hashes):
        raise RuntimeError('The normalized unsigned component changed raw archive bytes.')
    checked = work / 'checked'
    run('/usr/sbin/pkgutil', '--expand', output, checked, timeout=600)
    after = component_hashes(checked)
    if any(after[name] != before[name] for name in members if name != 'Scripts'):
        raise RuntimeError('Script normalization changed the BOM, payload or PackageInfo.')
    wanted = {name: {'type': 'file', 'mode': 0o755, 'sha256': expected_scripts[name]} for name in names}
    if after['Scripts'] != {'type': 'directory', 'entries': wanted}:
        raise RuntimeError('The normalized component must contain exactly the two fixed scripts.')
    return after


def configure_component_policy(policy):
    if not isinstance(policy, list) or not policy:
        raise RuntimeError('Package analysis did not identify the signed Setup bundle.')
    setup_count = 0
    def configure(entries):
        nonlocal setup_count
        for entry in entries:
            if not isinstance(entry, dict):
                raise RuntimeError('Invalid bundle entry in component analysis.')
            relative = entry.get('RootRelativeBundlePath', '')
            if not isinstance(relative, str) or relative.startswith('/') or '..' in Path(relative).parts:
                raise RuntimeError('Unsafe bundle path in component analysis.')
            entry['BundleIsRelocatable'] = False
            entry['BundleIsVersionChecked'] = False
            entry['BundleHasStrictIdentifier'] = True
            if relative == 'Kumo Setup.app':
                setup_count += 1
                entry['BundlePostInstallScriptPath'] = 'publish-kumo'
                # Documented pkgbuild key; macOS >15 respects the larger bound.
                # Older systems retain Apple's 10-minute maximum. Transaction
                # snapshots/leases remain protected if the OS stops a helper.
                entry['BundleInstallScriptTimeout'] = 3600
            child = entry.get('ChildBundles', [])
            if not isinstance(child, list):
                raise RuntimeError('Invalid child-bundle policy.')
            configure(child)
    configure(policy)
    if setup_count != 1:
        raise RuntimeError('Package analysis has no unambiguous Setup root bundle.')
    return policy


def scripts_for_build(build):
    if not re.fullmatch(r'[1-9][0-9]{0,17}', build):
        raise RuntimeError('Unsafe package build identifier.')
    source = f'/Library/Application Support/Kumo/Setup/{build}/Kumo Setup.app'
    # Only fixed, shell-quoted build paths and immutable system tools. Installer
    # arguments select no target, helper, package, command or account.
    preinstall = '''#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" = 0 ] || exit 77
[ "${3:-}" = / ] || { /bin/echo "Install Kumo on the current startup disk." >&2; exit 78; }
'''
    postinstall = preinstall + f'''
umask 077
stage=$(/usr/bin/mktemp -d /private/var/tmp/kumo-setup-XXXXXXXX)
trap '/bin/rm -rf "$stage"' EXIT HUP INT TERM
/usr/bin/ditto --rsrc --extattr --noacl {shlex.quote(source)} "$stage/Kumo Setup.app"
/usr/sbin/chown -R -h 0:0 "$stage/Kumo Setup.app"
/bin/chmod -R go-w "$stage/Kumo Setup.app"
/usr/bin/codesign --verify --deep --strict --all-architectures --test-requirement {shlex.quote('=' + SETUP_REQUIREMENT)} "$stage/Kumo Setup.app"
"$stage/Kumo Setup.app/Contents/MacOS/KumoSetup" --install-package-root
'''
    return preinstall, postinstall


def distribution_xml(components, app_metadata):
    root = ET.Element('installer-gui-script', {'minSpecVersion': '2'})
    ET.SubElement(root, 'title').text = 'Kumo'
    ET.SubElement(root, 'welcome', {'file': 'Welcome.html', 'mime-type': 'text/html'})
    ET.SubElement(root, 'conclusion', {'file': 'Conclusion.html', 'mime-type': 'text/html'})
    ET.SubElement(root, 'options', {'customize': 'never', 'require-scripts': 'true', 'hostArchitectures': 'arm64'})
    ET.SubElement(root, 'domains', {'enable_localSystem': 'true', 'enable_currentUserHome': 'false', 'enable_anywhere': 'false'})
    ET.SubElement(root, 'allowed-os-versions').append(ET.Element('os-version', {'min': '13.0'}))
    outline = ET.SubElement(root, 'choices-outline')
    ET.SubElement(outline, 'line', {'choice': 'antivirus'})
    ET.SubElement(outline, 'line', {'choice': 'browser'})
    vendor = ET.SubElement(root, 'choice', {'id': 'antivirus', 'visible': 'false', 'title': 'Antivirus engine', 'start_selected': 'true'})
    for component in components:
        ET.SubElement(vendor, 'pkg-ref', {'id': component['id']})
    browser = ET.SubElement(root, 'choice', {'id': 'browser', 'visible': 'false', 'title': 'Kumo browser and protection', 'start_selected': 'true'})
    ET.SubElement(browser, 'pkg-ref', {'id': PACKAGE_ID})
    for component in components:
        ref = ET.SubElement(root, 'pkg-ref', {'id': component['id'], 'version': component['version'], 'auth': 'Root', 'onConclusion': 'none'})
        ref.text = component['file']
    ref = ET.SubElement(root, 'pkg-ref', {'id': PACKAGE_ID, 'version': app_metadata['appVersion'], 'auth': 'Root', 'onConclusion': 'none'})
    ref.text = 'Kumo-Payload.pkg'
    close = ET.SubElement(ref, 'must-close')
    ET.SubElement(close, 'app', {'id': 'app.kumo.browser'})
    ET.SubElement(close, 'app', {'id': 'app.kumo.browser.updater'})
    ET.indent(root)
    return ET.tostring(root, encoding='unicode', xml_declaration=True) + '\n'


def xml_signature(element):
    """Compare XML meaning while ignoring serializer whitespace/attribute order."""
    if element.tail and element.tail.strip():
        raise RuntimeError('Unexpected text in the package distribution.')
    return (element.tag, tuple(sorted(element.attrib.items())),
            (element.text or '').strip(), tuple(xml_signature(child) for child in element))


def bundle_version_signature(element, inventory=False):
    """Canonicalize only productbuild's bundle-ID metadata map.

    PackageInfo can inventory several same-ID Chromium helpers. productbuild
    retains the last path for each ID and emits that map in arbitrary order.
    Duplicate inventory IDs must agree in every other attribute/text/child;
    generated duplicates and any changed selected path are still rejected.
    """
    header = xml_signature(element)[:3]
    entries, identities = {}, {}
    for bundle in element:
        identifier = bundle.attrib.get('id')
        if bundle.tag != 'bundle' or not identifier or 'path' not in bundle.attrib:
            raise RuntimeError('Invalid component bundle metadata.')
        signature = xml_signature(bundle)
        nonpath = (signature[0], tuple((k, v) for k, v in signature[1] if k != 'path'),
                   signature[2], signature[3])
        if identifier in entries:
            if not inventory or identities[identifier] != nonpath:
                raise RuntimeError('Ambiguous component bundle metadata.')
        entries[identifier], identities[identifier] = signature, nonpath
    return (*header, tuple(entries[identifier] for identifier in sorted(entries)))


def verify_distribution(expanded, planned):
    """Allow only productbuild's observed package metadata normalization.

    Apple adds size attributes, # local references, and separate pkg-ref nodes
    carrying bundle-version metadata. That metadata must match each embedded
    component's PackageInfo; every behavioral element remains exact.
    """
    expanded = Path(expanded)
    actual = ET.fromstring(regular(expanded / 'Distribution').read_bytes())
    expected = ET.fromstring(planned)
    if (actual.tag != expected.tag or actual.attrib != expected.attrib
            or (actual.text or '').strip()
            or [xml_signature(e) for e in actual if e.tag != 'pkg-ref']
               != [xml_signature(e) for e in expected if e.tag != 'pkg-ref']):
        raise RuntimeError('The final package changed a reviewed installation rule.')
    wanted = expected.findall('pkg-ref')
    refs = actual.findall('pkg-ref')
    if len(refs) < len(wanted) or len(refs) > len(wanted) * 3:
        raise RuntimeError('The final package has unexpected component references.')
    identifiers = [e.attrib['id'] for e in wanted]
    if [e.attrib.get('id') for e in refs[:len(wanted)]] != identifiers:
        raise RuntimeError('The final package changed the component installation order.')
    for planned_ref in wanted:
        identifier = planned_ref.attrib['id']
        filename = (planned_ref.text or '').strip()
        if Path(filename).name != filename or filename in ('', '.', '..'):
            raise RuntimeError('Unsafe reviewed package reference.')
        info = ET.fromstring(regular(expanded / filename / 'PackageInfo').read_bytes())
        if (info.tag != 'pkg-info' or info.attrib.get('identifier') != identifier
                or info.attrib.get('version') != planned_ref.attrib['version']):
            raise RuntimeError('The embedded component identity differs from the distribution.')
        bundles = info.findall('bundle-version')
        if len(bundles) > 1:
            raise RuntimeError('Ambiguous component bundle metadata.')
        generated_bundle = ET.Element('bundle-version')
        for bundle in info.findall('bundle'):
            value = ET.fromstring(ET.tostring(bundle))
            if 'path' in value.attrib:
                value.attrib['path'] = value.attrib['path'].removeprefix('./')
            generated_bundle.append(value)
        # productbuild promotes the component's bundle inventory into its
        # generated bundle-version node, while PackageInfo keeps the inventory
        # beside the (empty, for our non-version-checked bundles) node.
        if bundles and list(bundles[0]):
            raise RuntimeError('Unexpected version-checked component bundle policy.')
        expected_bundle = bundle_version_signature(generated_bundle, inventory=True) if bundles else None
        bundle_count = 0
        paths = []
        matching = [e for e in refs if e.attrib.get('id') == identifier]
        for index, ref in enumerate(matching):
            attrs = dict(ref.attrib)
            if index == 0:
                for key in ('installKBytes', 'updateKBytes'):
                    size = attrs.pop(key, None)
                    if size is not None and (not re.fullmatch(r'[0-9]{1,18}', size)):
                        raise RuntimeError('Invalid generated package size metadata.')
                if attrs != planned_ref.attrib:
                    raise RuntimeError('The final package changed component authorization or version.')
            elif attrs != {'id': identifier}:
                raise RuntimeError('Unexpected generated component attributes.')
            text = (ref.text or '').strip()
            if text:
                if text.removeprefix('#') != filename:
                    raise RuntimeError('The final package changed a component destination.')
                paths.append(text)
            reviewed_children = []
            for child in ref:
                if child.tag == 'bundle-version':
                    if bundle_version_signature(child) != expected_bundle:
                        raise RuntimeError('The final package changed component bundle metadata.')
                    bundle_count += 1
                else:
                    reviewed_children.append(xml_signature(child))
            if reviewed_children != ([xml_signature(c) for c in planned_ref] if index == 0 else []):
                raise RuntimeError('The final package changed required application closure rules.')
        if not paths or len(paths) > 2 or bundle_count != len(bundles):
            raise RuntimeError('The final package has incomplete or duplicate component metadata.')
    if set(e.attrib.get('id') for e in refs) != set(identifiers):
        raise RuntimeError('The final package added an unreviewed component.')
    return {'plannedSHA256': hashlib.sha256(planned.encode()).hexdigest(),
            'compiledSHA256': digest(expanded / 'Distribution'),
            'componentOrder': identifiers, 'behaviorVerified': True}


def snapshot_package(source, destination, maximum=4 * 1024**3):
    """Copy one bounded regular inode, never following links or reopening it."""
    source, destination = Path(source), Path(destination)
    if source.suffix != '.pkg':
        raise RuntimeError('A standard .pkg file is required.')
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        raise RuntimeError('The public package cannot be opened without following a link.') from error
    created = False
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise RuntimeError('The public package must be a bounded, non-hardlinked regular file.')
        state = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                               value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        created = True
        total, checksum = 0, hashlib.sha256()
        with os.fdopen(target, 'wb') as output:
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, before.st_size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > before.st_size or total > maximum:
                    raise RuntimeError('The public package grew during snapshot creation.')
                output.write(chunk)
                checksum.update(chunk)
        after = os.fstat(descriptor)
        try:
            current = source.lstat()
        except OSError as error:
            raise RuntimeError('The public package path changed during snapshot creation.') from error
        if total != before.st_size or state(after) != state(before) or state(current) != state(before):
            raise RuntimeError('The public package changed during snapshot creation.')
        if destination.stat().st_size != total:
            raise RuntimeError('The private package snapshot is incomplete.')
        return {'sha256': checksum.hexdigest(), 'bytes': total}
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def verify_public_package(package: Path, expected_version: str,
                          expected_build: str, expected_app_cdhash: str) -> dict:
    """Independently authenticate a public package; never install or trust a receipt.

    Only signed read-only Setup inspection modes execute, after its complete
    Developer ID signature verifies. All extraction uses a private snapshot;
    no caller path, account, shell fragment or package script is executed.
    """
    if (not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', expected_version)
            or not re.fullmatch(r'[1-9][0-9]{0,17}', expected_build)
            or not re.fullmatch(r'[0-9a-fA-F]{40}', expected_app_cdhash)):
        raise RuntimeError('Invalid expected public package identity.')
    package = Path(package)
    with tempfile.TemporaryDirectory(prefix='kumo-public-pkg-') as directory:
        work = Path(directory)
        snapshot = work / 'authenticated.pkg'
        snapshot_package(package, snapshot)
        signature = run('/usr/sbin/pkgutil', '--check-signature', snapshot, timeout=180)
        if PAYLOAD.TRUSTED_PACKAGE not in signature or INSTALLER_IDENTITY not in signature:
            raise RuntimeError('The public package lacks the trusted Carson Press Installer signature.')
        run('/usr/bin/xcrun', 'stapler', 'validate', snapshot, timeout=180)
        run('/usr/sbin/spctl', '--assess', '--type', 'install', '--verbose=2', snapshot, timeout=180)
        component_names = {f'clamav-1.5.4.macos.universal-{kind}.pkg' for kind, _ in COMPONENTS}
        allowed = {'Distribution', 'Resources', 'Kumo-Payload.pkg'} | component_names
        members = run('/usr/bin/xar', '-tf', snapshot).splitlines()
        if (not members or len(members) > 4000 or len(members) != len(set(members))
                or any(not member or member.startswith('/')
                       or any(part in ('', '.', '..') for part in member.split('/'))
                       or member.split('/')[0] not in allowed for member in members)):
            raise RuntimeError('The signed public package contains an unsafe archive member.')
        expanded = work / 'expanded'
        run('/usr/sbin/pkgutil', '--expand', snapshot, expanded, timeout=600)
        if {p.name for p in expanded.iterdir()} != allowed:
            raise RuntimeError('The public package has unexpected or missing components.')
        kumo = expanded / 'Kumo-Payload.pkg'
        component_hashes(kumo)
        info = ET.fromstring(regular(kumo / 'PackageInfo').read_bytes())
        if (info.attrib.get('identifier') != PACKAGE_ID
                or info.attrib.get('version') != expected_version
                or info.attrib.get('install-location') != f'/Library/Application Support/Kumo/Setup/{expected_build}'
                or info.attrib.get('relocatable') != 'false'
                or list(info.find('relocate') or [])):
            raise RuntimeError('The public package has an unsafe Setup installation destination.')
        scripts = info.find('scripts')
        declarations = [(child.tag, child.attrib) for child in scripts] if scripts is not None else []
        expected_declarations = [
            ('preinstall', {'file': './preinstall', 'timeout': '600'}),
            ('postinstall', {'file': './publish-kumo', 'component-id': 'app.kumo.setup', 'timeout': '3600'}),
        ]
        if declarations != expected_declarations:
            raise RuntimeError('The public package changed the fixed Setup script declarations.')
        script_directory = kumo / 'Scripts'
        if script_directory.is_symlink() or not script_directory.is_dir() or {p.name for p in script_directory.iterdir()} != {'preinstall', 'publish-kumo'}:
            raise RuntimeError('The public package has unexpected Setup scripts.')
        for name, wanted in zip(('preinstall', 'publish-kumo'), scripts_for_build(expected_build)):
            file = regular(script_directory / name)
            if file.read_text() != wanted or file.stat().st_mode & 0o111 != 0o111:
                raise RuntimeError('A public package Setup script differs from the reviewed implementation.')
        full = work / 'full'
        run('/usr/sbin/pkgutil', '--expand-full', snapshot, full, timeout=1200)
        payload = full / 'Kumo-Payload.pkg/Payload'
        if payload.is_symlink() or not payload.is_dir() or {p.name for p in payload.iterdir()} != {'Kumo Setup.app'}:
            raise RuntimeError('The public package has an unexpected Setup payload root.')
        setup = payload / 'Kumo Setup.app'
        metadata = validate_setup(setup)
        if (metadata['appVersion'] != expected_version or metadata['appBuild'] != expected_build
                or metadata['appCDHash'].lower() != expected_app_cdhash.lower()):
            raise RuntimeError('The packaged browser differs from the release app identity.')
        lock = PAYLOAD.load_lock(ROOT / 'config/clamav-lock.json')
        vendor_work = work / 'vendor'; vendor_work.mkdir(mode=0o700)
        components = authenticate_and_flatten_vendor(setup / 'Contents/Resources/payload/clamav.pkg', vendor_work, lock)
        for component in components:
            if component_hashes(expanded / component['file']) != component['sourceComponentFiles']:
                raise RuntimeError('A public antivirus component differs from the authenticated Cisco original.')
        verify_distribution(expanded, distribution_xml(components, metadata))
        return {'appVersion': expected_version, 'appBuild': expected_build,
                'appCDHash': expected_app_cdhash.lower(), 'teamId': TEAM, 'notarized': True}


def build(args):
    setup, output = Path(args.setup_app), Path(args.output)
    if output.suffix != '.pkg' or output.exists() or output.is_symlink():
        raise RuntimeError('Choose a new .pkg output path; existing outputs are never overwritten.')
    metadata = validate_setup(setup)
    output.parent.mkdir(parents=True, exist_ok=True)
    output = output.absolute()
    work = output.with_suffix('.pkg-build')
    work.mkdir(mode=0o700)
    try:
        lock = PAYLOAD.load_lock(ROOT / 'config/clamav-lock.json')
        vendor = setup / 'Contents/Resources/payload/clamav.pkg'
        components = authenticate_and_flatten_vendor(vendor, work, lock)
        payload_root = work / 'root'; payload_root.mkdir()
        staged_setup = payload_root / 'Kumo Setup.app'
        run('/usr/bin/ditto', '--rsrc', '--extattr', '--noacl', setup, staged_setup, timeout=900)
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--test-requirement', '=' + SETUP_REQUIREMENT, staged_setup, timeout=300)
        scripts = work / 'scripts'; scripts.mkdir()
        for name, content in zip(('preinstall', 'publish-kumo'), scripts_for_build(metadata['appBuild'])):
            write_new(scripts / name, content, 0o755)
        components_plist = work / 'component-policy.plist'
        run('/usr/bin/pkgbuild', '--analyze', '--root', payload_root, components_plist)
        policy = configure_component_policy(plistlib.loads(components_plist.read_bytes()))
        components_plist.write_bytes(plistlib.dumps(policy))
        run('/usr/bin/pkgbuild', '--root', payload_root, '--identifier', PACKAGE_ID,
            '--version', metadata['appVersion'], '--install-location', f"/Library/Application Support/Kumo/Setup/{metadata['appBuild']}",
            '--ownership', 'recommended', '--component-plist', components_plist, '--scripts', scripts,
            work / 'Kumo-Payload-raw.pkg', timeout=1200)
        payload_hashes = normalize_kumo_component_scripts(
            work / 'Kumo-Payload-raw.pkg', scripts, work / 'components/Kumo-Payload.pkg',
            work / 'payload-script-normalization')
        resources = work / 'Resources'; resources.mkdir()
        write_new(resources / 'Welcome.html', '<!doctype html><html><body><h1>Install Kumo</h1><p>This installer includes the browser, local phishing warnings, antivirus engine and current virus definitions. Close Kumo before continuing. macOS will ask for administrator approval.</p><p>Your browser profiles and existing protection choices are preserved. Connect your desktop AI apps later in Kumo Settings.</p></body></html>')
        write_new(resources / 'Conclusion.html', '<!doctype html><html><body><h1>Kumo is ready</h1><p>Open Kumo from Applications. Download protection has passed a harmless test scan and virus definitions will update automatically for the account currently logged in.</p><p>Local phishing warnings start on for new profiles. Existing opt-outs are preserved. No account password or website content is sent to a cloud model.</p></body></html>')
        distribution = distribution_xml(components, metadata)
        write_new(work / 'Distribution.xml', distribution)
        arguments = ['/usr/bin/productbuild', '--distribution', work / 'Distribution.xml',
                     '--resources', resources, '--package-path', work / 'components']
        if args.identity:
            if not args.identity.startswith('Developer ID Installer:') or f'({TEAM})' not in args.identity:
                raise RuntimeError('Package signing requires the Carson Press Developer ID Installer identity.')
            arguments += ['--sign', args.identity, '--timestamp']
        run(*arguments, output, timeout=1800)
        expanded = work / 'final-expanded'
        run('/usr/sbin/pkgutil', '--expand', output, expanded, timeout=600)
        expected_members = {'Distribution', 'Resources', 'Kumo-Payload.pkg'} | {c['file'] for c in components}
        if {p.name for p in expanded.iterdir()} != expected_members:
            raise RuntimeError('The final product has unexpected or missing components.')
        for component in components:
            if component_hashes(expanded / component['file']) != component['sourceComponentFiles']:
                raise RuntimeError('The final product changed an authenticated Cisco component.')
        if component_hashes(expanded / 'Kumo-Payload.pkg') != payload_hashes:
            raise RuntimeError('The final product changed Kumo publication payload or scripts.')
        distribution_proof = verify_distribution(expanded, distribution)
        if args.identity:
            signature = run('/usr/sbin/pkgutil', '--check-signature', output)
            if PAYLOAD.TRUSTED_PACKAGE not in signature or args.identity not in signature:
                raise RuntimeError('Final package signature did not match the requested Installer identity.')
        receipt = {'schemaVersion': 1, 'builtAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                   'output': str(output), 'sha256': digest(output), 'bytes': output.stat().st_size,
                   'app': metadata, 'vendorOriginalSHA256': lock['packageSHA256'], 'vendorComponents': components,
                   'kumoComponentFiles': payload_hashes,
                   'distributionSHA256': hashlib.sha256(distribution.encode()).hexdigest(),
                   'distributionVerification': distribution_proof,
                   'signed': bool(args.identity), 'notarized': False,
                   'readyForPublicDistribution': False, 'installedOnBuildHost': False,
                   'scope': 'Standard Apple Installer; Cisco components run before Kumo publication; no nested Installer; previous app retained until console-user protection is ready.',
                   'workDirectory': str(work)}
        if args.notary_profile:
            if not args.identity:
                raise RuntimeError('Notarization requires a Developer ID Installer-signed package.')
            command = ['/usr/bin/xcrun', 'notarytool', 'submit', output, '--keychain-profile', args.notary_profile]
            if args.notary_keychain:
                command += ['--keychain', args.notary_keychain]
            result = json.loads(run(*command, '--wait', '--output-format', 'json', timeout=1800))
            if result.get('status') != 'Accepted' or not result.get('id'):
                raise RuntimeError('Apple did not accept this package for notarization.')
            run('/usr/bin/xcrun', 'stapler', 'staple', output, timeout=180)
            run('/usr/bin/xcrun', 'stapler', 'validate', output, timeout=180)
            run('/usr/sbin/spctl', '--assess', '--type', 'install', '--verbose=2', output, timeout=180)
            receipt.update(notarized=True, notarizationSubmissionId=result['id'], readyForPublicDistribution=True,
                           sha256=digest(output), bytes=output.stat().st_size)
        write_new(output.with_suffix('.pkg-receipt.json'), json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt, indent=2))
        return receipt
    except BaseException:
        # Preserve the private build plan and diagnostics; never remove a
        # completed or partially produced package automatically on failure.
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup-app', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--identity', help='Optional Developer ID Installer identity; otherwise builds an unsigned review package.')
    parser.add_argument('--notary-profile')
    parser.add_argument('--notary-keychain', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin': parser.error('Apple packaging tools require macOS.')
    if args.notary_profile and not args.identity: parser.error('Notarization requires a Developer ID Installer identity.')
    build(args)


if __name__ == '__main__':
    main()
