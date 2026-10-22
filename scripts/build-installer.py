#!/usr/bin/env python3
"""Build a self-contained, signed/notarized Kumo Setup.app. Never installs it."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TEAM = 'PV65ZWXCWX'
SETUP_ID = 'app.kumo.setup'
SOURCE_SHA256 = '1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3'
SOURCE_BYTES = 63_702_396
TRUSTED_PACKAGE = 'Status: signed by a developer certificate issued by Apple for distribution'


def run(*arguments, timeout=600):
    result = subprocess.run([str(a) for a in arguments], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(str(arguments[0])).name} failed ({result.returncode}): {result.stdout[-2500:]}')
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'A regular non-symlink file is required: {path.name}')
    return path


def load_lock(path):
    value = json.loads(regular(path).read_text())
    if (value.get('schemaVersion') != 1 or value.get('version') != '1.5.4'
            or value.get('installPrefix') != '/usr/local/clamav'
            or value.get('codeTeamID') != 'DE8Y96K9QP'
            or value.get('installerTeamID') != 'DE8Y96K9QP'
            or value.get('packageBytes') != 166_772_489
            or not 0 < value.get('databaseMaxAgeHours', 0) <= 72
            or not value.get('files') or len(value['files']) > 100
            or not re.fullmatch('[0-9a-f]{64}', value.get('packageSHA256', ''))
            or not re.fullmatch('[0-9A-F]{64}', value.get('installerLeafSHA256', ''))):
        raise RuntimeError('The installer requires the exact authenticated ClamAV runtime policy.')
    return value


def validate_vendor(package, lock):
    package = regular(package)
    if package.stat().st_size != lock['packageBytes'] or digest(package) != lock['packageSHA256']:
        raise RuntimeError('ClamAV installer bytes do not match the publisher pin.')
    signature = run('/usr/sbin/pkgutil', '--check-signature', package, timeout=90)
    normalized = ''.join(signature.split()).upper()
    if (TRUSTED_PACKAGE not in signature
            or f"Developer ID Installer: Cisco ({lock['installerTeamID']})" not in signature
            or lock['installerLeafSHA256'].upper() not in normalized):
        raise RuntimeError('ClamAV installer signature is not the pinned trusted Cisco identity.')
    return {'sha256': lock['packageSHA256'], 'bytes': lock['packageBytes'], 'signatureVerified': True}


def validate_app(app):
    app = Path(app)
    if app.is_symlink() or not app.is_dir() or app.suffix != '.app':
        raise RuntimeError('Use an existing signed Kumo application bundle.')
    info = plistlib.loads(regular(app / 'Contents/Info.plist').read_bytes())
    build = load_build_metadata(app)
    if (info.get('CFBundleIdentifier') != 'app.kumo.browser'
            or info.get('CFBundleExecutable') != 'Kumo' or build.get('sourceCompiledLocally') is not True
            or not isinstance(build.get('sourceBuildReceipt'), dict) or not build['sourceBuildReceipt']
            or build.get('malwareProtection', {}).get('downloadAntivirusIncluded') is not True
            or build.get('phishingProtection', {}).get('included') is not True):
        raise RuntimeError('The Kumo payload must include its verified engine, download scanner and PhishLang.')
    phishing = app / 'Contents/Helpers/KumoPhishing.app/Contents'
    for path in ['MacOS/KumoPhishingHost', 'Resources/PhishLang/vocab.txt',
                 'Resources/PhishLang/NOTICE.md', 'Resources/PhishLang/model-info.json',
                 'Resources/PhishLang/PhishLang.mlmodelc/weights/weight.bin']:
        regular(phishing / path)
    regular(app / 'Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost')
    regular(app / 'Contents/MacOS/KumoMalwareSetup')
    architecture = run('/usr/bin/lipo', '-archs', app / 'Contents/MacOS/Chromium').strip().split()
    if architecture != ['arm64']:
        raise RuntimeError('This installer is qualified only for the supplied Apple Silicon Kumo engine.')
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app, timeout=180)
    details = run('/usr/bin/codesign', '-d', '--verbose=4', app)
    code_hash = re.search(r'^CDHash=([0-9a-fA-F]+)$', details, re.M)
    if ('Identifier=app.kumo.browser\n' not in details or f'TeamIdentifier={TEAM}\n' not in details
            or 'Authority=Developer ID Application:' not in details or not code_hash):
        raise RuntimeError('The Kumo app must have the expected Developer ID application signature.')
    run('/usr/bin/xcrun', 'stapler', 'validate', app, timeout=180)
    run('/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', app, timeout=180)
    return {'appBundleId': info['CFBundleIdentifier'], 'appVersion': info['CFBundleShortVersionString'],
            'appBuild': info['CFBundleVersion'], 'appCDHash': code_hash[1].lower(),
            'phishLangIncluded': True, 'architecture': 'arm64'}


def load_build_metadata(app):
    """Read the one canonical native record, or one historical legacy record.

    Two records are ambiguous even when their current bytes happen to agree.
    Never choose one silently during installation.
    """
    resources = Path(app) / 'Contents/Resources'
    candidates = [resources / 'kumo-build-info.json', resources / 'KumoExtension/build-info.json']
    present = [path for path in candidates if path.exists() or path.is_symlink()]
    if len(present) != 1:
        raise RuntimeError('Kumo must contain exactly one unambiguous build metadata record.')
    file = regular(present[0])
    if file.stat().st_size > 2 * 1024 * 1024:
        raise RuntimeError('Kumo build metadata is oversized.')
    value = json.loads(file.read_text())
    if not isinstance(value, dict):
        raise RuntimeError('Kumo build metadata is not an object.')
    return value


def collect_definitions(database, runtime, lock):
    database, runtime = Path(database), Path(runtime)
    if database.is_symlink() or not database.is_dir():
        raise RuntimeError('Definition source must be a real directory.')
    files = []
    daily_epoch = None
    for name in ['main', 'daily', 'bytecode']:
        file = regular(database / (name + '.cvd'))
        if not 512 <= file.stat().st_size <= 1_073_741_824:
            raise RuntimeError('A virus definition database is missing or truncated.')
        with file.open('rb') as stream:
            fields = stream.read(512).decode('utf-8', 'replace').strip().split(':')
        try:
            if len(fields) < 9 or fields[0] != 'ClamAV-VDB':
                raise ValueError('CVD header')
            version, epoch = int(fields[2]), float(fields[8])
            if epoch <= 0 or not (epoch < float('inf')):
                raise ValueError('CVD timestamp')
        except (ValueError, IndexError):
            raise RuntimeError('A definition database has an invalid publisher header.') from None
        signature = regular(database / f'{name}-{version}.cvd.sign')
        if not 1 <= signature.stat().st_size <= 100_000:
            raise RuntimeError('Definition detached signature is invalid.')
        run(runtime / 'bin/sigtool', '--verify', file, '--cvdcertsdir', runtime / 'etc/certs', timeout=30)
        files.extend([file, signature])
        if name == 'daily':
            daily_epoch = epoch
    age = time.time() - daily_epoch
    if age < -600 or age > lock['databaseMaxAgeHours'] * 3600:
        raise RuntimeError('Daily virus definitions are not current enough to package.')
    return {'files': files, 'definitionsBuiltAt': dt.datetime.fromtimestamp(daily_epoch, dt.timezone.utc).isoformat(),
            'definitionsAgeHours': max(0, age / 3600)}


def validate_runtime(runtime, lock):
    runtime = Path(runtime)
    if runtime.is_symlink() or not runtime.is_dir():
        raise RuntimeError('The official ClamAV runtime is missing.')
    requirement = 'anchor apple generic and certificate leaf[subject.OU] = "DE8Y96K9QP"'
    for entry in lock['files']:
        name = Path(entry['path'])
        if name.is_absolute() or '..' in name.parts:
            raise RuntimeError('Unsafe path in ClamAV runtime policy.')
        file = runtime / name
        if 'symlink' in entry:
            target = entry['symlink']
            if (not isinstance(target, str) or not target or '/' in target
                    or target in ['.', '..'] or not file.is_symlink() or os.readlink(file) != target):
                raise RuntimeError('A ClamAV library alias differs from its vendor pin.')
        else:
            regular(file)
            if file.stat().st_size != entry['bytes'] or digest(file) != entry['sha256']:
                raise RuntimeError('The definition verifier runtime differs from its vendor pin.')
            if entry['path'] in ['bin/clamscan', 'bin/freshclam', 'bin/sigtool'] or name.suffix == '.dylib':
                run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures',
                    '--test-requirement', '=' + requirement, file, timeout=90)


def write_manifest(staged, app_metadata, lock):
    resources = Path(staged) / 'Contents/Resources'
    payload = resources / 'payload'
    if payload.is_symlink() or not payload.is_dir():
        raise RuntimeError('Setup payload is missing.')
    required = ['Kumo.app/Contents/Info.plist', 'clamav.pkg', 'clamav-source.tar.gz',
                'definitions/main.cvd', 'definitions/daily.cvd', 'definitions/bytecode.cvd']
    for name in required:
        regular(payload / name)
    files = {}
    app_root = (payload / 'Kumo.app').resolve()
    for path in sorted(payload.rglob('*')):
        if path.is_symlink():
            try:
                inside_app = path.is_relative_to(payload / 'Kumo.app')
                target = path.resolve(strict=True)
            except (ValueError, RuntimeError, OSError):
                raise RuntimeError('Broken or recursive payload symlink.') from None
            if (not inside_app or os.path.isabs(os.readlink(path))
                    or not target.is_relative_to(app_root)):
                raise RuntimeError('A payload symlink escapes the sealed Kumo application.')
        elif path.is_file():
            files[str(path.relative_to(resources))] = digest(path)
        elif not path.is_dir():
            raise RuntimeError('Unexpected special file in installer payload.')
    required_signatures = []
    for name in ['main', 'daily', 'bytecode']:
        with (payload / 'definitions' / (name + '.cvd')).open('rb') as f:
            version = int(f.read(512).decode('utf-8', 'replace').strip().split(':')[2])
        required_signatures.append(regular(payload / 'definitions' / f'{name}-{version}.cvd.sign'))
    manifest = {'schemaVersion': 1, 'teamId': TEAM, **app_metadata,
                'vendorPackageSHA256': lock['packageSHA256'], 'vendorPackageBytes': lock['packageBytes'],
                'vendorInstallerLeafSHA256': lock['installerLeafSHA256'], 'files': files}
    (resources / 'installer-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    return manifest


def assemble(args):
    app, package, output = args.app.resolve(), args.vendor_package.resolve(), args.output.resolve()
    if output.exists() or output.suffix != '.app':
        raise RuntimeError('Choose a new .app output path; existing outputs are never overwritten.')
    lock = load_lock(ROOT / 'config/clamav-lock.json')
    print('Verifying signed Kumo and Cisco installer...', flush=True)
    metadata = validate_app(app)
    validate_vendor(package, lock)
    validate_runtime(args.runtime.resolve(), lock)
    definitions = collect_definitions(args.definitions.resolve(), args.runtime.resolve(), lock)
    source = regular(args.source_archive.resolve())
    if source.stat().st_size != SOURCE_BYTES or digest(source) != SOURCE_SHA256:
        raise RuntimeError('ClamAV corresponding source must match the published 1.5.4 archive.')
    if args.notices.is_symlink() or not args.notices.is_dir():
        raise RuntimeError('The vendor license/notice directory is missing.')
    executable = regular(args.executable.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o755)
    contents = output / 'Contents'
    resources = contents / 'Resources'
    payload = resources / 'payload'
    (contents / 'MacOS').mkdir(parents=True)
    (payload / 'definitions').mkdir(parents=True)
    info = {'CFBundleIdentifier': SETUP_ID, 'CFBundleName': 'Kumo Setup', 'CFBundleDisplayName': 'Kumo Setup',
            'CFBundleExecutable': 'KumoSetup', 'CFBundlePackageType': 'APPL', 'CFBundleInfoDictionaryVersion': '6.0',
            'CFBundleShortVersionString': metadata['appVersion'], 'CFBundleVersion': metadata['appBuild'],
            'LSMinimumSystemVersion': '13.0', 'LSArchitecturePriority': ['arm64'],
            'NSHighResolutionCapable': True, 'NSHumanReadableCopyright': 'Kumo / Carson Press LLC. Includes separately licensed components.'}
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    shutil.copy2(executable, contents / 'MacOS/KumoSetup')
    (contents / 'MacOS/KumoSetup').chmod(0o755)
    icon = app / 'Contents/Resources/Kumo.icns'
    if icon.is_file():
        shutil.copy2(icon, resources / 'Kumo.icns')
        info['CFBundleIconFile'] = 'Kumo.icns'
        (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    print('Copying browser, engine, PhishLang and current virus definitions...', flush=True)
    run('/usr/bin/ditto', '--rsrc', '--extattr', app, payload / 'Kumo.app', timeout=600)
    shutil.copy2(package, payload / 'clamav.pkg')
    shutil.copy2(source, payload / 'clamav-source.tar.gz')
    notices = payload / 'notices'
    notices.mkdir()
    # Preserve all original notice paths inside a single archive. Only regular
    # top-level files are installed alongside the corresponding source archive.
    shutil.make_archive(str(notices / 'ClamAV-Licenses-and-Notices'), 'gztar', root_dir=args.notices.resolve())
    shutil.copy2(regular(args.notices.resolve() / 'COPYING.txt'), notices / 'ClamAV-GPL.txt')
    (notices / 'README.txt').write_text(
        'ClamAV 1.5.4 is installed from the unmodified, Cisco-signed macOS installer.\n'
        'clamav-source.tar.gz contains matching official source, including vendored Rust dependencies.\n'
        'ClamAV-Licenses-and-Notices.tar.gz preserves the source license and notice files and their paths.\n'
        'Upstream source: https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4\n'
        'Original binaries: https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.macos.universal.pkg\n'
        'No Cisco runtime binaries or their signatures were modified by Kumo.\n')
    for path in definitions['files']:
        shutil.copy2(path, payload / 'definitions' / path.name)
    shutil.copy2(ROOT / 'config/clamav-lock.json', resources / 'clamav-lock.json')
    metadata['definitionsBuiltAt'] = definitions['definitionsBuiltAt']
    manifest = write_manifest(output, metadata, lock)
    validate_vendor(payload / 'clamav.pkg', lock)
    validate_app(payload / 'Kumo.app')
    print(json.dumps({'output': str(output), 'regularPayloadFiles': len(manifest['files']),
                      'phishLangIncluded': True, 'definitionsBuiltAt': definitions['definitionsBuiltAt'],
                      'signed': False, 'installedOnHost': False}, indent=2))
    return output


def setup_archive_name(app):
    info = plistlib.loads(regular(Path(app) / 'Contents/Info.plist').read_bytes())
    version, build = info.get('CFBundleShortVersionString'), info.get('CFBundleVersion')
    if (not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
            or not isinstance(build, str) or not re.fullmatch(r'[1-9][0-9]{0,17}', build)):
        raise RuntimeError('The signed Setup has invalid version metadata.')
    return f'Kumo-Setup-{version}-{build}-Apple-Silicon.zip'


def sign_setup(app, identity):
    # Existing nested Kumo/Cisco signatures are deliberately retained.
    executable = app / 'Contents/MacOS/KumoSetup'
    for target in [executable, app]:
        run('/usr/bin/codesign', '--force', '--sign', identity, '--timestamp', '--options', 'runtime',
            '--identifier', SETUP_ID, target, timeout=180)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app, timeout=240)
    run(executable, '--verify-payloads', timeout=600)


def sign_for_package(app, identity):
    """Sign a nested Setup payload; the enclosing distribution must be notarized."""
    sign_setup(app, identity)
    receipt = {'setup': str(app), 'signed': True, 'notarized': False,
               'readyForPublicDistribution': False, 'outerPackageNotarizationRequired': True,
               'nestedPackageOnly': True, 'includesPhishLang': True,
               'includesClamAV': True, 'includesDefinitions': True,
               'installedOnBuildHost': False}
    (app.parent / 'installer-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


def sign_and_notarize(app, identity, notary_profile, notary_keychain):
    sign_setup(app, identity)
    archive = app.with_suffix('.notary.zip')
    if archive.exists():
        raise RuntimeError('Notarization archive already exists.')
    print('Creating Apple notarization archive...', flush=True)
    run('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive, timeout=1200)
    print('Submitting signed setup to Apple notarization...', flush=True)
    arguments = ['/usr/bin/xcrun', 'notarytool', 'submit', archive, '--keychain-profile', notary_profile]
    if notary_keychain is not None:
        arguments += ['--keychain', str(notary_keychain.resolve())]
    result = json.loads(run(*arguments, '--wait', '--output-format', 'json', timeout=1800))
    if result.get('status') != 'Accepted' or not result.get('id'):
        raise RuntimeError(f"Setup notarization was not accepted: {result.get('status', 'unknown')}")
    run('/usr/bin/xcrun', 'stapler', 'staple', app, timeout=240)
    run('/usr/bin/xcrun', 'stapler', 'validate', app, timeout=240)
    run('/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', app, timeout=240)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app, timeout=240)
    final_zip = app.parent / setup_archive_name(app)
    if final_zip.exists():
        raise RuntimeError('Final installer archive already exists.')
    run('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, final_zip, timeout=1200)
    receipt = {'setup': str(app), 'archive': str(final_zip), 'sha256': digest(final_zip),
               'bytes': final_zip.stat().st_size, 'notarized': True, 'notarizationSubmissionId': result['id'],
               'includesPhishLang': True, 'includesClamAV': True, 'includesDefinitions': True,
               'installedOnBuildHost': False}
    (app.parent / 'installer-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--vendor-package', type=Path, default=ROOT / 'build/clamav-downloads/clamav-1.5.4.macos.universal.pkg')
    parser.add_argument('--definitions', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=Path('/usr/local/clamav'))
    parser.add_argument('--source-archive', type=Path, default=ROOT / 'build/installer-inputs/clamav-1.5.4.tar.gz')
    parser.add_argument('--notices', type=Path, default=ROOT / 'build/installer-inputs/notices')
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    signing = parser.add_mutually_exclusive_group()
    signing.add_argument('--sign', action='store_true', help='Sign and notarize a standalone Setup archive.')
    signing.add_argument('--sign-for-package', action='store_true',
                         help='Sign only a nested Setup payload; the outer distribution package must be notarized.')
    parser.add_argument('--identity')
    parser.add_argument('--notary-profile')
    parser.add_argument('--notary-keychain', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('macOS is required to build this installer.')
    if args.sign and (not args.identity or not args.notary_profile):
        parser.error('Distribution requires an existing Developer ID Application identity and saved notary profile.')
    if args.sign_for_package and not args.identity:
        parser.error('A nested package payload requires an existing Developer ID Application identity.')
    if args.sign_for_package and (args.notary_profile or args.notary_keychain):
        parser.error('Use --sign for standalone notarization; --sign-for-package signs only the nested payload.')
    app = assemble(args)
    if args.sign:
        sign_and_notarize(app, args.identity, args.notary_profile, args.notary_keychain)
    elif args.sign_for_package:
        sign_for_package(app, args.identity)


if __name__ == '__main__':
    main()
