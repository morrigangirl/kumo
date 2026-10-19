#!/usr/bin/env python3
"""Prepare the pinned official Sparkle framework and release tools; never reads signing keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def digest(file):
    value = hashlib.sha256()
    with file.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def inventory(directory):
    result = {}
    for p in sorted(directory.rglob('*')):
        if p.name == 'preparation-receipt.json' and p.parent == directory:
            continue
        relative = str(p.relative_to(directory))
        if p.is_symlink():
            if not p.resolve().is_relative_to(directory.resolve()):
                raise RuntimeError('Sparkle contains an external symlink.')
            result[relative] = {'symlink': os.readlink(p)}
        elif p.is_file():
            if p.stat().st_nlink != 1:
                raise RuntimeError('Sparkle files must not be hard links.')
            result[relative] = {'sha256': digest(p), 'bytes': p.stat().st_size,
                                'executable': bool(p.stat().st_mode & stat.S_IXUSR)}
        elif not p.is_dir():
            raise RuntimeError('Unsupported Sparkle archive member.')
    return result


def verify_prepared(root=ROOT, destination=None):
    directory = destination or root / 'build/sparkle'
    if directory.is_symlink():
        raise RuntimeError('Sparkle preparation must be a real directory.')
    lock = json.loads((root / 'config/sparkle-lock.json').read_text())
    receipt = json.loads((directory / 'preparation-receipt.json').read_text())
    if receipt['version'] != lock['version'] or receipt['archiveSHA256'] != lock['archiveSHA256']:
        raise RuntimeError('Sparkle preparation does not match the lock.')
    if receipt['files'] != inventory(directory):
        raise RuntimeError('Prepared Sparkle files changed; prepare a fresh verified copy.')
    for file in ['Sparkle.framework/Sparkle', 'bin/sign_update', 'bin/generate_keys', 'bin/generate_appcast']:
        if not (directory / file).is_file():
            raise RuntimeError('Required Sparkle framework or tool is missing.')
    return receipt


def prepare(root=ROOT, destination=None):
    destination = destination or root / 'build/sparkle'
    if destination.exists() or destination.is_symlink():
        return verify_prepared(root, destination)
    lock = json.loads((root / 'config/sparkle-lock.json').read_text())
    expected_url = f"https://github.com/sparkle-project/Sparkle/releases/download/{lock['version']}/Sparkle-{lock['version']}.tar.xz"
    if lock.get('schema') != 1 or lock['archiveURL'] != expected_url:
        raise RuntimeError('Unsupported Sparkle dependency lock.')
    cache = root / '.cache/sparkle'
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"Sparkle-{lock['version']}.tar.xz"
    if not archive.exists() or archive.is_symlink() or digest(archive) != lock['archiveSHA256']:
        with tempfile.NamedTemporaryFile(dir=cache, prefix='download-', delete=False) as handle:
            partial = Path(handle.name)
            try:
                with urllib.request.urlopen(lock['archiveURL'], timeout=60) as response:
                    total = 0
                    while block := response.read(1024 * 1024):
                        total += len(block)
                        if total > lock['archiveBytes']:
                            raise RuntimeError('Sparkle download exceeds its pinned size.')
                        handle.write(block)
                handle.flush()
                if total != lock['archiveBytes'] or digest(partial) != lock['archiveSHA256']:
                    raise RuntimeError('Sparkle archive size or SHA-256 mismatch.')
                partial.replace(archive)
            finally:
                partial.unlink(missing_ok=True)
    if archive.stat().st_size != lock['archiveBytes']:
        raise RuntimeError('Sparkle cached archive size mismatch.')
    if not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Sparkle preparation requires Python with tarfile.data_filter (Python 3.12+).')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.sparkle-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'payload'
        stage.mkdir()
        with tarfile.open(archive, 'r:xz') as source:
            members = source.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 256 * 1024 * 1024:
                raise RuntimeError('Sparkle archive exceeds extraction bounds.')
            if any(not (m.isfile() or m.isdir() or m.issym()) for m in members):
                raise RuntimeError('Sparkle archive has an unsupported member type.')
            source.extractall(stage, members=members, filter='data')
        receipt = {'schema': 1, 'version': lock['version'], 'archiveSHA256': lock['archiveSHA256'],
                   'files': inventory(stage)}
        (stage / 'preparation-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        stage.rename(destination)
    return verify_prepared(root, destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    options = parser.parse_args()
    try:
        result = verify_prepared() if options.verify else prepare()
        print(json.dumps({'verified': True, 'version': result['version'], 'archiveSHA256': result['archiveSHA256']}))
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        parser.exit(1, f'Sparkle preparation failed: {error}\n')
