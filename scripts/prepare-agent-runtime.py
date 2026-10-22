#!/usr/bin/env python3
"""Prepare the pinned private Node runtime. Never installs globally or executes Node."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'config/node-runtime-lock.json'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def load_lock(path=LOCK):
    value = json.loads(Path(path).read_bytes())
    version = value.get('version', '')
    require(value.get('schemaVersion') == 1 and re.fullmatch(r'22\.\d+\.\d+', version), 'Unsupported pinned Node runtime.')
    name = f'node-v{version}-darwin-arm64.tar.gz'
    require(value.get('platform') == 'darwin' and value.get('architecture') == 'arm64' and
            value.get('archiveName') == name and value.get('archiveURL') == f'https://nodejs.org/dist/v{version}/{name}', 'Node runtime must use the exact official Apple Silicon release URL.')
    for key in ('archiveSHA256', 'nodeSHA256', 'licenseSHA256'):
        require(isinstance(value.get(key), str) and re.fullmatch('[0-9a-f]{64}', value[key]), 'Invalid pinned runtime hash.')
    require(type(value.get('archiveBytes')) is int and 0 < value['archiveBytes'] <= 100 * 1024 * 1024, 'Invalid runtime archive size.')
    require(value.get('executionArgs') == ['--jitless', '--no-expose-wasm'], 'Runtime must disable JIT and WebAssembly.')
    return value


def archive_payload(archive, lock):
    archive = Path(archive)
    require(archive.is_file() and not archive.is_symlink(), 'Runtime archive must be a regular file.')
    raw = archive.read_bytes()
    require(len(raw) == lock['archiveBytes'] and checksum(raw) == lock['archiveSHA256'], 'Node archive checksum or size differs.')
    prefix = f"node-v{lock['version']}-darwin-arm64"
    selected = {prefix + '/bin/node': 'bin/node', prefix + '/LICENSE': 'LICENSE.node'}
    result = {}
    with tarfile.open(archive, 'r:gz') as source:
        count = 0
        for member in source:
            count += 1
            parts = PurePosixPath(member.name).parts
            require(count <= 20000 and parts and parts[0] == prefix and not PurePosixPath(member.name).is_absolute() and '..' not in parts, 'Unsafe Node archive path or member count.')
            if member.name not in selected:
                continue
            name = selected[member.name]
            require(name not in result and member.isfile() and member.size <= (200 * 1024 * 1024 if name == 'bin/node' else 2 * 1024 * 1024), 'Invalid selected runtime member.')
            result[name] = source.extractfile(member).read()
    require(set(result) == {'bin/node', 'LICENSE.node'}, 'Runtime archive lacks the required executable or complete license.')
    require(checksum(result['bin/node']) == lock['nodeSHA256'] and checksum(result['LICENSE.node']) == lock['licenseSHA256'], 'Extracted Node runtime or license differs.')
    return result


def verify_payload(directory, lock=None):
    lock = lock or load_lock()
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'Runtime payload directory is indirect.')
    require({str(p.relative_to(directory)) for p in directory.rglob('*')} == {'bin', 'bin/node', 'LICENSE.node', 'runtime.json'}, 'Unexpected runtime payload member.')
    for name in ('bin/node', 'LICENSE.node', 'runtime.json'):
        p = directory / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1, 'Runtime payload must contain direct regular files.')
    manifest = json.loads((directory / 'runtime.json').read_bytes())
    require(manifest == lock, 'Runtime manifest differs from its lock.')
    require(checksum((directory / 'bin/node').read_bytes()) == lock['nodeSHA256'] and checksum((directory / 'LICENSE.node').read_bytes()) == lock['licenseSHA256'], 'Runtime payload checksum differs.')
    return manifest


def prepare(output, archive=None, lock=None):
    lock = lock or load_lock()
    output = Path(output).absolute()
    require(not os.path.lexists(output) and output.parent.is_dir(), 'Choose a fresh runtime output directory with an existing parent.')
    with tempfile.TemporaryDirectory(prefix='.kumo-node-', dir=output.parent) as temporary:
        temporary = Path(temporary)
        if archive is None:
            archive = temporary / lock['archiveName']
            request = urllib.request.Request(lock['archiveURL'], headers={'User-Agent': 'Kumo-runtime-preparation/1', 'Accept-Encoding': 'identity'})
            with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as target:
                require(response.url == lock['archiveURL'], 'Runtime download redirected outside the pinned URL.')
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    require(total <= lock['archiveBytes'], 'Runtime download exceeds its pinned size.')
                    target.write(chunk)
        values = archive_payload(archive, lock)
        staged = temporary / 'payload'; (staged / 'bin').mkdir(parents=True)
        for name, data in values.items():
            p = staged / name; p.write_bytes(data); p.chmod(0o755 if name == 'bin/node' else 0o644)
        (staged / 'runtime.json').write_text(json.dumps(lock, indent=2) + '\n')
        verify_payload(staged, lock)
        # No overwrites: the destination must still be absent at publication.
        require(not os.path.lexists(output), 'Runtime output appeared during preparation.')
        staged.rename(output)
    return verify_payload(output, lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/agent-runtime')
    parser.add_argument('--archive', type=Path, help='Already-downloaded exact pinned archive')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    value = verify_payload(args.output) if args.verify else prepare(args.output, args.archive)
    print(json.dumps({'verified': True, 'version': value['version'], 'output': str(args.output), 'executed': False}))


if __name__ == '__main__':
    main()
