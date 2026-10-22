"""Synthetic archive/payload safety checks. Never executes or downloads Node."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('kumo_agent_runtime', ROOT / 'scripts/prepare-agent-runtime.py')
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)


class RuntimePreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.lock = runtime.load_lock()
        self.node = b'synthetic non-executable Node fixture'; self.license = b'Complete synthetic license.'
        self.lock['nodeSHA256'] = hashlib.sha256(self.node).hexdigest()
        self.lock['licenseSHA256'] = hashlib.sha256(self.license).hexdigest()

    def archive(self, extras=(), linked=False):
        p = self.root / 'fixture.tar.gz'
        prefix = f"node-v{self.lock['version']}-darwin-arm64/"
        with tarfile.open(p, 'w:gz') as target:
            for name, data in [('bin/node', self.node), ('LICENSE', self.license)]:
                entry = tarfile.TarInfo(prefix + name)
                if linked and name == 'bin/node': entry.type = tarfile.SYMTYPE; entry.linkname = '/external/node'; target.addfile(entry)
                else: entry.size = len(data); target.addfile(entry, io.BytesIO(data))
            for name in extras:
                entry = tarfile.TarInfo(name); entry.size = 1; target.addfile(entry, io.BytesIO(b'x'))
        raw = p.read_bytes(); self.lock['archiveBytes'] = len(raw); self.lock['archiveSHA256'] = hashlib.sha256(raw).hexdigest()
        return p

    def test_exact_payload_retains_complete_license_and_no_unneeded_packages(self):
        archive = self.archive(); output = self.root / 'payload'; runtime.prepare(output, archive, self.lock)
        self.assertEqual(runtime.verify_payload(output, self.lock), self.lock)
        self.assertEqual((output / 'LICENSE.node').read_bytes(), self.license)
        self.assertEqual({str(p.relative_to(output)) for p in output.rglob('*')}, {'bin', 'bin/node', 'LICENSE.node', 'runtime.json'})

    def test_archive_hash_size_and_selected_file_hash_tampering_rejected(self):
        p = self.archive()
        for key, value in [('archiveSHA256', '0' * 64), ('archiveBytes', 1), ('nodeSHA256', '1' * 64), ('licenseSHA256', '2' * 64)]:
            lock = dict(self.lock, **{key: value})
            with self.subTest(key=key), self.assertRaises(RuntimeError): runtime.archive_payload(p, lock)

    def test_traversal_or_unexpected_root_and_linked_binary_rejected(self):
        for extra in ['../escape', '/absolute', 'wrong-root/data']:
            with self.subTest(extra=extra), self.assertRaises(RuntimeError): runtime.archive_payload(self.archive([extra]), self.lock)
        with self.assertRaises(RuntimeError): runtime.archive_payload(self.archive(linked=True), self.lock)

    def test_existing_output_and_indirect_archive_rejected_without_overwrite(self):
        p = self.archive(); output = self.root / 'output'; output.mkdir(); (output / 'preserve').write_text('owned')
        with self.assertRaises(RuntimeError): runtime.prepare(output, p, self.lock)
        self.assertEqual((output / 'preserve').read_text(), 'owned')
        link = self.root / 'archive-link'; link.symlink_to(p)
        with self.assertRaises(RuntimeError): runtime.archive_payload(link, self.lock)

    def test_payload_mutation_addition_and_hardlink_rejected(self):
        output = self.root / 'payload'; runtime.prepare(output, self.archive(), self.lock)
        (output / 'extra').write_text('unexpected')
        with self.assertRaises(RuntimeError): runtime.verify_payload(output, self.lock)
        (output / 'extra').unlink(); (output / 'bin/node').write_bytes(b'changed')
        with self.assertRaises(RuntimeError): runtime.verify_payload(output, self.lock)

    def test_lock_forbids_arbitrary_urls_wrong_architecture_and_jit(self):
        for changes in [{'archiveURL': 'https://example.org/node.tgz'}, {'architecture': 'x64'}, {'executionArgs': []}, {'version': '20.0.0'}]:
            p = self.root / 'lock.json'; p.write_text(json.dumps(dict(self.lock, **changes)))
            with self.subTest(changes=changes), self.assertRaises(RuntimeError): runtime.load_lock(p)


if __name__ == '__main__': unittest.main(verbosity=2)
