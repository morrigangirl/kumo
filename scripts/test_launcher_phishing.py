#!/usr/bin/env python3
"""Compile the production retirement helper; never register a product extension."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
LEGACY=['com.kumo.agent_bridge.json','com.kumo.phishing.json','com.kumo.malware.json']


class LegacyHostRetirement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='kumo-retired-hosts-',dir='/private/tmp');cls.directory=Path(cls.temp.name).resolve()
        prefix,separator,_=(ROOT/'native/launcher/main.swift').read_text().partition('\nfunc run() throws')
        if not separator:raise AssertionError('Production launcher boundary missing')
        source=cls.directory/'retire.swift';source.write_text(prefix+r'''
do {
    try retireLegacyHosts(URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true))
} catch { fputs("retire-test: \(error.localizedDescription)\n", stderr); exit(1) }
''')
        cls.helper=cls.directory/'retire'
        r=subprocess.run(['swiftc','-O','-module-cache-path',str(cls.directory/'modules'),str(source),'-o',str(cls.helper),'-framework','AppKit'],capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stderr)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.temp_case=tempfile.TemporaryDirectory(dir=self.directory,prefix='case-');self.addCleanup(self.temp_case.cleanup);self.base=Path(self.temp_case.name);self.hosts=self.base/'owned profile/NativeMessagingHosts';self.hosts.mkdir(parents=True,mode=0o700)
    def invoke(self,hosts=None):return subprocess.run([str(self.helper),str(hosts or self.hosts)],capture_output=True,text=True,timeout=15)
    def test_exact_three_legacy_ids_are_retired_and_custom_hosts_survive(self):
        for name in LEGACY:(self.hosts/name).write_bytes(b'old registration')
        custom=self.hosts/'com.owner.passwords.json';custom.write_bytes(b'CUSTOM PLUGIN')
        other=self.hosts/'com.kumo.phishing.json.backup';other.write_bytes(b'OWNER BACKUP')
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr);self.assertEqual({p.name for p in self.hosts.iterdir()},{custom.name,other.name});self.assertEqual(custom.read_bytes(),b'CUSTOM PLUGIN');self.assertEqual(other.read_bytes(),b'OWNER BACKUP');self.assertEqual(self.invoke().returncode,0)
    def test_legacy_symlinks_are_unlinked_without_following_or_altering_targets(self):
        target=self.base/'private target';target.write_bytes(b'PRESERVE')
        for name in LEGACY:(self.hosts/name).symlink_to(target)
        self.assertEqual(self.invoke().returncode,0);self.assertEqual(target.read_bytes(),b'PRESERVE');self.assertFalse(any(os.path.lexists(self.hosts/name) for name in LEGACY))
    def test_legacy_hardlink_unlink_preserves_original_bytes(self):
        target=self.base/'original';target.write_bytes(b'PRESERVE');os.link(target,self.hosts/LEGACY[0]);self.assertEqual(self.invoke().returncode,0);self.assertEqual(target.read_bytes(),b'PRESERVE');self.assertEqual(target.stat().st_nlink,1)
    def test_directory_at_a_legacy_id_is_rejected_without_recursive_deletion(self):
        entry=self.hosts/LEGACY[0];entry.mkdir();(entry/'preserve').write_bytes(b'DO NOT DELETE');result=self.invoke();self.assertEqual(result.returncode,1);self.assertIn('removed safely',result.stderr);self.assertEqual((entry/'preserve').read_bytes(),b'DO NOT DELETE')
    def test_symlinked_profile_ancestor_is_rejected_without_touching_external_data(self):
        external=self.base/'outside';external.mkdir();(external/LEGACY[0]).write_bytes(b'PRESERVE');linked=self.base/'linked';linked.symlink_to(external,target_is_directory=True);result=self.invoke(linked);self.assertEqual(result.returncode,1);self.assertEqual((external/LEGACY[0]).read_bytes(),b'PRESERVE')
    def test_group_writable_profile_parent_is_rejected(self):
        self.hosts.parent.chmod(0o777);result=self.invoke();self.assertEqual(result.returncode,1);self.assertIn('Unsafe parent',result.stderr)


if __name__=='__main__':unittest.main(verbosity=2)
