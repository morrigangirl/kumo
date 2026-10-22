#!/usr/bin/env python3
"""Compile shipping native policy and run the actual isolated-world sampler.

All inputs are synthetic. Does not launch a browser, read profiles, or load a model.
Chromium-specific integration translation units are checked separately with the
verified source target's compiler and headers before its normal build.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROTECTION = ROOT / 'native/browser/protection'


class NativeProtectionPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kumo-native-policy-')
        cls.directory = Path(cls.temporary.name)
        include = cls.directory / 'chrome/browser/kumo'
        include.mkdir(parents=True)
        (include / 'protection').symlink_to(PROTECTION, target_is_directory=True)
        fixture = cls.directory / 'fixture.cc'
        fixture.write_text(r'''
#include <cassert>
#include <string>
#include "chrome/browser/kumo/protection/protection_policy.h"
using namespace kumo::protection;
int main() {
  assert(ResolveEnabled(std::nullopt, std::nullopt));
  assert(!ResolveEnabled(std::nullopt, false));
  assert(ResolveEnabled(std::nullopt, true));
  assert(!ResolveEnabled(false, true));
  assert(ResolveEnabled(true, false));
  for (const auto* good : {"example.com", "a-b.example", "xn--bcher-kva.de"}) assert(ValidDomain(good));
  for (const auto* bad : {"EXAMPLE.com", "example.com.", "a..com", ".com", "a.123", "1.2.3.4", "a/b.com", "-a.com", "a-.com", "a.com\n", "a.com:443", "user@a.com"}) assert(!ValidDomain(bad));
  std::set<std::string, std::less<>> list{"example.com", "other.test"};
  assert(ListedDomain(list, "example.com")); assert(ListedDomain(list, "a.b.example.com"));
  assert(ListedDomain(list, "example.com."));
  assert(!ListedDomain(list, "badexample.com")); assert(!ListedDomain(list, "example.com.attacker.test"));
  const std::string header = "# Title: Threat Intelligence Feeds mini version\n# Homepage: https://github.com/hagezi/dns-blocklists\n# License: https://github.com/hagezi/dns-blocklists/blob/main/LICENSE\n# Syntax: Domains (without subdomains)\n# Expires: 8 hours\n# Version: 2026.1021.1200.1\n# Last modified: 21 Oct 2026 12:00 UTC\n# Number of entries: 2\n";
  const std::string valid = header + "one.example\ntwo.example\n";
  auto parsed = ParseDomainFeed(valid, 2); assert(parsed && parsed->domains.size() == 2);
  assert(parsed->version == "2026.1021.1200.1");
  assert(!ParseDomainFeed(valid, 3));
  assert(!ParseDomainFeed(header + "one.example\none.example\n", 1));
  assert(!ParseDomainFeed(header + "one.example\n", 1));
  assert(!ParseDomainFeed(valid + "# Late: header\n", 1));
  assert(!ParseDomainFeed("# Homepage: https://attacker.example/\n" + valid, 1));
  assert(!ParseDomainFeed(header + "one.example\nTWO.example\n", 1));
  assert(!ParseDomainFeed(header + "one.example\ntwo.example\r\n", 1));
  assert(!ParseDomainFeed(std::string(kMaximumFeedBytes + 1, 'x'), 1));
}
''')
        cls.executable = cls.directory / 'policy-fixture'
        compiler = shutil.which('clang++') or shutil.which('c++')
        if not compiler:
            raise unittest.SkipTest('C++ compiler unavailable')
        subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                        '-I', str(cls.directory), str(PROTECTION / 'protection_policy.cc'),
                        str(fixture), '-o', str(cls.executable)], check=True, capture_output=True, timeout=90)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_shipping_domain_parser_suffix_boundary_and_optout_policy(self):
        subprocess.run([str(self.executable)], check=True, capture_output=True, timeout=15)

    def test_actual_native_sampler_privacy_revision_and_bounds(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node test runner unavailable')
        subprocess.run([node, '--test', str(PROTECTION / 'tests/sampler.test.mjs')],
                       check=True, capture_output=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
