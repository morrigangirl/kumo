#!/usr/bin/env python3
"""Execute the pinned manifest root guards and namespace helpers offline.

The C++ predicates are extracted unchanged from Chromium. A minimal base::Value
container supplies the parsed XML dictionaries; ElementTree supplies those
dictionaries. This tests the actual root guards, not Chromium's XML decoder,
Mojo IPC, network transport, or extension installation.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'config/source-lock.json').is_file())
SOURCE = ROOT / 'build/source-155.0.8059.84/recipe/build/src'
SPEC = importlib.util.spec_from_file_location(
    'namespace_overlay', Path(__file__).with_name('extensions_overlay.py'))
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)
PRISTINE_SHA = '4f2bd8da7e79c5ae3f2c24b4bdb2ec7ddb54044c3701887adc3b2e9a851959ae'
OFFICIAL = 'http://www.google.com/update2/response'
SUBSTITUTED = 'http://www.9oo91e.qjz9zk/update2/response'

# Exact public XML returned by the one anonymous replay of the owned browser's
# native request on 2026-10-19. This is a historical response fixture.
OFFER = r'''<?xml version="1.0" encoding="UTF-8"?><gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod"><daystart elapsed_days="7231" elapsed_seconds="22009"/><app appid="ddkjiahejlhfcafbddmgiahcphecmpfh" cohort="1::" cohortname="" status="ok"><updatecheck _esbAllowlist="true" codebase="https://clients2.googleusercontent.com/crx/blobs/AZPVhcRYe4sOX4czxaaPxT3nVyfO8lRbp_p9e6Y4yNYVdUcK-wxqKE0sQaqlVLIxO-KTgEOdZK5Ktmf1qE00-EJKrCrTdK6bkMRrSn5_Znc34sd_N7JYlX6_7xlhYWKVHZUGAMZSmuUG6Xe5Tcl2Jcrk-dGTNkrFF2fBRg/DDKJIAHEJLHFCAFBDDMGIAHCPHECMPFH_2026_1018_2229_0.crx" fp="1.559d10ef7dcb96bc4e812de6b3ff0c2e6c7abca578324d8d7afd7d8cf78a6dd7" hash_sha256="559d10ef7dcb96bc4e812de6b3ff0c2e6c7abca578324d8d7afd7d8cf78a6dd7" protected="0" size="9145194" status="ok" version="2026.1018.2229"/></app></gupdate>'''


def function(text, name):
    start = re.search(r'^(?:bool|std::string) ' + re.escape(name) + r'\(', text, re.M)
    assert start, name
    opened = text.index('{', start.start())
    depth, end = 1, opened + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start.start():end]


def element(xml):
    # iterparse emits ('start-ns', (prefix, URI)), not (prefix, URI) directly.
    namespaces = dict(value for event, value in
                      ET.iterparse(io.StringIO(xml), events=['start-ns']))
    root = ET.fromstring(xml)
    if root.tag.startswith('{'):
        uri, local = root.tag[1:].split('}', 1)
        prefix = next(key for key, value in namespaces.items() if value == uri)
        tag = (prefix + ':' if prefix else '') + local
    else:
        tag = root.tag
    pairs = lambda values: '{' + ','.join(
        '{' + json.dumps(key) + ',' + json.dumps(value) + '}'
        for key, value in values.items()) + '}'
    return 'Element(' + json.dumps(tag) + ',' + pairs(namespaces) + ',' + pairs(root.attrib) + ')'


class StoreManifestNamespaceTests(unittest.TestCase):
    def sources(self):
        before = (SOURCE / overlay.PARSER_CC).read_text()
        old, new = overlay.PARSER_HOOKS[0]
        if new in before:
            before = before.replace(new, old, 1)
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(), PRISTINE_SHA)
        return before, overlay.transform(before, overlay.PARSER_HOOKS)

    def test_exact_constant_change_and_fail_closed_drift(self):
        before, after = self.sources()
        old, new = overlay.PARSER_HOOKS[0]
        self.assertEqual(after.replace(new, old, 1), before)
        self.assertEqual(len(overlay.PARSER_HOOKS), 1)
        self.assertEqual(overlay.EXPECTED_SHA256[overlay.PARSER_CC], PRISTINE_SHA)
        self.assertIn('GetXmlElementNamespacePrefix(root, kExpectedGupdateXmlns,', after)
        with self.assertRaisesRegex(RuntimeError, 'already applied'):
            overlay.transform(after, overlay.PARSER_HOOKS)
        for drift in (before.replace(old, '', 1), before + old):
            with self.assertRaisesRegex(RuntimeError, 'hook drift'):
                overlay.transform(drift, overlay.PARSER_HOOKS)

    def test_actual_root_guards_and_namespace_helpers(self):
        compiler = shutil.which('clang++') or shutil.which('c++')
        self.assertIsNotNone(compiler, 'A C++ compiler is required for this regression')
        before, after = self.sources()
        fixture_sha = hashlib.sha256(OFFER.encode()).hexdigest()
        self.assertEqual(fixture_sha, 'a884f628bbf37ab9bf0edd30d1422989a1e37a37be72c0dd8d912e290350682f')
        root = ET.fromstring(OFFER)
        ns = {'g': OFFICIAL}
        check = root.find('g:app/g:updatecheck', ns)
        self.assertEqual(check.get('version'), '2026.1018.2229')
        self.assertEqual(check.get('status'), 'ok')
        self.assertTrue(overlay.approved_url(check.get('codebase'), package=True))
        self.assertIsNone(check.get('prodversionmin'))
        helper_path = SOURCE / 'services/data_decoder/public/cpp/safe_xml_parser.cc'
        helpers = helper_path.read_text()
        bodies = '\n'.join(function(helpers, name) for name in [
            'GetXmlQualifiedName', 'IsXmlElementNamed',
            'GetXmlElementNamespacePrefix', 'GetXmlElementAttribute'])
        # Keep the actual root-validation branch byte-for-byte. Only the caller
        # and base container/expected types are supplied by this fixture.
        def guards(text, name):
            constants = text[text.index('constexpr char kExpectedGupdateProtocol'):text.index('// Helper function')]
            start = text.index('    // Look for the required namespace declaration.')
            end = text.index('\n    return root;', start)
            return ('namespace ' + name + ' {\n' + constants +
                    '\nbase::expected<base::Value, ManifestParseFailure> Validate(base::Value root) {\n'
                    'std::string gupdate_ns;\n' + text[start:end] +
                    '\nreturn root;\n}\n}\n')
        prefixed = re.sub(r'<(/?)(gupdate|daystart|app|updatecheck)\b', r'<\1g:\2', OFFER).replace('xmlns=', 'xmlns:g=', 1)
        cases = [
            (OFFER, 'NONE', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (prefixed, 'NONE', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (OFFER.replace(OFFICIAL, SUBSTITUTED), 'INVALID_XLMNS_ON_GUPDATE_TAG', 'NONE'),
            (OFFER.replace(OFFICIAL, 'https://attacker.invalid/update2/response'), 'INVALID_XLMNS_ON_GUPDATE_TAG', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (OFFER.replace(' xmlns="' + OFFICIAL + '"', ''), 'INVALID_XLMNS_ON_GUPDATE_TAG', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (OFFER.replace('<gupdate ', '<wrong ').replace('</gupdate>', '</wrong>'), 'MISSING_GUPDATE_TAG', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (OFFER.replace('protocol="2.0"', 'protocol="3.0"'), 'INVALID_PROTOCOL_ON_GUPDATE_TAG', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
            (OFFER.replace(' protocol="2.0"', ''), 'INVALID_PROTOCOL_ON_GUPDATE_TAG', 'INVALID_XLMNS_ON_GUPDATE_TAG'),
        ]
        calls = '\n'.join('Check(' + element(xml) + ',ManifestInvalidError::' + fixed +
                          ',ManifestInvalidError::' + baseline + ');'
                          for xml, fixed, baseline in cases)
        harness = r'''
#include <cassert>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
namespace base {
struct DictValue;
struct Value {
  std::variant<std::string, std::shared_ptr<DictValue>> value;
  Value(std::string text) : value(std::move(text)) {}
  Value(DictValue dict);
  bool is_dict() const { return std::holds_alternative<std::shared_ptr<DictValue>>(value); }
  const DictValue& GetDict() const { return *std::get<std::shared_ptr<DictValue>>(value); }
  const std::string& GetString() const { return std::get<std::string>(value); }
};
struct DictValue : std::map<std::string, Value> {
  const DictValue* FindDict(const std::string& key) const {
    auto it = find(key); return it != end() && it->second.is_dict() ? &it->second.GetDict() : nullptr;
  }
  const std::string* FindString(const std::string& key) const {
    auto it = find(key); return it != end() && !it->second.is_dict() ? &it->second.GetString() : nullptr;
  }
};
Value::Value(DictValue dict) : value(std::make_shared<DictValue>(std::move(dict))) {}
template<typename E> struct Unexpected { E error; };
template<typename E> Unexpected<E> unexpected(E error) { return {std::move(error)}; }
template<typename T, typename E> struct expected {
  std::optional<T> result; std::optional<E> error;
  expected(T value) : result(std::move(value)) {}
  expected(Unexpected<E> value) : error(std::move(value.error)) {}
};
}
namespace data_decoder {
namespace mojom { struct XmlParser {
  static constexpr const char* kTagKey = "tag";
  static constexpr const char* kNamespacesKey = "namespaces";
  static constexpr const char* kAttributesKey = "attributes";
}; }
__ACTUAL_HELPERS__
}
using data_decoder::GetXmlElementAttribute;
using data_decoder::GetXmlElementNamespacePrefix;
using data_decoder::GetXmlQualifiedName;
using data_decoder::IsXmlElementNamed;
enum class ManifestInvalidError { NONE, INVALID_XLMNS_ON_GUPDATE_TAG, MISSING_GUPDATE_TAG, INVALID_PROTOCOL_ON_GUPDATE_TAG };
struct ManifestParseFailure {
  std::string detail; ManifestInvalidError error;
  ManifestParseFailure(std::string message, ManifestInvalidError code) : detail(std::move(message)), error(code) {}
};
__ACTUAL_BASELINE_GUARDS__
__ACTUAL_PATCHED_GUARDS__
base::Value Element(std::string tag, std::map<std::string,std::string> namespaces, std::map<std::string,std::string> attributes) {
  base::DictValue ns, attrs, root;
  for (auto& [key,value] : namespaces) ns.emplace(key, base::Value(value));
  for (auto& [key,value] : attributes) attrs.emplace(key, base::Value(value));
  root.emplace("tag",base::Value(std::move(tag)));
  root.emplace("namespaces",base::Value(std::move(ns)));
  root.emplace("attributes",base::Value(std::move(attrs)));
  return base::Value(std::move(root));
}
void Check(base::Value root, ManifestInvalidError fixed, ManifestInvalidError old) {
  auto fixed_result = patched::Validate(root), baseline_result = baseline::Validate(root);
  assert((fixed_result.error ? fixed_result.error->error : ManifestInvalidError::NONE) == fixed);
  assert((baseline_result.error ? baseline_result.error->error : ManifestInvalidError::NONE) == old);
}
int main() {
__CASES__
}
'''.replace('__ACTUAL_HELPERS__', bodies).replace(
            '__ACTUAL_BASELINE_GUARDS__', guards(before, 'baseline')).replace(
            '__ACTUAL_PATCHED_GUARDS__', guards(after, 'patched')).replace('__CASES__', calls)
        with tempfile.TemporaryDirectory(prefix='kumo-manifest-namespace-test-') as folder:
            cpp, binary = Path(folder) / 'actual-root-guards.cc', Path(folder) / 'actual-root-guards'
            cpp.write_text(harness)
            command = [compiler, '-std=c++20', str(cpp), '-o', str(binary)]
            if shutil.which('xcrun'):
                sdk = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
                command.extend(['-isysroot', sdk])
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
