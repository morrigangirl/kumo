#!/usr/bin/env python3
"""Offline policy/rewriter fixtures. These do not prove a native CRX update install."""
import hashlib
import importlib.util
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT_ROOT = next((parent for parent in Path(__file__).resolve().parents
                     if (parent / "config/source-lock.json").is_file()),
                    Path(__file__).resolve().parents[1])
LOCKED_SOURCE = PROJECT_ROOT / "build/source-155.0.8059.84/recipe/build/src"

SPEC = importlib.util.spec_from_file_location("extensions_overlay", Path(__file__).with_name("extensions_overlay.py"))
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


class ExtensionOverlayFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="extension-overlay-test-")
        self.src = Path(self.temporary.name)
        self.inputs = {
            overlay.CC: "\n\n".join(old for old, new in overlay.CC_HOOKS),
            overlay.HEADER: "\n\n".join(old for old, new in overlay.HEADER_HOOKS),
            overlay.PERMISSIONS_CC: "\n\n".join(old for old, new in overlay.PERMISSIONS_HOOKS),
            overlay.PARSER_CC: "\n\n".join(old for old, new in overlay.PARSER_HOOKS),
        }
        self.inputs.update({rel: "\n\n".join(old for old, new in hooks)
                            for rel, hooks in overlay.NAVIGATION_HOOKS.items()})
        for rel, text in self.inputs.items():
            self.put(rel, text)
        self.put("chrome/VERSION", "MAJOR=155\nMINOR=0\nBUILD=8059\nPATCH=84\n")
        self.put("extensions/common/extension_urls.cc", "global Store classifier stays disabled\n")
        self.put("components/update_client/update_checker.cc", "component checks stay disabled\n")
        hashes = {rel: overlay.digest(text) for rel, text in self.inputs.items()}
        self.patch = mock.patch.object(overlay, "EXPECTED_SHA256", hashes)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def put(self, rel, text):
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def transformed(self):
        overlay.apply_overlay(self.src)
        return (self.src / overlay.CC).read_text(), (self.src / overlay.HEADER).read_text()

    def test_strict_endpoint_policy_matrix(self):
        root = "https://clients2.google.com/service/update2/crx"
        accepted = [root, root + "?x=id%3Dabc%26v%3D1%26uc", "https://CLIENTS2.GOOGLE.COM:443/service/update2/crx"]
        rejected = [root.replace("https:", "http:"), root + "#", root + "#fragment",
            root + "/", root.replace("/service/", "/Service/"),
            root.replace("clients2.google.com", "clients2.google.com.attacker.invalid"),
            root.replace("clients2.google.com", "other.clients2.google.com"),
            root.replace("clients2.google.com", "clients2.google.com."),
            root.replace("clients2.google.com", "user@clients2.google.com"),
            root.replace("clients2.google.com", "@clients2.google.com"),
            root.replace("clients2.google.com", "user:secret@clients2.google.com"),
            root.replace("clients2.google.com", "clients2.google.com:444"),
            root.replace("clients2.google.com", "clients2.google.com:notaport"),
            "file:///service/update2/crx", "data:text/plain,hello", "", "not a URL"]
        for url in accepted:
            with self.subTest(url=url):
                self.assertTrue(overlay.approved_url(url))
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(overlay.approved_url(url))

    def test_strict_cdn_policy_matrix(self):
        root = "https://clients2.googleusercontent.com/crx/blobs/package.crx"
        self.assertTrue(overlay.approved_url(root, package=True))
        self.assertTrue(overlay.approved_url(root + "?download=1", package=True))
        for url in (root.replace("https:", "http:"), root + "#fragment",
                    root.replace("/crx/blobs/", "/other/"),
                    root.replace("clients2.googleusercontent.com", "evil.clients2.googleusercontent.com"),
                    root.replace("clients2.googleusercontent.com", "clients2.googleusercontent.com:444"),
                    root.replace("clients2.googleusercontent.com", "user@clients2.googleusercontent.com")):
            with self.subTest(url=url):
                self.assertFalse(overlay.approved_url(url, package=True))

    def test_predicate_accessors_exist_in_locked_gurl_header(self):
        # Bind the shim's external API assumptions to the actual pinned source
        # when available; predicate compilation still does not test URL parsing.
        header = LOCKED_SOURCE / "url/gurl.h"
        if not header.is_file():
            self.skipTest("The locked Chromium GURL header is unavailable")
        api = header.read_text()
        methods = set(re.findall(r"\burl\.([A-Za-z_]\w*)\(", overlay.HELPERS))
        self.assertTrue(methods)
        for method in methods:
            with self.subTest(method=method):
                self.assertRegex(api, rf"\b{re.escape(method)}\s*\(")

    def test_native_predicate_runs_on_parsed_url_components(self):
        compiler = shutil.which("clang++") or shutil.which("c++")
        if not compiler:
            self.skipTest("A C++ compiler is unavailable for the standalone predicate fixture")
        # Execute the actual generated C++ predicates, using a parsed-component
        # GURL shim. This verifies predicate logic, not Chromium URL parsing.
        harness = r'''
#include <cassert>
#include <string>
#include <string_view>
namespace url { constexpr const char* kHttpsScheme = "https"; }
namespace base {
bool StartsWith(std::string_view text, std::string_view prefix) {
  return text.starts_with(prefix);
}
}
struct GURL {
  bool valid = true;
  std::string scheme = "https";
  std::string host_value = "clients2.google.com";
  std::string path_value = "/service/update2/crx";
  bool username = false, password = false, fragment = false, query = false;
  int port = 443;
  bool is_valid() const { return valid; }
  bool SchemeIs(const char* value) const { return scheme == value; }
  bool has_username() const { return username; }
  bool has_password() const { return password; }
  bool has_ref() const { return fragment; }
  bool has_query() const { return query; }
  int EffectiveIntPort() const { return port; }
  std::string_view host() const { return host_value; }
  std::string_view path() const { return path_value; }
};
namespace mojom {
enum class ManifestLocation { kInternal, kUnpacked, kExternalPolicy, kComponent };
}
struct Manifest { enum class Type { kUnknown, kExtension, kTheme }; };
struct ExtensionDownloaderTask {
  mojom::ManifestLocation install_location = mojom::ManifestLocation::kInternal;
  Manifest::Type type = Manifest::Type::kExtension;
  GURL update_url;
};
''' + overlay.HELPERS + r'''
int main() {
  GURL good;
  assert(IsKumoStoreUpdateUrl(good));
  for (int mode = 0; mode < 9; ++mode) {
    GURL bad = good;
    switch (mode) {
      case 0: bad.valid = false; break;
      case 1: bad.scheme = "http"; break;
      case 2: bad.username = true; break;
      case 3: bad.password = true; break;
      case 4: bad.fragment = true; break;
      case 5: bad.port = 444; break;
      case 6: bad.host_value = "clients2.google.com.attacker.invalid"; break;
      case 7: bad.host_value = "other.clients2.google.com"; break;
      case 8: bad.path_value += "/"; break;
    }
    assert(!IsKumoStoreUpdateUrl(bad));
  }
  GURL package = good;
  package.host_value = "clients2.googleusercontent.com";
  package.path_value = "/crx/blobs/package.crx";
  assert(IsKumoStoreCrxUrl(package));
  assert(!IsKumoStoreUpdateUrl(package));
  package.path_value = "/other/package.crx";
  assert(!IsKumoStoreCrxUrl(package));
  ExtensionDownloaderTask task;
  assert(IsKumoStoreTask(task));
  task.update_url.query = true;
  assert(IsKumoStoreUpdateUrl(task.update_url));
  assert(!IsKumoStoreTask(task));
  task.update_url.query = false;
  assert(IsKumoStoreTask(task));
  package.path_value = "/crx/blobs/package.crx";
  package.query = true;
  assert(IsKumoStoreCrxUrl(package));
  task.type = Manifest::Type::kTheme;
  assert(IsKumoStoreTask(task));
  task.type = Manifest::Type::kUnknown;
  assert(!IsKumoStoreTask(task));
  task.type = Manifest::Type::kExtension;
  for (auto loc : {mojom::ManifestLocation::kUnpacked,
                   mojom::ManifestLocation::kExternalPolicy,
                   mojom::ManifestLocation::kComponent}) {
    task.install_location = loc;
    assert(!IsKumoStoreTask(task));
  }
}
'''
        source = self.src / "predicate.cc"
        executable = self.src / "predicate"
        source.write_text(harness)
        command = [compiler, "-std=c++20", str(source), "-o", str(executable)]
        if shutil.which("xcrun"):
            sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            command.extend(["-isysroot", sdk])
        built = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(built.returncode, 0, built.stderr)
        subprocess.run([str(executable)], check=True)

    def test_overlay_keeps_global_services_untouched(self):
        untouched = {p: p.read_bytes() for p in (self.src / "extensions/common/extension_urls.cc",
                                                self.src / "components/update_client/update_checker.cc")}
        result = overlay.apply_overlay(self.src)
        self.assertEqual(set(result), {overlay.CC, overlay.HEADER, overlay.PERMISSIONS_CC, overlay.PARSER_CC, *overlay.NAVIGATION_HOOKS})
        for path, before in untouched.items():
            self.assertEqual(path.read_bytes(), before)

    def test_gate_provenance_failure_completion_and_publisher_proof_hooks(self):
        cc, header = self.transformed()
        self.assertIn("if (IsKumoStoreTask(task)) {\n      AddToFetches", cc)
        self.assertIn("rejected_tasks.push_back(std::move(task))", cc)
        self.assertIn("{task.id}, {task.request_id}", cc)
        self.assertIn("ExtensionDownloaderDelegate::Error::DISABLED", cc)
        self.assertIn("const bool is_kumo_store_update;", header)
        self.assertIn("is_kumo_store_update(IsKumoStoreTask(task))", cc)
        proof = "fetch_data->is_kumo_store_update\n          ? GetWebstoreVerifierFormat(false)"
        self.assertIn(proof, cc)
        self.assertNotIn("extension_urls::IsWebstoreUpdateUrl(fetch_data->url)", cc)
        self.assertIn("!IsKumoStoreCrxUrl(fetch_data->url)", cc)

    def test_credentials_redirects_retries_and_ping_hooks(self):
        cc, header = self.transformed()
        self.assertIn("if (IsKumoStoreUpdateUrl(active_request->base_url())) {", cc)
        self.assertEqual(cc.count("network::mojom::CredentialsMode::kOmit;"), 2)
        self.assertEqual(cc.count("network::mojom::RedirectMode::kError;"), 2)
        self.assertIn("if (fetch->is_kumo_store_update)\n    return false;", cc)
        self.assertIn("if (!fetch->is_kumo_store_update &&", cc)
        self.assertNotIn("ping_mode = ManifestFetchData::PING_WITH_ENABLED_STATE", cc)
        self.assertIn("ManifestFetchData::PingMode ping_mode = ManifestFetchData::NO_PING;", cc)
        self.assertIn("task.update_url_data.clear();", cc)

    def test_store_navigation_preserves_explicit_click_and_theme_policy(self):
        self.transformed()
        appearance = (self.src / "chrome/browser/resources/settings/appearance_page/appearance_page.ts").read_text()
        template = (self.src / "chrome/browser/resources/settings/appearance_page/appearance_page.html.ts").read_text()
        sidebar = (self.src / "chrome/browser/resources/extensions/sidebar.ts").read_text()
        self.assertIn('?hidden="${!this.pageVisibility_.setTheme}"', template)
        self.assertIn('@click="${this.onThemeClick_}"', template)
        self.assertIn("https://chromewebstore.google.com/detail/", appearance)
        self.assertIn("https://chromewebstore.google.com/category/extensions", sidebar)
        self.assertNotIn("utm_", sidebar)
        self.assertNotIn("fetch(", appearance + sidebar)
        # Execute the generated click handler against allowed and forced/default
        # theme states. Navigation must require a click and use noopener.
        node = shutil.which("node")
        if not node:
            self.skipTest("Node is unavailable for the user-click behavior fixture")
        method = re.search(r"  protected onThemeClick_\(\) \{(.*?)\n  \}", appearance, re.S)
        self.assertIsNotNone(method)
        import json
        harness = """
const assert = require('node:assert/strict');
const calls = [];
global.window = {open: (...args) => calls.push(['open', ...args])};
const click = new Function(BODY);
const store = 'https://chromewebstore.google.com/detail/abcdefghijklmnopabcdefghijklmnop';
for (const [url, forced, expected] of [[store, false, 'open'], ['', false, 'customize'], [store, true, 'customize']]) {
  calls.length = 0;
  const state = {themeUrl_: url, isForcedTheme_: forced,
    appearanceBrowserProxy_: {openCustomizeChrome: () => calls.push(['customize'])}};
  assert.equal(calls.length, 0);
  click.call(state);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], expected);
  if (expected === 'open') assert.deepEqual(calls[0], ['open', store, '_blank', 'noopener']);
}
""".replace("BODY", json.dumps(method.group(1)))
        subprocess.run([node, "-e", harness], check=True)

    def bundled_reload_sources(self):
        rel = 'chrome/browser/resources/extensions/service.ts'
        path = LOCKED_SOURCE / rel
        if not path.is_file():
            self.skipTest('The locked Chromium Extensions service source is unavailable')
        before = path.read_text()
        old, new = overlay.NAVIGATION_HOOKS[rel][0]
        if new in before:
            before = before.replace(new, old, 1)
        # setUp patches hashes for synthetic fixtures; bind this real file to
        # its separately pinned post-domain baseline rather than those shims.
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(),
                         '63bcf00f0281e0b0ac8c4269102ae8ca5c35e776b6822ece5f622269e9236899')
        return rel, before, overlay.transform(before, overlay.NAVIGATION_HOOKS[rel])

    def test_bundled_helper_reload_is_one_exact_filter_change_and_refuses_replay(self):
        rel, before, after = self.bundled_reload_sources()
        old, new = overlay.NAVIGATION_HOOKS[rel][0]
        self.assertEqual(after.replace(new, old, 1), before)
        self.assertEqual(after.count(overlay.MARKER), 1)
        self.assertEqual(before.count('chrome.developerPrivate.autoUpdate()'), 1)
        self.assertEqual(after.count('chrome.developerPrivate.autoUpdate()'), 1)
        self.assertEqual(before.count('await this.reloadItem(extension.id)'), 1)
        self.assertEqual(after.count('await this.reloadItem(extension.id)'), 1)
        helper_id = re.search(r"ext.id !== '([a-p]{32})'", new).group(1)
        self.assertIn('extension_id_ == "' + helper_id + '"', overlay.SCRIPT_GUARD)
        import base64
        import json
        manifest = json.loads((PROJECT_ROOT / 'extension/manifest.json').read_text())
        key_hash = hashlib.sha256(base64.b64decode(manifest['key'], validate=True)).hexdigest()[:32]
        self.assertEqual(helper_id, ''.join(chr(ord('a') + int(c, 16)) for c in key_hash))
        with self.assertRaisesRegex(RuntimeError, 'already applied'):
            overlay.transform(after, overlay.NAVIGATION_HOOKS[rel])
        for drift in (before.replace(old, '', 1), before + old):
            with self.assertRaisesRegex(RuntimeError, 'hook drift'):
                overlay.transform(drift, overlay.NAVIGATION_HOOKS[rel])

    def test_actual_update_method_retains_native_check_and_ordinary_reload_behavior(self):
        _rel, _before, after = self.bundled_reload_sources()
        node = shutil.which('node')
        if not node:
            self.skipTest('Node is unavailable for the actual service-method fixture')
        start = after.index('  updateAllExtensions(')
        opened = after.index('{', start)
        depth, end = 1, opened + 1
        while depth:
            depth += (after[end] == '{') - (after[end] == '}')
            end += 1
        # Only this TypeScript generic requires erasure; the actual transformed
        # method body, native-check ordering and reload loop are otherwise used.
        body = after[opened + 1:end - 1].replace('new Promise<void>', 'new Promise')
        import json
        harness = r'''
const assert = require('node:assert/strict');
const update = new Function('extensions', BODY);
const helper = 'eldkgppmnhligdekahicdcdndcoongio';
const rows = Object.freeze([
  {id: helper, location: 'UNPACKED', state: 'ENABLED'},
  {id: helper, location: 'UNPACKED', state: 'DISABLED'},
  {id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', location: 'UNPACKED', state: 'ENABLED'},
  {id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', location: 'UNPACKED', state: 'DISABLED'},
  {id: 'eldkgppmnhligdekahicdcdndcoongip', location: 'UNPACKED', state: 'ENABLED'},
  {id: 'dddddddddddddddddddddddddddddddd', location: 'FROM_STORE', state: 'ENABLED'},
].map(Object.freeze));
const unchanged = JSON.stringify(rows);
let events = [], native;
global.chrome = {
  developerPrivate: {Location: {UNPACKED: 'UNPACKED'}, autoUpdate: () => { events.push('native'); return native; }},
  metricsPrivate: {recordUserAction: () => events.push('metrics')},
};
(async () => {
  let finishNative;
  native = new Promise(resolve => { finishNative = resolve; });
  const pending = update.call({reloadItem: async id => { events.push(id); }}, rows);
  assert.deepEqual(events, ['native']);
  finishNative();
  await pending;
  assert.deepEqual(events, ['native', 'metrics', rows[2].id, rows[3].id, rows[4].id]);
  assert.equal(JSON.stringify(rows), unchanged);
  for (const row of rows.slice(0, 2)) {
    events = []; native = Promise.resolve();
    await update.call({reloadItem: async () => { throw new Error('Bundled helper must never reload'); }}, [row]);
    assert.deepEqual(events, ['native', 'metrics']);
    assert.equal(JSON.stringify(rows), unchanged);
  }
  events = []; native = Promise.reject(new Error('Native check failed'));
  await assert.rejects(update.call({reloadItem: async id => events.push(id)}, rows), /Native check failed/);
  assert.deepEqual(events, ['native']);
  events = []; native = Promise.resolve();
  await assert.rejects(update.call({reloadItem: async id => {
    events.push(id); if (id === rows[3].id) throw new Error('Ordinary reload failed');
  }}, rows), /Ordinary reload failed/);
  assert.deepEqual(events, ['native', 'metrics', rows[2].id, rows[3].id]);
  assert.equal(JSON.stringify(rows), unchanged);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace('BODY', json.dumps(body))
        subprocess.run([node, '-e', harness], check=True)

    def test_navigation_checksum_drift_refuses_before_any_writes(self):
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        rel = next(iter(overlay.NAVIGATION_HOOKS))
        self.put(rel, self.inputs[rel] + "unexpected navigation drift")
        with self.assertRaisesRegex(RuntimeError, "checksum differs"):
            overlay.apply_overlay(self.src)
        for path, data in before.items():
            if path != rel:
                self.assertEqual((self.src / path).read_bytes(), data)

    def test_permissions_checksum_drift_refuses_before_any_writes(self):
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        self.put(overlay.PERMISSIONS_CC, self.inputs[overlay.PERMISSIONS_CC] + "unexpected permissions drift")
        with self.assertRaisesRegex(RuntimeError, "checksum differs"):
            overlay.apply_overlay(self.src)
        for rel, data in before.items():
            if rel != overlay.PERMISSIONS_CC:
                self.assertEqual((self.src / rel).read_bytes(), data)

    def test_permissions_marker_in_partial_tree_refuses_before_any_writes(self):
        self.put(overlay.PERMISSIONS_CC,
                 overlay.transform(self.inputs[overlay.PERMISSIONS_CC], overlay.PERMISSIONS_HOOKS))
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        with self.assertRaisesRegex(RuntimeError, "already applied"):
            overlay.apply_overlay(self.src)
        for rel, data in before.items():
            self.assertEqual((self.src / rel).read_bytes(), data)

    def test_parser_checksum_drift_refuses_before_any_writes(self):
        self.put(overlay.PARSER_CC, self.inputs[overlay.PARSER_CC] + "unexpected parser drift")
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        with self.assertRaisesRegex(RuntimeError, "checksum differs"):
            overlay.apply_overlay(self.src)
        for rel, data in before.items():
            self.assertEqual((self.src / rel).read_bytes(), data)

    def test_parser_marker_in_partial_tree_refuses_before_any_writes(self):
        self.put(overlay.PARSER_CC,
                 overlay.transform(self.inputs[overlay.PARSER_CC], overlay.PARSER_HOOKS))
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        with self.assertRaisesRegex(RuntimeError, "already applied"):
            overlay.apply_overlay(self.src)
        for rel, data in before.items():
            self.assertEqual((self.src / rel).read_bytes(), data)

    def test_only_two_explicit_customize_theme_functions_change(self):
        rel = "chrome/browser/ui/webui/side_panel/customize_chrome/customize_chrome_page_handler.cc"
        hooks = overlay.NAVIGATION_HOOKS[rel]
        self.assertEqual(len(hooks), 2)
        for before, after in hooks:
            self.assertEqual(after, before.replace("chromewebstore.9oo91e.qjz9zk", "chromewebstore.google.com"))
        self.assertIn("OpenChromeWebStore()", hooks[0][0])
        self.assertIn("OpenThirdPartyThemePage(", hooks[1][0])
        self.assertIn("base::EscapePath(theme_id)", hooks[1][1])

    def test_restored_sidebar_resource_dependencies_exist_in_locked_source(self):
        real = LOCKED_SOURCE
        strings = real / "chrome/browser/ui/webui/extensions/extensions_ui.cc"
        if not strings.is_file():
            self.skipTest("The locked Chromium WebUI resources are unavailable")
        self.assertRegex(strings.read_text(), r'\{"sidebarDiscoverMore",\s*IDS_EXTENSIONS_SIDEBAR_DISCOVER_MORE\}')
        self.assertIn('id="web_store-custom"',
                      (real / "chrome/browser/resources/extensions/icons.html").read_text())
        self.assertIn("#moreExtensions", (real / "chrome/browser/resources/extensions/sidebar.css").read_text())
        self.assertIn("cr_link_row/cr_link_row.js",
                      (real / "chrome/browser/resources/settings/appearance_page/appearance_page.ts").read_text())

    def test_repeated_apply_refused(self):
        self.transformed()
        with self.assertRaisesRegex(RuntimeError, "already applied"):
            overlay.apply_overlay(self.src)

    def test_checksum_drift_refuses_before_any_writes(self):
        before = (self.src / overlay.CC).read_bytes()
        self.put(overlay.HEADER, self.inputs[overlay.HEADER] + "unexpected change")
        with self.assertRaisesRegex(RuntimeError, "checksum differs"):
            overlay.apply_overlay(self.src)
        self.assertEqual((self.src / overlay.CC).read_bytes(), before)

    def test_hook_drift_refuses_before_any_writes(self):
        before = {rel: (self.src / rel).read_bytes() for rel in self.inputs}
        with mock.patch.object(overlay, "HEADER_HOOKS", (("missing exact upstream hook", "replacement"),)):
            with self.assertRaisesRegex(RuntimeError, "hook drift"):
                overlay.apply_overlay(self.src)
        for rel, data in before.items():
            self.assertEqual((self.src / rel).read_bytes(), data)

    def test_wrong_version_refused(self):
        self.put("chrome/VERSION", "MAJOR=155\nMINOR=0\nBUILD=8059\nPATCH=39\n")
        with self.assertRaisesRegex(RuntimeError, "requires Chromium"):
            overlay.apply_overlay(self.src)

    def test_actual_pristine_84_fixture_copy_only(self):
        real = LOCKED_SOURCE
        if not all((real / rel).is_file() for rel in overlay.EXPECTED_SHA256):
            self.skipTest("Prepared pristine .84 candidate is unavailable")
        hashes = {rel: hashlib.sha256((real / rel).read_bytes()).hexdigest() for rel in overlay.EXPECTED_SHA256}
        # Stop the small synthetic-baseline patch while testing real pinned files.
        self.patch.stop()
        try:
            if hashes != overlay.EXPECTED_SHA256:
                self.skipTest("The local .84 tree has already moved beyond the pristine fixture")
            result = overlay.validate_copy(real)
            self.assertEqual(set(result), {overlay.CC, overlay.HEADER, overlay.PERMISSIONS_CC, overlay.PARSER_CC, *overlay.NAVIGATION_HOOKS})
            self.assertEqual(hashes, {rel: hashlib.sha256((real / rel).read_bytes()).hexdigest() for rel in hashes})
        finally:
            self.patch.start()


if __name__ == "__main__":
    unittest.main()
