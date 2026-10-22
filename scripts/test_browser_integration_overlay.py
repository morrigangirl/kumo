#!/usr/bin/env python3
"""Native browser source guards and disposable pinned-source integration fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_browser_overlay', ROOT/'scripts/browser_integration_overlay.py')
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)
PREPARED = Path(os.environ.get('KUMO_NATIVE_SOURCE_FIXTURE', ROOT/'build/source-156.0.8078.47-passwordless001/recipe/build/src'))


class NativeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kumo-native-inventory-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'nested').mkdir()
        (self.root/'nested/input.js').write_text('bounded native resource')

    def test_nested_resources_are_inventoried_and_changes_detected(self):
        before = overlay.native_files(self.root)
        self.assertEqual(set(before), {'nested/input.js'})
        (self.root/'nested/input.js').write_text('changed native resource')
        self.assertNotEqual(before, overlay.native_files(self.root))

    def test_file_and_directory_symlinks_are_rejected(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                link = self.root/'link'
                link.symlink_to(self.root/'nested' if directory else self.root/'nested/input.js', target_is_directory=directory)
                with self.assertRaisesRegex(RuntimeError, 'symlink'):
                    overlay.native_files(self.root)
                link.unlink()

    def test_root_symlink_is_rejected(self):
        link = self.root/'root-link'; link.symlink_to(self.root/'nested', target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'real directory'):
            overlay.native_files(link)

    def test_required_resource_ids_match_native_consumers(self):
        for path, expected in {
            'new_tab/resources/new_tab.html':'IDR_KUMO_NEW_TAB_HTML',
            'protection/resources/phishing_sampler.js':'IDR_KUMO_PHISHING_SAMPLER_JS',
            'protection/resources/protection_warning.js':'IDR_KUMO_PROTECTION_WARNING_JS',
        }.items():
            self.assertEqual(overlay.resource_id(path), expected)


@unittest.skipUnless((PREPARED/'chrome/VERSION').is_file(), 'Optional pinned prepared-source fixture is unavailable')
class PinnedNativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kumo-native-source-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.src = Path(self.temp.name)/'src'; self.src.mkdir()
        self.native = Path(self.temp.name)/'native'
        shutil.copytree(overlay.NATIVE, self.native)
        self.patch = mock.patch.object(overlay, 'NATIVE', self.native); self.patch.start(); self.addCleanup(self.patch.stop)
        self.originals = {}
        for rel in (*overlay.EXPECTED_SHA256, 'chrome/VERSION'):
            data = (PREPARED/rel).read_bytes(); self.originals[rel] = data
            dest = self.src/rel; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data)

    def test_complete_native_integration_and_original_source_preservation(self):
        record = overlay.apply_overlay(self.src)
        self.assertGreater(len(record['outputs']), 35)
        settings = (self.src/'chrome/browser/resources/settings/settings_main/settings_main.html').read_text()
        self.assertIn('<settings-kumo-page>', settings)
        self.assertIn('AddSettingsPageUIHandler(std::make_unique<kumo::KumoSettingsHandler>());', (self.src/'chrome/browser/ui/webui/settings/settings_ui.cc').read_text())
        self.assertIn('ISOLATED_WORLD_ID_KUMO_AGENT', (self.src/'chrome/common/chrome_isolated_world_ids.h').read_text())
        self.assertIn('ISOLATED_WORLD_ID_KUMO_PHISHING', (self.src/'chrome/common/chrome_isolated_world_ids.h').read_text())
        for rel,data in self.originals.items(): self.assertEqual((PREPARED/rel).read_bytes(), data)
        self.assertEqual(overlay.verify_applied(self.src), record)

    def test_reapplying_or_interrupted_destination_is_rejected(self):
        overlay.apply_overlay(self.src)
        with self.assertRaisesRegex(RuntimeError, 'already applied or interrupted'):
            overlay.apply_overlay(self.src)

    def test_preimage_mismatch_is_rejected_before_any_output(self):
        path = self.src/next(iter(overlay.EXPECTED_SHA256))
        path.write_bytes(path.read_bytes()+b'\nchanged')
        with self.assertRaisesRegex(RuntimeError, 'preimage changed'):
            overlay.apply_overlay(self.src)
        self.assertFalse((self.src/overlay.DESTINATION).exists())

    def test_post_apply_input_and_prepared_source_drift_are_rejected(self):
        overlay.apply_overlay(self.src)
        path = self.src/'chrome/browser/kumo/settings/kumo_settings_handler.cc'
        path.write_bytes(path.read_bytes()+b'\nchanged')
        with self.assertRaisesRegex(RuntimeError, 'output changed'):
            overlay.verify_applied(self.src)

    def test_nested_native_change_invalidates_prepared_manifest(self):
        overlay.apply_overlay(self.src)
        path = self.native/'new_tab/resources/new_tab.js'
        path.write_bytes(path.read_bytes()+b'\nchanged')
        with self.assertRaisesRegex(RuntimeError, 'inputs changed'):
            overlay.verify_applied(self.src)

    def test_runtime_product_branding_and_internal_artifact_contract_are_separate(self):
        overlay.apply_overlay(self.src)
        self.assertIn('PRODUCT_FULLNAME=Kumo', (self.src/'chrome/app/theme/chromium/BRANDING').read_text())
        self.assertIn('chrome_product_full_name = "Chromium"', (self.src/'build/util/branding.gni').read_text())
        self.assertIn('Chromium Authors', (self.src/'chrome/app/chromium_strings.grd').read_text())

    def test_every_websocket_creator_uses_context_gate_and_upstream_transport_is_preserved(self):
        overlay.apply_overlay(self.src)
        rel = 'content/browser/websockets/websocket_connector_impl.cc'
        original = self.originals[rel].decode()
        transformed = (self.src/rel).read_text()
        old_start = original.index('void WebSocketConnectorImpl::Connect(')
        old_body = original[original.index('  CHECK(BrowserThread::CurrentlyOn', old_start):original.index('void WebSocketConnectorImpl::ConnectCalledByContentBrowserClient(', old_start)]
        new_start = transformed.index('void WebSocketConnectorImpl::ConnectAfterAdmission(')
        new_body = transformed[transformed.index('  CHECK(BrowserThread::CurrentlyOn', new_start):transformed.index('void WebSocketConnectorImpl::ConnectCalledByContentBrowserClient(', new_start)]
        self.assertEqual(new_body, old_body)
        wrapper = transformed[transformed.index('void WebSocketConnectorImpl::Connect('):new_start]
        self.assertIn('process->GetBrowserContext(), url,', wrapper)
        self.assertIn('weak_factory_.GetWeakPtr()', wrapper)
        self.assertNotIn('if (!frame)', wrapper)
        self.assertIn('if (!allowed) return;', transformed[new_start:new_start+800])
        default = (self.src/'content/public/browser/content_browser_client.cc').read_text()
        self.assertIn('std::move(callback).Run(true); // '+overlay.MARKER, default)

    def test_both_loader_paths_and_transport_admissions_are_hooked(self):
        overlay.apply_overlay(self.src)
        text = (self.src/'chrome/browser/chrome_content_browser_client.cc').read_text()
        self.assertEqual(text.count('kumo::CreateProtectionThrottle(profile)'), 2)
        self.assertIn('kumo::AllowNetworkConnection(Profile::FromBrowserContext(context)', text)
        transport = text[text.index('void ChromeContentBrowserClient::WillCreateWebTransport('):]
        self.assertLess(transport.index('protection->ShouldBlock(url)'), transport.index('web_request_api->ProxyWebTransport('))

    def test_old_product_is_suppressed_at_load_and_universal_admission(self):
        overlay.apply_overlay(self.src)
        installed = (self.src/'chrome/browser/extensions/installed_loader.cc').read_text()
        self.assertEqual(installed.count('info.extension_id == "eldkgppmnhligdekahicdcdndcoongio"'), 2)
        registrar = (self.src/'extensions/browser/extension_registrar.cc').read_text()
        self.assertIn('if (extension->id() == "eldkgppmnhligdekahicdcdndcoongio") return;', registrar)
        gn = (self.src/'chrome/browser/kumo/BUILD.gn').read_text()
        impl, tests = gn.split('source_set("unit_tests")', 1)
        self.assertNotIn('kumo_preferences_unittest.cc', impl)
        self.assertIn('kumo_preferences_unittest.cc', tests)
        self.assertIn('kumo_network_admission_unittest.cc', tests)

    def test_product_extension_exceptions_are_removed_and_store_guard_remains(self):
        overlay.apply_overlay(self.src)
        permissions = (self.src/'extensions/common/permissions/permissions_data.cc').read_text()
        self.assertNotIn('is_kumo_store_helper', permissions)
        self.assertIn('kCannotScriptGallery', permissions)
        self.assertIn('document_url.DomainIs("chromewebstore.google.com")', permissions)
        self.assertNotIn('eldkgppmnhligdekahicdcdndcoongio', (self.src/'chrome/browser/resources/extensions/service.ts').read_text())

    def test_focused_native_tests_use_the_same_production_cores(self):
        overlay.apply_overlay(self.src)
        gn = (self.src/'chrome/browser/kumo/BUILD.gn').read_text()
        core = gn.split('source_set("core")', 1)[1].split('source_set("impl")', 1)[0]
        tests = gn.split('source_set("unit_tests")', 1)[1]
        self.assertIn('kumo_preferences_core.cc', core)
        self.assertIn('kumo_network_admission_wait.cc', core)
        self.assertNotIn('content/public/browser', core)
        self.assertIn('public_deps = [ ":headers", ":core" ]', gn)
        self.assertNotIn('testing_profile', tests)
        self.assertNotIn('content/test', tests)
        self.assertNotIn('  deps = [ ":impl"', tests)
        self.assertIn('test("kumo_native_tests")', tests)
        self.assertIn('"//base/test:run_all_unittests"', tests)

    def test_settings_template_is_a_compiled_input_with_named_handlers(self):
        overlay.apply_overlay(self.src)
        folder = self.src/'chrome/browser/resources/settings'
        self.assertIn('"kumo_page/kumo_page.html.ts"', (folder/'BUILD.gn').read_text())
        page = (folder/'kumo_page/kumo_page.ts').read_text()
        template = (folder/'kumo_page/kumo_page.html.ts').read_text()
        self.assertIn('return getHtml.bind(this)();', page)
        self.assertIn('interface HTMLElementTagNameMap', page)
        self.assertNotIn('return html`', page)
        self.assertIn('export function getHtml(this: SettingsKumoPageElement)', template)
        self.assertIn('@click="${this.onActionClick}"', template)
        self.assertNotIn('@click=${() =>', template)
        self.assertNotIn('@change=${(e: Event) =>', template)


if __name__ == '__main__': unittest.main()
