#!/usr/bin/env python3
"""Native browser source guards and disposable pinned-source integration fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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

    def test_product_menu_commands_are_bounded_and_do_not_alias_upstream_ids(self):
        # AppMenu routes IDs >= 0xE000 to dynamic bookmarks/recent-tabs/
        # tab-group delegates before consulting the browser command model.
        # 65002 previously reached a null STGEverythingMenu on menu creation.
        overlay.apply_overlay(self.src)
        header = (self.src/'chrome/app/chrome_command_ids.h').read_text()
        definitions = re.findall(r'^#define\s+(IDC_\w+)\s+(\d+)\s*$', header, re.M)
        commands = {name: int(value) for name, value in definitions}
        product = {name: value for name, value in commands.items() if name.startswith('IDC_KUMO_')}
        self.assertEqual(set(product), {'IDC_KUMO_CHECK_FOR_UPDATES', 'IDC_KUMO_AGENTS'})
        self.assertEqual(len(set(product.values())), len(product))
        for name, value in product.items():
            with self.subTest(command=name):
                self.assertGreaterEqual(value, commands['IDC_MinimumLabelValue'])
                self.assertLess(value, 0xE000, 'Static menu command entered Chromium dynamic dispatch')
                self.assertEqual([other for other, number in commands.items() if number == value], [name])

    @unittest.skipUnless(shutil.which('clang'), 'Clang is required for the command-range preprocessing regression')
    def test_menu_guard_rejects_each_dynamic_id_at_preprocessing(self):
        overlay.apply_overlay(self.src)
        header = (self.src/'chrome/app/chrome_command_ids.h').read_text()
        start = header.index('// '+overlay.MARKER+': bounded commands')
        block = header[start:header.index('#endif', start)+len('#endif')]
        constants = (PREPARED/'ui/base/command_id_constants.h').read_text()
        # Compile the actual generated guard against the pinned upstream limit.
        # Mutating either command back into the reserved range must fail.
        for name in (None, 'IDC_KUMO_CHECK_FOR_UPDATES', 'IDC_KUMO_AGENTS'):
            with self.subTest(command=name):
                text = block if name is None else re.sub(
                    rf'(#define\s+{name}\s+)\d+', r'\g<1>65002', block)
                result = subprocess.run(['clang', '-E', '-x', 'c', '-'],
                    input=constants+'\n'+text, text=True, capture_output=True, timeout=20)
                if name is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Kumo commands must remain below', result.stderr)

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

    def test_navigation_and_transport_admissions_preserve_upstream_keepalive_throttles(self):
        original = (self.src/'chrome/browser/chrome_content_browser_client.cc').read_text()
        def keepalive_body(text):
            function = text[text.index('ChromeContentBrowserClient::CreateURLLoaderThrottlesForKeepAlive('):]
            return function[:function.index('\n}\n')]
        overlay.apply_overlay(self.src)
        text = (self.src/'chrome/browser/chrome_content_browser_client.cc').read_text()
        self.assertEqual(text.count('kumo::CreateProtectionThrottle(profile)'), 1)
        self.assertEqual(keepalive_body(text), keepalive_body(original))
        self.assertNotIn('kumo::CreateProtectionThrottle', keepalive_body(text))
        self.assertEqual(text.count('kumo::ProxyDomainURLLoaderFactory('), 1)
        self.assertIn('builder, factory_override);', text)
        self.assertIn('kumo::AllowNetworkConnection(Profile::FromBrowserContext(context)', text)
        transport = text[text.index('void ChromeContentBrowserClient::WillCreateWebTransport('):]
        self.assertLess(transport.index('protection->ShouldBlock(url)'), transport.index('web_request_api->ProxyWebTransport('))

    def test_final_factory_admission_follows_all_extension_request_rewriters(self):
        before = (self.src/'chrome/browser/chrome_content_browser_client.cc').read_text()
        def factory_body(text):
            function = text[text.index('void ChromeContentBrowserClient::WillCreateURLLoaderFactory('):]
            return function[:function.index('\n}\n')]
        overlay.apply_overlay(self.src)
        text = (self.src/'chrome/browser/chrome_content_browser_client.cc').read_text()
        self.assertEqual(factory_body(before), factory_body(text))
        self.assertEqual(text.count('kumo::ProxyDomainURLLoaderFactory('), 1)
        self.assertIn('builder, factory_override);', text)
        internal = (self.src/'content/browser/loader/url_loader_factory_utils.cc').read_text()
        self.assertLess(internal.index('devtools_params->Run('), internal.index('content_client_params->RunFinal('))
        self.assertLess(internal.index('content_client_params->RunFinal('), internal.index('terminal_params.TakeURLLoaderFactory()'))
        self.assertIn('browser_context_.get(), builder, factory_override);', internal)
        default = (self.src/'content/public/browser/content_browser_client.cc').read_text()
        self.assertIn('network::mojom::URLLoaderFactoryOverride* factory_override) {}', default)
        gn = (self.src/'chrome/browser/kumo/BUILD.gn').read_text()
        core = gn.split('source_set("core")', 1)[1].split('source_set("impl")', 1)[0]
        impl = gn.split('source_set("impl")', 1)[1].split('source_set("unit_tests")', 1)[0]
        self.assertIn('network/kumo_url_loader_factory.cc', core)
        self.assertNotIn('network/kumo_url_loader_factory.cc', impl)

    def test_settings_profile_and_about_labels_are_narrowly_branded(self):
        before = {name: (self.src/name).read_text() for name in
            ['chrome/app/settings_strings.grdp', 'chrome/app/settings_chromium_strings.grdp']}
        overlay.apply_overlay(self.src)
        people = (self.src/'chrome/app/settings_strings.grdp').read_text()
        about = (self.src/'chrome/app/settings_chromium_strings.grdp').read_text()
        self.assertEqual(people, before['chrome/app/settings_strings.grdp'].replace(
            '\n      You and Google\n', '\n      Your profile\n', 1))
        self.assertEqual(about, before['chrome/app/settings_chromium_strings.grdp'].replace(
            '\n        About Chromium\n', '\n        About Kumo\n', 1))
        self.assertIn('About Chrome for Testing', about)

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

    def test_mac_runtime_paths_match_artifacts_while_product_brand_stays_kumo(self):
        overlay.apply_overlay(self.src)
        brand = (self.src/'chrome/app/theme/chromium/BRANDING').read_text()
        self.assertIn('PRODUCT_FULLNAME=Kumo', brand)
        gn = (self.src/'build/util/branding.gni').read_text()
        self.assertIn('chrome_product_full_name = "Chromium"', gn)
        loader = (self.src/'chrome/app/chrome_exe_main_mac.cc').read_text()

        def loader_paths(source):
            source = source.replace('PRODUCT_FULLNAME_STRING', '"Kumo"')
            source = source.replace('CHROME_VERSION_STRING', '"'+overlay.VERSION+'"')
            return [''.join(re.findall(r'"([^"\n]*)"', expression)) for expression in
                    re.findall(r'static constexpr char rel_path\[\] =\s*([^;]+);', source)]

        paths = loader_paths(loader)
        self.assertEqual(paths, ['../../../../Libraries/librenderer.dylib',
                                '../../../../Chromium Framework',
                                '../Frameworks/Chromium Framework.framework/Versions/'+overlay.VERSION+'/Chromium Framework'])
        # The original product-macro path is wrong once visible branding is Kumo.
        self.assertNotEqual(loader_paths(self.originals['chrome/app/chrome_exe_main_mac.cc'].decode())[-1], paths[-1])
        constants = (self.src/'chrome/common/chrome_constants.cc').read_text()
        for name in ['Chromium', 'Chromium Helper', 'Chromium.app/Contents/MacOS/Chromium',
                     'Chromium Helper.app/Contents/MacOS/Chromium Helper',
                     'Chromium Framework.framework', 'Chromium Framework']:
            self.assertIn('FPL("'+name+'")', constants)
        self.assertNotIn('PRODUCT_FULLNAME_STRING', constants)
        # When a compiled fixture exists, exercise the computed paths against its
        # actual main/helper artifact tree, including every ordinary helper.
        app = PREPARED/'out/Default/Chromium.app'
        if app.is_dir():
            self.assertTrue((app/'Contents/MacOS'/paths[-1]).is_file())
            framework = app/'Contents/Frameworks/Chromium Framework.framework/Versions'/overlay.VERSION
            for suffix in ['', ' (Renderer)', ' (GPU)', ' (Alerts)']:
                binary_folder = framework/('Helpers/Chromium Helper'+suffix+'.app/Contents/MacOS')
                self.assertTrue((binary_folder/paths[1]).is_file(), suffix)


if __name__ == '__main__': unittest.main()
