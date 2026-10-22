#!/usr/bin/env python3
"""Pinned, one-use native Kumo browser integration for Chromium 156.

Settings, menus, new tab and browser services compile into the engine. No
component extension, renderer process grant, or command-line extension is added.
Run only in an isolated prepared source workspace after the existing overlays.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native/browser"
VERSION = "156.0.8078.47"
MARKER = "KUMO_NATIVE_BROWSER_V1"
DESTINATION = "chrome/browser/kumo"
RECORD = DESTINATION + "/integration-manifest.json"
EXPECTED_SHA256 = {
    'content/browser/loader/url_loader_factory_utils.h': 'e08addcc15e67325ad76d564431f3f41a42f4458ac8ea38fef07e65128d5ebef',
    'content/browser/loader/url_loader_factory_utils.cc': 'eb842a491f332820fb44ca91f0871c7d710c9719c24cb9daad4ad41b953766db',
    'chrome/app/settings_strings.grdp': 'ea4b55d209f455f5cd6df6fa4f2ef78ffec9220ecd88f379fa4874cd910d6caa',
    'chrome/app/settings_chromium_strings.grdp': '2052b02a52de5e77f1d6cd213947a4223898b7d020397f54be17c5fcbebcbc20',
    'chrome/app/chrome_exe_main_mac.cc': '96ed48f2bd53d81cebba0063f1408fec4da7c952af2d7446f047a5d46fa885df',
    'chrome/common/chrome_constants.cc': '31acb1832e0ab5f0c2c0f2df6d403589baeb2b1a553b982edf17e395d13d9672',
    'content/browser/websockets/websocket_connector_impl.cc': '9186e2bff0b0db6ba636eb6e9d15467933725e474c439fa87af17a62061b8252',
    'content/browser/websockets/websocket_connector_impl.h': 'f9cd596bf071dc614f4290b6140e8ffff51ad4c44571de34f38a1e33ddc3f264',
    'content/public/browser/content_browser_client.cc': '831a8f847353333323614b093b0916b515f3ecf7c578aace373b13a44342f09b',
    'content/public/browser/content_browser_client.h': 'bd3a8f5c8e4f36ccad7a430453107313240fd741818aa991babaeabb29ba9f60',
    'chrome/browser/chrome_content_browser_client.h': 'b81c1a72ab48463e3b2edadd085751b891f201c3beb1b329ade0906753f6b720',
    'chrome/test/BUILD.gn': 'f1b19b5589189f722672ac418b8f9e01895e3e304e7001c98576376ebebc41ad',
    'extensions/browser/extension_registrar.cc': 'ac66e79497f4a0bff47df524787c9a53e9e11024b5d25f851ab3ace98afcc0cf',
    'chrome/browser/extensions/installed_loader.cc': '4dd1ab740cffb5195914eb5668dc9f7e03c3ee7e39498a228dc81333347414ec',
    "build/util/branding.gni": "bea1ea627b838a56f404e66a50e8fa6c3f3ad2d165d2a326de6f55f0dec2f80d",
    "chrome/BUILD.gn": "1c548467a578bca48572160a52317c75b4494af958fb5107780f7ffedc8888a9",
    "chrome/app/chrome_command_ids.h": "66ff9a6ea64cc0fb6de535bdd2b6791d2d567615d5783718de427e4f46df54de",
    "chrome/app/chromium_strings.grd": "e1c8b5c6e9692bfa793396b3a2be11d0d186dbda34e3551c19a72f94fa88e5ba",
    "chrome/app/generated_resources.grd": "b2a2428438a7d7fcb5eac3ee86b0ae9cec521a33d834b958963a6e9abd43dc05",
    "chrome/app/theme/chromium/BRANDING": "5563ee94d05d70e70163c0ba0c3a7713148d66d65e6fdf6c3bb765a35a0fc981",
    "chrome/browser/BUILD.gn": "4fd197d79e573b69412d3658affbb080ed00ebc979735fe4f5148701d4341459",
    "chrome/browser/app_controller_mac.mm": "6ee80c08bc8dd9efbabbbf2a34002f20a0ebe69c3a66fb5c7338ab4f6997bae2",
    "chrome/browser/browser_resources.grd": "a169a4321e5b5fe396d005e45b8594d04c3a8d53a6b7a2582afe890c708100b9",
    "chrome/browser/chrome_content_browser_client.cc": "d43f558f74c0b82596aa422afc05f9be7cebf2af88baf258340672a0e6253abd",
    "chrome/browser/prefs/browser_prefs.cc": "6e4cf9172f1237a5d82be7f28959a91b595b807676aa6d4554e567663a985684",
    "chrome/browser/resources/extensions/service.ts": "eee45bcdc17667758c43796aee1a8eb51cc7719065a802f8e01be616dfb5effc",
    "chrome/browser/resources/settings/BUILD.gn": "001448df16687bdf70d1056674bc3ecfcd51f1da99c9f9f4f642f76ac7ae3e5e",
    "chrome/browser/resources/settings/route.ts": "d26cca9b32c27b6703b5b25404f207b1afea79554562eaa0af84cfccde76dbff",
    "chrome/browser/resources/settings/router.ts": "bbb3c4fd4fdc11f4b3d4541d7fce57845fba51c5a59c8dda10c3d803ca7c899e",
    "chrome/browser/resources/settings/settings_main/settings_main.html": "b7f8a60f4f226ae27ad2fb05d8d356ef217156971f6d87a79ae7521ee47430f7",
    "chrome/browser/resources/settings/settings_main/settings_main.ts": "13e308ad677db60b8df44d07b2342fb1e43c016ca4525bf6f56fd91ed14b74e2",
    "chrome/browser/resources/settings/settings_menu/settings_menu.html": "20adeb43ff54c9631f261fd86f3be3a6cd46abbfabf617da3f7dc0b0913ff45d",
    "chrome/browser/resources/settings/settings_menu/settings_menu.ts": "1ae55b3817382fbc1e38a84ffdc4bf717a820bb4a0f1f9f5a93f124ccf31faab",
    "chrome/browser/search/search.cc": "6e261abf41aef5a8b4cde442794836c13ca0ee7509b97e537c19dcf6c42df2b6",
    "chrome/browser/ui/browser_command_controller.cc": "e7c93eef2fdb98f309633d7b56756fde9706088ebf69d265d2d71b1b5c79b82b",
    "chrome/browser/ui/chrome_pages.cc": "148c1db0d1348a5eefdaec6acf5cdf7f41b41a62769ee5f2da216d815ca51e49",
    "chrome/browser/ui/cocoa/main_menu_builder.mm": "491aadf93baa0d161c7de98dc5cdaffbb71f9dee7e5ad100b441836342ab678a",
    "chrome/browser/ui/tab_helpers.cc": "bde4316840dcc675edefd6703505a00a98dc3cdcf8085787e342579b58d8c18b",
    "chrome/browser/ui/toolbar/app_menu_model.cc": "f6aaca1cd72918859cbf2b452cd19b45e4f1c5bf3c48a39fd4dabf38ea0f99e7",
    "chrome/browser/ui/webui/BUILD.gn": "f92e9a966032bddc9fdf5961605a8e95b42d4a93d7e748974951a045569079c7",
    "chrome/browser/ui/webui/chrome_web_ui_configs.cc": "d7a36e1517cc044699cbfa04777b39605b5b829fe47f1fa5d8802b08aba8ee2b",
    "chrome/browser/ui/webui/settings/BUILD.gn": "59031c85a08c12ac161d5ae5db9255ad9bb1556b0b0e62aa240eba16cdcc93f9",
    "chrome/browser/ui/webui/settings/settings_ui.cc": "0de76625d45d44de1729bcc84e59d3429354f8930a33f473e87646e51465f308",
    "chrome/common/chrome_isolated_world_ids.h": "6b5384da3ab0cb04ff100b19b8981e8846d51d0d405acf595ccbaf048d1e219a",
    "components/infobars/core/infobar_delegate.h": "b73748679d20b23c0f81799675e110cbf172d610672f800fa940d61ad2631230",
    "extensions/common/permissions/permissions_data.cc": "d0f2b381684e8a44a84198a5a5512064aadb7fa6bd6d07a09e832ca1d70c1873"
}


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def native_files(root=None):
    """Inventory all inputs; directory links and special files are never followed."""
    root = Path(NATIVE if root is None else root)
    require(root.is_dir() and not root.is_symlink(), "Native browser source must be a real directory")
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), "Native browser symlink is forbidden: " + str(path))
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "Native browser special file is forbidden: " + str(path))
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    require(bool(result), "Native browser source inventory is empty")
    return result


def once(text, old, new):
    require(text.count(old) == 1, "Native browser source hook is missing or ambiguous: " + old[:110])
    return text.replace(old, new, 1)


def include(text, name):
    matches = list(re.finditer(r'^#include [^\n]+\n', text, re.M))
    require(bool(matches) and name not in text, "Native include preimage changed: " + name)
    end = matches[0].end()
    return text[:end] + '#include "' + name + '"\n' + text[end:]


def resource_id(relative):
    return "IDR_KUMO_" + re.sub(r"[^A-Z0-9]", "_", Path(relative).name.upper())


def generated(native):
    sources = sorted(path for path in native if Path(path).suffix in (".cc", ".mm") and not Path(path).stem.endswith(("_test", "_unittest")))
    core_sources = ["actions/kumo_preferences_core.cc", "network/kumo_network_admission_wait.cc",
                    "network/kumo_url_loader_factory.cc"]
    require(all(path in sources for path in core_sources), "Required native testable cores are missing")
    sources = [path for path in sources if path not in core_sources]
    headers = sorted(path for path in native if Path(path).suffix == ".h")
    tests = sorted(path for path in native if path.endswith("_unittest.cc"))
    require(all(path in native for path in ("kumo_browser_api.h", "settings/kumo_settings_handler.cc", "new_tab/kumo_new_tab_ui.cc", "store/kumo_store_helper.cc")), "Required native browser sources are missing")
    deps = ["//base", "//base/version_info", "//chrome/browser:browser_public_dependencies",
            "//chrome/browser/profiles:profile", "//chrome/browser/themes",
            "//chrome/browser/ui/browser_window", "//chrome/browser/ui/tabs:tab_strip",
            "//chrome/browser/infobars", "//chrome/browser:resources", "//chrome/common",
            "//extensions/browser", "//extensions/common",
            "//components/download/public/common:public", "//components/infobars/content",
            "//components/infobars/core", "//components/keyed_service/content",
            "//components/pref_registry", "//components/prefs", "//components/sessions",
            "//components/user_prefs", "//content/public/browser", "//crypto", "//net",
            "//services/network/public/cpp", "//services/network/public/mojom",
            "//third_party/blink/public/common", "//ui/base", "//ui/webui", "//url"]
    lines = ["# " + MARKER, 'import("//testing/test.gni")', 'assert(is_mac)', 'source_set("headers") {',
             "  public = " + json.dumps(headers), '  public_deps = [ "//base", "//content/public/browser" ]', "}",
             'source_set("core") {', "  sources = " + json.dumps(core_sources),
             '  public = [ "actions/kumo_preferences.h", "network/kumo_network_admission.h", "network/kumo_url_loader_factory.h" ]',
             '  public_deps = [ "//base" ]',
             '  deps = [ "//components/pref_registry", "//components/prefs", "//mojo/public/cpp/bindings", "//net", "//services/network/public/cpp", "//services/network/public/mojom", "//url" ]', "}",
             'source_set("impl") {', "  sources = " + json.dumps(sources),
             '  public_deps = [ ":headers", ":core" ]', "  deps = " + json.dumps(deps),
             '  frameworks = [ "AppKit.framework", "Security.framework", "Foundation.framework" ]', "}", ""]
    if tests:
        lines += ['source_set("unit_tests") {', '  testonly = true',
                  "  sources = " + json.dumps(tests),
                  '  deps = [ ":core", "//base/test:test_support", "//components/prefs", "//components/sync_preferences:test_support", "//mojo/core/embedder", "//mojo/public/cpp/bindings", "//net", "//net/traffic_annotation:test_support", "//services/network/public/cpp", "//services/network/public/mojom", "//testing/gtest", "//url" ]', "}", ""]
    if tests:
        lines += ['test("kumo_native_tests") {',
                  '  deps = [ ":unit_tests", "//base/test:run_all_unittests" ]', "}", ""]
    return {DESTINATION + "/BUILD.gn": "\n".join(lines).encode()}


def transform(inputs, native):
    out = dict(inputs)
    def edit(path, callback): out[path] = callback(out[path])
    api = "chrome/browser/kumo/kumo_browser_api.h"
    edit("chrome/browser/ui/webui/settings/settings_ui.cc", lambda t: once(include(t, "chrome/browser/kumo/settings/kumo_settings_handler.h"),
        '  AddSettingsPageUIHandler(std::make_unique<AppearanceHandler>(web_ui));',
        '  // '+MARKER+'\n  AddSettingsPageUIHandler(std::make_unique<kumo::KumoSettingsHandler>());\n  AddSettingsPageUIHandler(std::make_unique<AppearanceHandler>(web_ui));'))
    edit("chrome/browser/resources/settings/router.ts", lambda t: once(t, '  BASIC: Route;', '  BASIC: Route;\n  KUMO: Route; // '+MARKER))
    edit("chrome/browser/resources/settings/route.ts", lambda t: once(t, "  r.BASIC = new Route('/');", "  r.BASIC = new Route('/');\n  r.KUMO = r.BASIC.createSection('/kumo', 'kumo', 'Kumo'); // "+MARKER))
    edit("chrome/browser/resources/settings/settings_main/settings_main.ts", lambda t: once(t, "import '../about_page/about_page.js';", "import '../about_page/about_page.js';\nimport '../kumo_page/kumo_page.js'; // "+MARKER))
    edit("chrome/browser/resources/settings/settings_main/settings_main.html", lambda t: once(t,
        '    show-all$="[[shouldShowAll_(inSearchMode_, lastRoute_)]]">',
        '    show-all$="[[shouldShowAll_(inSearchMode_, lastRoute_)]]">\n  <!-- '+MARKER+' -->\n  <div slot="view" id="kumo"><template is="dom-if" if="[[renderPlugin_(routes_.KUMO, lastRoute_, inSearchMode_)]]"><settings-kumo-page></settings-kumo-page></template></div>'))
    edit("chrome/browser/resources/settings/settings_menu/settings_menu.html", lambda t: once(t,
        '          on-click="onLinkClick_" selected-attribute="selected">',
        '          on-click="onLinkClick_" selected-attribute="selected">\n        <!-- '+MARKER+' -->\n        <a role="menuitem" id="kumo" href="/kumo" class="cr-nav-menu-item"><cr-icon icon="settings:settings"></cr-icon><span class="menu-label">Kumo</span><cr-ripple></cr-ripple></a>'))
    edit("chrome/browser/resources/settings/settings_menu/settings_menu.ts", lambda t: once(t,
        "const pathToActionMap: Map<string, string> = new Map([", "const pathToActionMap: Map<string, string> = new Map([\n  ['/kumo', 'SettingsMenu_KumoClicked'], // "+MARKER))
    edit("chrome/browser/resources/settings/BUILD.gn", lambda t: once(t, '  ts_files = [',
        '  # '+MARKER+'\n  ts_files = [\n    "kumo_page/kumo_page.ts",\n    "kumo_page/kumo_page.html.ts",\n    "kumo_page/kumo_browser_proxy.ts",'))
    edit("chrome/browser/ui/webui/chrome_web_ui_configs.cc", lambda t: once(include(include(t,
        "chrome/browser/kumo/new_tab/kumo_new_tab_ui.h"), "chrome/browser/kumo/protection/kumo_phishing_warning_ui.h"),
        '  map.AddWebUIConfig(std::make_unique<DownloadsUIConfig>());',
        '  // '+MARKER+'\n  map.AddWebUIConfig(std::make_unique<kumo::KumoNewTabUIConfig>());\n  map.AddWebUIConfig(std::make_unique<kumo::KumoPhishingWarningUIConfig>());\n  map.AddWebUIConfig(std::make_unique<DownloadsUIConfig>());'))
    edit("chrome/browser/search/search.cc", lambda t: once(t,
        '    const bool default_is_google = DefaultSearchProviderIsGoogle(profile);',
        '    // '+MARKER+': native normal-profile NTP, independent of search provider.\n#if BUILDFLAG(IS_MAC)\n    return NewTabURLDetails(GURL("chrome://kumo-new-tab/"), NEW_TAB_URL_VALID);\n#endif\n    const bool default_is_google = DefaultSearchProviderIsGoogle(profile);'))
    edit("chrome/browser/search/search.cc", lambda t: once(t,
        '  if (IsInstantNTPURL(*url, profile)) {',
        '  // '+MARKER+'\n  if (url->spec() == "chrome://kumo-new-tab/" || IsInstantNTPURL(*url, profile)) {'))
    edit("chrome/common/chrome_isolated_world_ids.h", lambda t: once(t,
        '  ISOLATED_WORLD_ID_APPLESCRIPT,', '  ISOLATED_WORLD_ID_APPLESCRIPT,\n  // '+MARKER+'\n  ISOLATED_WORLD_ID_KUMO_AGENT,\n  ISOLATED_WORLD_ID_KUMO_PHISHING,'))
    edit("chrome/browser/prefs/browser_prefs.cc", lambda t: once(include(t, api),
        '  TRACE_EVENT0("browser", "chrome::RegisterProfilePrefs");',
        '  TRACE_EVENT0("browser", "chrome::RegisterProfilePrefs");\n  kumo::RegisterProfilePrefs(registry); // '+MARKER))
    edit("chrome/browser/ui/tab_helpers.cc", lambda t: once(include(include(t, api), "chrome/browser/kumo/store/kumo_store_helper.h"),
        '  infobars::ContentInfoBarManager::CreateForWebContents(web_contents);',
        '  infobars::ContentInfoBarManager::CreateForWebContents(web_contents);\n  // '+MARKER+'\n  kumo::AttachToWebContents(web_contents);\n  kumo::AttachStoreHelper(web_contents);'))
    edit("chrome/browser/chrome_content_browser_client.cc", lambda t: once(include(t,
        "chrome/browser/kumo/protection/kumo_protection_service.h"),
        '  DCHECK(profile);\n\n  ChromeNavigationUIData* chrome_navigation_ui_data =',
        '  DCHECK(profile);\n  // '+MARKER+'\n  if (auto throttle = kumo::CreateProtectionThrottle(profile))\n    result.push_back(std::move(throttle));\n\n  ChromeNavigationUIData* chrome_navigation_ui_data ='))
    edit("chrome/browser/chrome_content_browser_client.cc", lambda t: once(t,
        '  DCHECK(profile);\n\n#if BUILDFLAG(IS_ANDROID)\n  auto [client_data_header, unused_is_custom_tab] =',
        '  DCHECK(profile);\n  // '+MARKER+': keepalive requests use the same native domain gate.\n  if (auto throttle = kumo::CreateProtectionThrottle(profile))\n    result.push_back(std::move(throttle));\n\n#if BUILDFLAG(IS_ANDROID)\n  auto [client_data_header, unused_is_custom_tab] ='))
    def network_admission(t):
        t = include(t, "net/base/net_errors.h")
        t = include(t, "chrome/browser/kumo/network/kumo_network_admission.h")
        t = once(t, 'bool ChromeContentBrowserClient::WillInterceptWebSocket(',
            'void ChromeContentBrowserClient::AllowWebSocketConnection(\n    content::BrowserContext* context, const GURL& url,\n    base::OnceCallback<void(bool)> callback) {\n  kumo::AllowNetworkConnection(Profile::FromBrowserContext(context), url, std::move(callback));\n}\n\nbool ChromeContentBrowserClient::WillInterceptWebSocket(')
        anchor = '    WillCreateWebTransportCallback callback) {\n'
        gate = r'''  // KUMO_NATIVE_BROWSER_V1: WebTransport also has a browser-owned domain gate.
  if (auto* host = content::RenderProcessHost::FromID(process_id)) {
    auto* protection = kumo::KumoProtectionService::Get(
        Profile::FromBrowserContext(host->GetBrowserContext()));
    if (!protection->DomainsReady()) {
      kumo::AllowNetworkConnection(Profile::FromBrowserContext(host->GetBrowserContext()), url, base::BindOnce(
          [](ChromeContentBrowserClient* client,
             base::WeakPtr<kumo::KumoProtectionService> service,
             int process, int routing, GURL target, url::Origin origin,
             mojo::PendingRemote<network::mojom::WebTransportHandshakeClient> handshake,
             WillCreateWebTransportCallback callback, bool allowed) {
            auto* host = content::RenderProcessHost::FromID(process);
            if (!allowed || !service || !host || kumo::KumoProtectionService::Get(
                Profile::FromBrowserContext(host->GetBrowserContext())) != service.get()) {
              std::move(callback).Run(std::move(handshake),
                  network::mojom::WebTransportError::New(net::ERR_ABORTED, 0,
                      "The connection was blocked or its browser session ended", false));
              return;
            }
            client->WillCreateWebTransport(process, routing, target, origin,
                std::move(handshake), std::move(callback));
          }, base::Unretained(this), protection->GetWeakPtr(), process_id,
          frame_routing_id, url, initiator_origin, std::move(handshake_client),
          std::move(callback)));
      return;
    }
    if (protection->ShouldBlock(url)) {
      std::move(callback).Run(std::move(handshake_client),
          network::mojom::WebTransportError::New(net::ERR_BLOCKED_BY_ADMINISTRATOR,
              0, "Blocked by Kumo domain protection", false));
      return;
    }
  }
'''
        t = once(t, anchor, anchor + gate)
        return once(t, 'void ChromeContentBrowserClient::AllowWebSocketConnection(',
            'void ChromeContentBrowserClient::WillFinalizeURLLoaderFactory(\n'
            '    content::BrowserContext* context, network::URLLoaderFactoryBuilder& builder,\n'
            '    network::mojom::URLLoaderFactoryOverride* factory_override) {\n'
            '  // '+MARKER+': after extension and DevTools URL rewriting, including internal overrides.\n'
            '  kumo::ProxyDomainURLLoaderFactory(Profile::FromBrowserContext(context), builder, factory_override);\n'
            '}\n\nvoid ChromeContentBrowserClient::AllowWebSocketConnection(')
    edit("chrome/browser/chrome_content_browser_client.cc", network_admission)
    edit("chrome/browser/chrome_content_browser_client.h", lambda t: once(t,
        '  bool WillInterceptWebSocket(content::RenderFrameHost* frame) override;',
        '  // '+MARKER+'\n  void WillFinalizeURLLoaderFactory(content::BrowserContext* context,\n      network::URLLoaderFactoryBuilder& builder,\n      network::mojom::URLLoaderFactoryOverride* factory_override) override;\n  void AllowWebSocketConnection(content::BrowserContext* context, const GURL& url,\n      base::OnceCallback<void(bool)> callback) override;\n  bool WillInterceptWebSocket(content::RenderFrameHost* frame) override;'))
    edit("content/public/browser/content_browser_client.h", lambda t: once(t,
        '  // Returns true when the embedder wants to intercept a websocket connection.',
        '  // '+MARKER+': final factory policy after embedder and DevTools rewriting.\n  // Keep existing override/CORS/header policy; an override target pipe can be wrapped.\n  // Default implementation is a no-op. Called on UI with the owning context.\n  virtual void WillFinalizeURLLoaderFactory(BrowserContext* context,\n      network::URLLoaderFactoryBuilder& builder,\n      network::mojom::URLLoaderFactoryOverride* factory_override);\n\n'
        '  // '+MARKER+': context-aware admission also covers frameless workers.\n  // The callback may run asynchronously on UI. Default embedder policy allows.\n  virtual void AllowWebSocketConnection(BrowserContext* context, const GURL& url,\n      base::OnceCallback<void(bool)> callback);\n\n  // Returns true when the embedder wants to intercept a websocket connection.'))
    edit("content/public/browser/content_browser_client.cc", lambda t: once(t,
        'bool ContentBrowserClient::WillInterceptWebSocket(RenderFrameHost*) {',
        'void ContentBrowserClient::WillFinalizeURLLoaderFactory(\n'
        '    BrowserContext* context, network::URLLoaderFactoryBuilder& builder,\n'
        '    network::mojom::URLLoaderFactoryOverride* factory_override) {}\n\n'
        'void ContentBrowserClient::AllowWebSocketConnection(\n    BrowserContext* context, const GURL& url, base::OnceCallback<void(bool)> callback) {\n  std::move(callback).Run(true); // '+MARKER+'\n}\n\nbool ContentBrowserClient::WillInterceptWebSocket(RenderFrameHost*) {'))
    edit("content/browser/loader/url_loader_factory_utils.h", lambda t: once(t,
        '           bool is_for_network_service);\n\n private:\n  raw_ptr<BrowserContext> browser_context_;',
        '           bool is_for_network_service);\n\n'
        '  // '+MARKER+': run the final browser policy after DevTools interceptors.\n'
        '  void RunFinal(network::URLLoaderFactoryBuilder& builder,\n'
        '                network::mojom::URLLoaderFactoryOverride* factory_override);\n\n'
        ' private:\n  raw_ptr<BrowserContext> browser_context_;'))
    edit("content/browser/loader/url_loader_factory_utils.cc", lambda t: once(once(t,
        '      is_for_network_service);\n}\n\nnamespace {\n\n// Returns (is_navigation, is_download).',
        '      is_for_network_service);\n}\n\n'
        'void ContentClientParams::RunFinal(network::URLLoaderFactoryBuilder& builder,\n'
        '    network::mojom::URLLoaderFactoryOverride* factory_override) {\n'
        '  GetContentClient()->browser()->WillFinalizeURLLoaderFactory(\n'
        '      browser_context_.get(), builder, factory_override);\n}\n\n'
        'namespace {\n\n// Returns (is_navigation, is_download).'),
        '  if (auto terminal_url_loader_factory =\n          terminal_params.TakeURLLoaderFactory()) {',
        '  // '+MARKER+': all production URL rewriters have now been installed.\n'
        '  if (content_client_params)\n'
        '    content_client_params->RunFinal(factory_builder, factory_override.get());\n\n'
        '  if (auto terminal_url_loader_factory =\n          terminal_params.TakeURLLoaderFactory()) {'))
    def socket_header(t):
        t = include(t, "base/memory/weak_ptr.h")
        t = once(t, ' private:\n  static void ConnectCalledByContentBrowserClient(', r''' private:
  // KUMO_NATIVE_BROWSER_V1: preserve the original transport path after admission.
  void ConnectAfterAdmission(const GURL& url,
      const std::vector<std::string>& requested_protocols,
      const std::optional<std::string>& user_agent,
      mojo::PendingRemote<network::mojom::WebSocketHandshakeClient> handshake_client,
      const std::optional<base::UnguessableToken>& throttling_profile_id,
      network::mojom::IPAddressSpace target_address_space, bool allowed);
  static void ConnectCalledByContentBrowserClient(''')
        return once(t, '  const std::optional<base::UnguessableToken> devtools_worker_token_;',
            '  const std::optional<base::UnguessableToken> devtools_worker_token_;\n  base::WeakPtrFactory<WebSocketConnectorImpl> weak_factory_{this}; // '+MARKER)
    edit("content/browser/websockets/websocket_connector_impl.h", socket_header)
    def socket_connector(t):
        start=t.index('void WebSocketConnectorImpl::Connect(')
        end=t.index('  CHECK(BrowserThread::CurrentlyOn',start)
        signature=t[start:end]
        wrapper=signature + r'''  CHECK(BrowserThread::CurrentlyOn(BrowserThread::UI), base::NotFatalUntil::M159);
  // Validate the untrusted request before creating any admission work.
  if (auto error = network::VerifyWebSocketConnectParameters(
          url, requested_protocols, isolation_info_)) {
    mojo::ReportBadMessage(*error);
    return;
  }
  auto* process = RenderProcessHost::FromID(frame_id_.child_id);
  if (!process) return;
  // KUMO_NATIVE_BROWSER_V1: shared/service workers have no RenderFrameHost;
  // their live renderer process still supplies the authoritative BrowserContext.
  GetContentClient()->browser()->AllowWebSocketConnection(
      process->GetBrowserContext(), url,
      base::BindOnce(&WebSocketConnectorImpl::ConnectAfterAdmission,
          weak_factory_.GetWeakPtr(), url, requested_protocols, user_agent,
          std::move(handshake_client), throttling_profile_id, target_address_space));
}

'''
        continuation=signature.replace('WebSocketConnectorImpl::Connect(', 'WebSocketConnectorImpl::ConnectAfterAdmission(')
        continuation=once(continuation, 'network::mojom::IPAddressSpace target_address_space) {',
            'network::mojom::IPAddressSpace target_address_space, bool allowed) {')
        # The upstream continuation retains its document/process checks, extension
        # observers, DevTools headers, network restrictions and transport factory.
        return t[:start]+wrapper+continuation+'  if (!allowed) return;\n'+t[end:]
    edit("content/browser/websockets/websocket_connector_impl.cc", socket_connector)
    edit("chrome/browser/extensions/installed_loader.cc", lambda t: once(t,
        '  for (auto& info : extensions_info) {',
        '  for (auto& info : extensions_info) {\n    // '+MARKER+': preserve old storage, never execute the retired product extension.\n    if (info.extension_id == "eldkgppmnhligdekahicdcdndcoongio") continue;'))
    edit("chrome/browser/extensions/installed_loader.cc", lambda t: once(t,
        '  for (const auto& info : extensions_info) {',
        '  for (const auto& info : extensions_info) {\n    if (info.extension_id == "eldkgppmnhligdekahicdcdndcoongio") continue; // '+MARKER))
    edit("extensions/browser/extension_registrar.cc", lambda t: once(t,
        'void ExtensionRegistrar::AddExtension(\n    scoped_refptr<const Extension> extension) {\n  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);',
        'void ExtensionRegistrar::AddExtension(\n    scoped_refptr<const Extension> extension) {\n  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);\n  // '+MARKER+': all locations, including explicit old command-line loads.\n  if (extension->id() == "eldkgppmnhligdekahicdcdndcoongio") return;'))
    edit("chrome/browser/ui/chrome_pages.cc", lambda t: once(t,
        'void ShowSettings(BrowserWindowInterface* browser) {\n  ShowSettingsSubPage(browser, std::string());',
        'void ShowSettings(BrowserWindowInterface* browser) {\n  // '+MARKER+'\n  ShowSettingsSubPage(browser, "kumo");'))
    edit("chrome/app/chrome_command_ids.h", lambda t: once(t,
        '#define IDC_ABOUT                       40018',
        '#define IDC_ABOUT                       40018\n// '+MARKER+'\n#define IDC_KUMO_CHECK_FOR_UPDATES       65001\n#define IDC_KUMO_AGENTS                  65002'))
    edit("chrome/browser/ui/browser_command_controller.cc", lambda t: once(include(t, api),
        '    case IDC_OPTIONS:\n      ShowSettings(webui::GetBrowserForOpeningWebUi(browser_));',
        '    case IDC_KUMO_CHECK_FOR_UPDATES:\n      kumo::CheckForUpdatesFromMenu(browser_->GetProfile());\n      break;\n    case IDC_KUMO_AGENTS:\n      ShowSettingsSubPage(webui::GetBrowserForOpeningWebUi(browser_), "kumo");\n      break;\n    case IDC_OPTIONS:\n      ShowSettings(webui::GetBrowserForOpeningWebUi(browser_));'))
    edit("chrome/browser/ui/browser_command_controller.cc", lambda t: once(t,
        '  command_updater_->UpdateCommandEnabled(IDC_ABOUT, show_main_ui);',
        '  command_updater_->UpdateCommandEnabled(IDC_ABOUT, show_main_ui);\n  command_updater_->UpdateCommandEnabled(IDC_KUMO_CHECK_FOR_UPDATES, show_main_ui);\n  command_updater_->UpdateCommandEnabled(IDC_KUMO_AGENTS, show_main_ui);'))
    edit("chrome/browser/app_controller_mac.mm", lambda t: once(include(t, api),
        '    case IDC_OPTIONS:\n      [self showPreferences:sender];\n      break;',
        '    case IDC_KUMO_CHECK_FOR_UPDATES:\n      app_controller_mac::RunInLastProfileSafely(base::BindOnce(^(Profile* profile) {\n        if (profile) kumo::CheckForUpdatesFromMenu(profile);\n      }), app_controller_mac::kShowProfilePickerOnFailure);\n      break;\n    case IDC_KUMO_AGENTS:\n      [self showPreferences:sender];\n      break;\n    case IDC_OPTIONS:\n      [self showPreferences:sender];\n      break;'))
    edit("chrome/browser/ui/cocoa/main_menu_builder.mm", lambda t: once(t,
        '              Item(IDS_PREFERENCES)\n                  .tag(IDC_OPTIONS)',
        '              Item(IDS_KUMO_CHECK_FOR_UPDATES).command_id(IDC_KUMO_CHECK_FOR_UPDATES),\n              Item(IDS_KUMO_AGENTS).command_id(IDC_KUMO_AGENTS),\n              Item(IDS_PREFERENCES)\n                  .tag(IDC_OPTIONS)'))
    def app_menu(t):
        pattern = r'(  AddItemWithStringIdAndVectorIcon\(\n      this, IDC_OPTIONS, IDS_SETTINGS,[\s\S]*?\);)'
        matches = list(re.finditer(pattern, t)); require(len(matches) == 1, "Native app menu Settings hook changed")
        return t[:matches[0].end()] + '\n  AddItem(IDC_KUMO_CHECK_FOR_UPDATES, l10n_util::GetStringUTF16(IDS_KUMO_CHECK_FOR_UPDATES));\n  AddItem(IDC_KUMO_AGENTS, l10n_util::GetStringUTF16(IDS_KUMO_AGENTS));\n' + t[matches[0].end():]
    edit("chrome/browser/ui/toolbar/app_menu_model.cc", app_menu)
    edit("components/infobars/core/infobar_delegate.h", lambda t: once(t,
        '    CONTEXTUAL_CUE_INFOBAR_DELEGATE_IOS = 140,',
        '    CONTEXTUAL_CUE_INFOBAR_DELEGATE_IOS = 140,\n    KUMO_STORE_INSTALL_INFOBAR_DELEGATE = 141, // '+MARKER))
    edit("chrome/app/generated_resources.grd", lambda t: once(t, '  </messages>',
        '    <!-- '+MARKER+' -->\n    <message name="IDS_KUMO_CHECK_FOR_UPDATES" desc="Kumo native menu item">Check for Updates…</message>\n    <message name="IDS_KUMO_AGENTS" desc="Kumo native menu item">Agent Connections…</message>\n  </messages>'))
    edit("chrome/app/theme/chromium/BRANDING", lambda t: once(t, 'PRODUCT_FULLNAME=Chromium', 'PRODUCT_FULLNAME=Kumo'))
    edit("build/util/branding.gni", lambda t: once(t,
        'chrome_product_full_name = _result.full_name',
        '# '+MARKER+': retain locked raw bundle/framework paths; runtime version_info reads BRANDING directly.\nchrome_product_full_name = _result.full_name\nif (is_mac && _result.full_name == "Kumo") {\n  chrome_product_full_name = "Chromium"\n}'))
    # User-visible PRODUCT_FULLNAME remains Kumo. These private filesystem
    # paths must match the locked Chromium GN artifact and Mach-O install names.
    edit("chrome/app/chrome_exe_main_mac.cc", lambda t: once(once(t,
        '      "../../../../" PRODUCT_FULLNAME_STRING " Framework";',
        '      "../../../../Chromium Framework";'),
        '      "../Frameworks/" PRODUCT_FULLNAME_STRING\n      " Framework.framework/Versions/" CHROME_VERSION_STRING\n      "/" PRODUCT_FULLNAME_STRING " Framework";',
        '      "../Frameworks/Chromium Framework.framework/Versions/" CHROME_VERSION_STRING\n      "/Chromium Framework";'))
    def mac_runtime_artifact_names(t):
        for before, after in (
            ('FPL(PRODUCT_FULLNAME_STRING);', 'FPL("Chromium");'),
            ('FPL(PRODUCT_FULLNAME_STRING " Helper");', 'FPL("Chromium Helper");'),
            ('FPL(PRODUCT_FULLNAME_STRING ".app/Contents/MacOS/" PRODUCT_FULLNAME_STRING);',
             'FPL("Chromium.app/Contents/MacOS/Chromium");'),
            ('FPL(PRODUCT_FULLNAME_STRING\n        " Helper.app/Contents/MacOS/" PRODUCT_FULLNAME_STRING " Helper");',
             'FPL("Chromium Helper.app/Contents/MacOS/Chromium Helper");'),
            ('FPL(PRODUCT_FULLNAME_STRING " Framework.framework");',
             'FPL("Chromium Framework.framework");'),
            ('FPL(PRODUCT_FULLNAME_STRING " Framework");', 'FPL("Chromium Framework");'),
        ):
            t = once(t, before, after)
        return t
    edit("chrome/common/chrome_constants.cc", mac_runtime_artifact_names)
    def brand_messages(t):
        def replace(match):
            name, body = match.group(2), match.group(3)
            if any(x in name for x in ('COPYRIGHT','LICENSE','CREDITS','TERMS')) or 'Chromium Authors' in body: return match.group(0)
            return match.group(1) + body.replace('Chromium', 'Kumo') + match.group(4)
        return re.sub(r'(<message\b[^>]*\bname="([^"]+)"[^>]*>)(.*?)(</message>)', replace, t, flags=re.S)
    edit("chrome/app/chromium_strings.grd", brand_messages)
    edit("chrome/app/settings_strings.grdp", lambda t: once(t,
        '''<message name="IDS_SETTINGS_PEOPLE" desc="Name of the settings page which manages the user's relationship to Google.">
      You and Google
    </message>''',
        '''<message name="IDS_SETTINGS_PEOPLE" desc="Name of the settings page which manages the user's relationship to Google.">
      Your profile
    </message>'''))
    edit("chrome/app/settings_chromium_strings.grdp", lambda t: once(t,
        '''<message name="IDS_SETTINGS_ABOUT_PROGRAM" desc="Menu title for the About Chromium page.">
        About Chromium
      </message>''',
        '''<message name="IDS_SETTINGS_ABOUT_PROGRAM" desc="Menu title for the About Chromium page.">
        About Kumo
      </message>'''))
    edit("chrome/test/BUILD.gn", lambda t: once(t,
        '    "//chrome/browser:core_unit_tests",',
        '    "//chrome/browser:core_unit_tests",\n    "//chrome/browser/kumo:unit_tests", # '+MARKER))
    edit("chrome/browser/BUILD.gn", lambda t: once(t,
        'group("browser_public_dependencies") {\n  public_deps = [',
        'group("browser_public_dependencies") {\n  public_deps = [\n    "//chrome/browser/kumo:headers", # '+MARKER))
    edit("chrome/BUILD.gn", lambda t: once(t,
        'group("dependencies") {\n  public_deps = [',
        'group("dependencies") {\n  public_deps = [\n    "//chrome/browser/kumo:impl", # '+MARKER))
    edit("chrome/browser/ui/webui/BUILD.gn", lambda t: once(t,
        'source_set("configs") {\n  sources = [',
        'source_set("configs") {\n  deps = [ "//chrome/browser/kumo:headers" ] # '+MARKER+'\n  sources = ['))
    # The configs target initializes deps later; make the existing initialization additive.
    edit("chrome/browser/ui/webui/BUILD.gn", lambda t: once(t,
        '  deps = [\n    ":gcm_internals_ui",', '  deps += [\n    ":gcm_internals_ui",'))
    edit("chrome/browser/ui/webui/settings/BUILD.gn", lambda t: once(t,
        '    "site_settings_helper.h",\n  ]\n\n  public_deps = [',
        '    "site_settings_helper.h",\n  ]\n\n  public_deps = [\n    "//chrome/browser/kumo:headers", # '+MARKER))
    resources = [(resource_id(path), 'kumo/'+path) for path in native
                 if '/resources/' in path and Path(path).suffix in ('.html','.js','.css')]
    require(len({name for name, _ in resources}) == len(resources), "Duplicate native resource names")
    entries = '\n'.join('      <include name="'+name+'" file="'+path+'" type="BINDATA" />' for name,path in resources)
    edit("chrome/browser/browser_resources.grd", lambda t: once(t, '    </includes>',
        '      <!-- '+MARKER+' -->\n'+entries+'\n    </includes>'))
    # Retire the product extension exceptions, keeping the Store scripting guard.
    spec = importlib.util.spec_from_file_location('_kumo_existing_store_overlay', ROOT/'scripts/extensions_overlay.py')
    old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    edit(old.PERMISSIONS_CC, lambda t: once(t, old.SCRIPT_GUARD,
        '  // '+MARKER+': no Kumo extension exception.\n  if (document_url.DomainIs("chromewebstore.google.com") ||\n      document_url.DomainIs("chrome.google.com")) {\n    if (error) *error = manifest_errors::kCannotScriptGallery;\n    return true;\n  }\n\n'))
    for before, after in reversed(old.NAVIGATION_HOOKS['chrome/browser/resources/extensions/service.ts']):
        edit('chrome/browser/resources/extensions/service.ts', lambda t, a=after,b=before: once(t,a,b))
    return out


def output_files(src):
    native = native_files()
    inputs = {}
    for relative, expected in EXPECTED_SHA256.items():
        path = src/relative
        require(path.is_file() and not path.is_symlink(), "Expected direct prepared source: "+relative)
        text = path.read_text()
        require(digest(text) == expected, "Pinned native browser source preimage changed: "+relative)
        inputs[relative] = text
    outputs = {path:text.encode() for path,text in transform(inputs,native).items()}
    outputs.update({DESTINATION+'/'+path:data for path,data in native.items()})
    for path,data in native.items():
        if path.startswith('settings/resources/'):
            outputs['chrome/browser/resources/settings/kumo_page/'+path.removeprefix('settings/resources/')] = data
    outputs.update(generated(native))
    return outputs, native


def verify_applied(src):
    record_path = src/RECORD
    require(record_path.is_file() and not record_path.is_symlink(), "Native browser integration manifest is missing")
    record = json.loads(record_path.read_text())
    require(record.get('schema') == 1 and record.get('marker') == MARKER, "Invalid native browser integration manifest")
    native = native_files()
    require(record['nativeInputs'] == {path:digest(data) for path,data in native.items()}, "Native browser inputs changed after preparation; use a new workspace")
    for relative, expected in record['outputs'].items():
        path = src/relative
        require(path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == expected, "Prepared native browser output changed: "+relative)
    require('"--load-extension"' not in (src/DESTINATION/'BUILD.gn').read_text(), "Native integration must not load an extension")
    return record


def apply_overlay(src):
    src = Path(src).resolve()
    require(not (src/DESTINATION).exists() and not (src/DESTINATION).is_symlink(), "Native browser integration was already applied or interrupted")
    version = dict(line.split('=',1) for line in (src/'chrome/VERSION').read_text().splitlines() if '=' in line)
    require('.'.join(version[k] for k in ('MAJOR','MINOR','BUILD','PATCH')) == VERSION, "Unexpected Chromium version")
    outputs,native = output_files(src)
    record = {'schema':1,'marker':MARKER,'chromiumVersion':VERSION,
              'nativeInputs':{path:digest(data) for path,data in native.items()},
              'outputs':{path:digest(data) for path,data in outputs.items()}}
    outputs[RECORD] = (json.dumps(record,sort_keys=True,indent=2)+'\n').encode()
    staged = []
    try:
        for relative,data in outputs.items():
            path = src/relative; path.parent.mkdir(parents=True,exist_ok=True)
            require(not path.is_symlink(), "Prepared output symlink is forbidden")
            fd, temporary = tempfile.mkstemp(prefix='.kumo-native-',dir=path.parent)
            with os.fdopen(fd,'wb') as handle: handle.write(data)
            os.chmod(temporary,0o644); staged.append((Path(temporary),path))
        for temporary,path in staged: os.replace(temporary,path)
    finally:
        for temporary,_ in staged: temporary.unlink(missing_ok=True)
    return verify_applied(src)


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('source',type=Path)
    parser.add_argument('--verify-applied',action='store_true'); args=parser.parse_args()
    value=verify_applied(args.source) if args.verify_applied else apply_overlay(args.source)
    print(json.dumps({'marker':value['marker'],'nativeInputCount':len(value['nativeInputs']),'outputCount':len(value['outputs'])}))
if __name__=='__main__':
    try: main()
    except (RuntimeError,OSError,ValueError) as error: raise SystemExit('Native browser integration: '+str(error))
