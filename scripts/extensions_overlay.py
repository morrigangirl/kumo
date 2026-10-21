#!/usr/bin/env python3
"""One-time, pinned Chromium 156.0.8078.47 Store navigation/update/script-protection overlay.

Apply only after the pinned common/macOS patches and domain substitution. This
keeps global Store identity and component services disabled. It restores a
credential-free legacy update path for installed internal extensions/themes
with an explicit Store update URL. It also restores explicit user-clicked Store
navigation in Appearance, Extensions and Customize Chrome. Real Store domains
remain script-restricted except for the pinned command-line Kumo helper at the
canonical modern HTTPS origin; that exception retains normal permission checks.
Runtime behavior
remains to be tested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

VERSION = "156.0.8078.47"
MARKER = "KUMO_STORE_EXTENSION_UPDATES_V1"
CC = "extensions/browser/updater/extension_downloader.cc"
HEADER = "extensions/browser/updater/extension_downloader.h"
PERMISSIONS_CC = "extensions/common/permissions/permissions_data.cc"
PARSER_CC = "extensions/browser/updater/safe_manifest_parser.cc"
SCRIPT_GUARD_MARKER = "KUMO_STORE_SCRIPT_GUARD_V1"
EXPECTED_SHA256 = {
    PARSER_CC: "4f2bd8da7e79c5ae3f2c24b4bdb2ec7ddb54044c3701887adc3b2e9a851959ae",
    'chrome/browser/resources/extensions/service.ts': '63bcf00f0281e0b0ac8c4269102ae8ca5c35e776b6822ece5f622269e9236899',
    PERMISSIONS_CC: "496cc16b52fd414dbc83bb326ea280b410ae81f8bf46700abc006e1f7ab69af5",
    'chrome/browser/resources/settings/appearance_page/appearance_page.html.ts': 'dac96168074bcbc25d6ce6e5b7ad044d0dac2ebabade4a5fe5042a24cf9d5bcc',
    'chrome/browser/resources/settings/appearance_page/appearance_page.ts': '98ffc19d6b8117ba45c9596fddb3c5e4161a7113640274ed0d4bcaa708504946',
    'chrome/browser/resources/extensions/sidebar.html.ts': 'ba7a1da913d73729a628279072c1b40e2ff2d21d4596a6b1676e1e32c83270a9',
    'chrome/browser/resources/extensions/sidebar.ts': '00b067519b03f119c91479c40675ae939770388a26a27f39c8712f7574e58bec',
    'chrome/browser/ui/webui/side_panel/customize_chrome/customize_chrome_page_handler.cc': '28b580692033b83777f5c4885f5316684fa12c6576ff8ef2a62efa459bc9e210',
    CC: "569ea004873e5ef742f1cddb4c7b1285c3ccee9e3eddcc043932a4bd23dc8ff8",
    HEADER: "0483271f7a679dbcfc2f31fbec0cbe7a11741ee0be0a0864ce636fd3c638ee08",
}

HELPERS = r'''// KUMO_STORE_EXTENSION_UPDATES_V1
// Local transport policy only: do not restore global Store service identity.
bool IsKumoPublicHttpsUrl(const GURL& url) {
  return url.is_valid() && url.SchemeIs(url::kHttpsScheme) &&
         !url.has_username() && !url.has_password() && !url.has_ref() &&
         url.EffectiveIntPort() == 443;
}

bool IsKumoStoreUpdateUrl(const GURL& url) {
  return IsKumoPublicHttpsUrl(url) &&
         url.host() == "clients2.google.com" &&
         url.path() == "/service/update2/crx";
}

bool IsKumoStoreCrxUrl(const GURL& url) {
  return IsKumoPublicHttpsUrl(url) &&
         url.host() == "clients2.googleusercontent.com" &&
         base::StartsWith(url.path(), "/crx/blobs/");
}

bool IsKumoStoreTask(const ExtensionDownloaderTask& task) {
  // Pending tasks have unknown type. Unpacked, external, policy and component
  // locations are outside this initial user-installed CRX update path.
  // Original task URLs must not carry arbitrary account/token query data.
  // The downloader generates the protocol query after this eligibility check.
  return task.install_location == mojom::ManifestLocation::kInternal &&
         task.type != Manifest::Type::kUnknown &&
         !task.update_url.has_query() &&
         IsKumoStoreUpdateUrl(task.update_url);
}

'''

# Each old hook must occur exactly once. All files are transformed in memory
# before either is written; whole-file input hashes pin the complete baseline.
CC_HOOKS = (
    ("// This sanitizes update urls used to fetch update manifests for extensions.\n",
     HELPERS + "// This sanitizes update urls used to fetch update manifests for extensions.\n"),
    ("      fetch_priority(fetch_priority),\n      credentials(CREDENTIALS_NONE),",
     "      fetch_priority(fetch_priority),\n      is_kumo_store_update(IsKumoStoreTask(task)),\n      credentials(CREDENTIALS_NONE),"),
    ("  std::string install_source =\n      extension_urls::IsWebstoreUpdateUrl(task.update_url)",
     "  // Store updates need no extension-supplied tracking data.\n"
     "  if (IsKumoStoreTask(task))\n    task.update_url_data.clear();\n"
     "  std::string install_source =\n      extension_urls::IsWebstoreUpdateUrl(task.update_url)"),
    ("  for (ExtensionDownloaderTask& task : pending_tasks_)\n"
     "    AddToFetches(fetches_preparing, std::move(task));\n"
     "  pending_tasks_.clear();\n\n}\n\nvoid ExtensionDownloader::SetIdentityManager(",
     "  std::vector<ExtensionDownloaderTask> rejected_tasks;\n"
     "  for (ExtensionDownloaderTask& task : pending_tasks_) {\n"
     "    if (IsKumoStoreTask(task)) {\n"
     "      AddToFetches(fetches_preparing, std::move(task));\n"
     "    } else {\n      rejected_tasks.push_back(std::move(task));\n    }\n  }\n"
     "  pending_tasks_.clear();\n\n"
     "  // Complete rejected requests too; never leave the updater awaiting IDs.\n"
     "  for (const ExtensionDownloaderTask& task : rejected_tasks) {\n"
     "    NotifyExtensionsDownloadStageChanged(\n"
     "        {task.id}, ExtensionDownloaderDelegate::Stage::FINISHED);\n"
     "    NotifyExtensionsDownloadFailed(\n"
     "        {task.id}, {task.request_id},\n"
     "        ExtensionDownloaderDelegate::Error::DISABLED);\n  }\n"
     "  for (auto& fetch_list : fetches_preparing) {\n"
     "    for (auto& fetch : fetch_list.second)\n"
     "      StartUpdateCheck(std::move(fetch));\n  }\n"
     "}\n\nvoid ExtensionDownloader::SetIdentityManager("),
    ("  if (extension_urls::IsWebstoreUpdateUrl(active_request->full_url())) {",
     "  if (IsKumoStoreUpdateUrl(active_request->base_url())) {\n"
     "    resource_request->credentials_mode =\n"
     "        network::mojom::CredentialsMode::kOmit;\n"
     "    // Fail closed if this public endpoint begins redirecting.\n"
     "    resource_request->redirect_mode = network::mojom::RedirectMode::kError;\n"
     "  } else if (extension_urls::IsWebstoreUpdateUrl(active_request->full_url())) {"),
    ("  if (!fetch_data->url.is_valid()) {\n",
     "  // The approved manifest's original task is the provenance, not the\n"
     "  // separately hosted CRX URL. Admit only the public HTTPS Store CDN.\n"
     "  if (!fetch_data->is_kumo_store_update ||\n"
     "      !IsKumoStoreCrxUrl(fetch_data->url)) {\n"
     "    NotifyExtensionsDownloadStageChanged(\n"
     "        {fetch_data->id}, ExtensionDownloaderDelegate::Stage::FINISHED);\n"
     "    NotifyExtensionsDownloadFailed(\n"
     "        {fetch_data->id}, fetch_data->GetRequestIds(),\n"
     "        ExtensionDownloaderDelegate::Error::CRX_FETCH_URL_INVALID);\n"
     "    return;\n  }\n"
     "  if (!fetch_data->url.is_valid()) {\n"),
    ("  const crx_file::VerifierFormat required_format =\n"
     "      extension_urls::IsWebstoreUpdateUrl(fetch_data->url)\n"
     "          ? GetWebstoreVerifierFormat(false)\n"
     "          : crx_format_requirement_;",
     "  const crx_file::VerifierFormat required_format =\n"
     "      fetch_data->is_kumo_store_update\n"
     "          ? GetWebstoreVerifierFormat(false)\n"
     "          : crx_format_requirement_;"),
    ("  if (fetch->credentials != ExtensionFetch::CREDENTIALS_COOKIES || !is_secure) {",
     "  if (fetch->is_kumo_store_update) {\n"
     "    extension_loader_resource_request_->credentials_mode =\n"
     "        network::mojom::CredentialsMode::kOmit;\n"
     "    extension_loader_resource_request_->redirect_mode =\n"
     "        network::mojom::RedirectMode::kError;\n"
     "  } else if (fetch->credentials != ExtensionFetch::CREDENTIALS_COOKIES ||\n"
     "             !is_secure) {"),
    ("  if (fetch->credentials == ExtensionFetch::CREDENTIALS_OAUTH2_TOKEN &&\n      is_secure) {",
     "  if (!fetch->is_kumo_store_update &&\n"
     "      fetch->credentials == ExtensionFetch::CREDENTIALS_OAUTH2_TOKEN &&\n      is_secure) {"),
    ("    ExtensionFetch* fetch,\n    int response_code) {\n"
     "  bool auth_failure = response_code == net::HTTP_UNAUTHORIZED ||",
     "    ExtensionFetch* fetch,\n    int response_code) {\n"
     "  // Public Store packages never retry with cookies, OAuth or authuser.\n"
     "  if (fetch->is_kumo_store_update)\n    return false;\n"
     "  bool auth_failure = response_code == net::HTTP_UNAUTHORIZED ||"),
    ("  ManifestFetchData::PingMode ping_mode = ManifestFetchData::NO_PING;\n"
     "  if (update_url.DomainIs(ping_enabled_domain_.c_str()))\n"
     "    ping_mode = ManifestFetchData::PING_WITH_ENABLED_STATE;",
     "  // No rollcall, active-bit, brand, enabled-state or disable-reason pings.\n"
     "  ManifestFetchData::PingMode ping_mode = ManifestFetchData::NO_PING;"),
)
HEADER_HOOKS = (
    ("    DownloadFetchPriority fetch_priority;\n"
     "    std::vector<ExtensionDownloaderTask> associated_tasks;",
     "    DownloadFetchPriority fetch_priority;\n"
     "    // KUMO_STORE_EXTENSION_UPDATES_V1: immutable original-task provenance.\n"
     "    const bool is_kumo_store_update;\n"
     "    std::vector<ExtensionDownloaderTask> associated_tasks;"),
)


# Store UI hooks retain explicit navigation and the browser-bundled helper.
# Global classifiers, promotions and account/component services stay disabled.
NAVIGATION_HOOKS = {
    'chrome/browser/resources/settings/appearance_page/appearance_page.html.ts': (
        ('  return html`<!--_html_template_start_-->\n<settings-section page-title="$i18n{appearancePageTitle}">\n  <div route-path="default">\n    <div class="cr-row first" id="themeRow"\n        ?hidden="${!this.pageVisibility_.setTheme}">\n      <div class="flex cr-padded-text">\n        <div>$i18n{themes}</div><div class="secondary">${this.themeSublabel_}</div>\n      </div>\n<if expr="not is_linux">\n      ${this.themeIdPref_?.value ? html`\n        <div class="separator"></div>\n',
         '  return html`<!--_html_template_start_-->\n<settings-section page-title="$i18n{appearancePageTitle}">\n  <div route-path="default">\n    <div class="settings-row first" id="themeRow"\n        ?hidden="${!this.pageVisibility_.setTheme}">\n      <cr-link-row id="openTheme" class="first"\n          ?hidden="${!this.pageVisibility_.setTheme}"\n          label="$i18n{themes}" sub-label="${this.themeSublabel_}"\n          @click="${this.onThemeClick_}" external></cr-link-row>\n<if expr="not is_linux">\n      ${this.themeIdPref_?.value ? html`\n        <div class="separator"></div>\n'),
    ),
    'chrome/browser/resources/settings/appearance_page/appearance_page.ts': (
        ('  }\n\n  protected onThemeClick_() {\n    this.appearanceBrowserProxy_.openCustomizeChrome();\n  }\n\n',
         "  }\n\n  protected onThemeClick_() {\n    if (this.themeUrl_ && !this.isForcedTheme_) {\n      window.open(this.themeUrl_, '_blank', 'noopener');\n      return;\n    }\n    this.appearanceBrowserProxy_.openCustomizeChrome();\n  }\n\n"),
        ("        this.themeSublabel_ = info.name;\n      });\n\n      this.themeUrl_ = 'https://chrome.9oo91e.qjz9zk/webstore/detail/' + themeId;\n      return;\n    }\n\n",
         "        this.themeSublabel_ = info.name;\n      });\n\n      this.themeUrl_ = 'https://chromewebstore.google.com/detail/' + themeId;\n      return;\n    }\n\n"),
    ),
    'chrome/browser/resources/extensions/sidebar.html.ts': (
        ('    <cr-ripple></cr-ripple>\n  </a>\n</cr-menu-selector>\n<!--_html_template_end_-->`;\n  // clang-format on\n}\n',
         '    <cr-ripple></cr-ripple>\n  </a>\n</cr-menu-selector>\n<div class="separator"></div>\n<div class="cr-nav-menu-item" id="moreExtensions">\n  <cr-icon id="web-store-icon" icon="extensions-icons:web_store-custom">\n  </cr-icon>\n  <span id="discover-more-text" class="cr-secondary-text"\n      @click="${this.onMoreExtensionsClick_}"\n      .innerHTML="${this.computeDiscoverMoreText_()}">\n  </span>\n  <cr-ripple></cr-ripple>\n</div>\n<!--_html_template_end_-->`;\n  // clang-format on\n}\n'),
    ),
    'chrome/browser/resources/extensions/sidebar.ts': (
        ('    sectionsExtensions: HTMLElement,\n    sectionsShortcuts: HTMLElement,\n    sectionsSitePermissions: HTMLElement,\n  };\n}\n\n',
         '    sectionsExtensions: HTMLElement,\n    sectionsShortcuts: HTMLElement,\n    sectionsSitePermissions: HTMLElement,\n    moreExtensions: HTMLElement,\n  };\n}\n\n'),
        ('    }\n  }\n\n}\n\ndeclare global {\n',
         "    }\n  }\n\n  protected computeDiscoverMoreText_(): TrustedHTML {\n    return this.i18nAdvanced('sidebarDiscoverMore', {\n      tags: ['a'],\n      attrs: ['target'],\n      substitutions: ['https://chromewebstore.google.com/category/extensions'],\n    });\n  }\n\n}\n\ndeclare global {\n"),
    ),
    'chrome/browser/resources/extensions/service.ts': (
        ('              const unpackedExtensions = extensions.filter(\n                  (ext) => ext.location ===\n                      chrome.developerPrivate.Location.UNPACKED);',
         "              // KUMO_STORE_EXTENSION_UPDATES_V1: this UI ships with the browser.\n              // Preserve its command-line location and user enablement state.\n              const unpackedExtensions = extensions.filter(\n                  (ext) => ext.id !== 'eldkgppmnhligdekahicdcdndcoongio' &&\n                      ext.location ===\n                          chrome.developerPrivate.Location.UNPACKED);"),
    ),
    'chrome/browser/ui/webui/side_panel/customize_chrome/customize_chrome_page_handler.cc': (
        ('void CustomizeChromePageHandler::OpenChromeWebStore() {\n  open_url_callback_.Run(\n      GURL("https://chromewebstore.9oo91e.qjz9zk/category/themes"));',
         'void CustomizeChromePageHandler::OpenChromeWebStore() {\n  open_url_callback_.Run(\n      GURL("https://chromewebstore.google.com/category/themes"));'),
        ('void CustomizeChromePageHandler::OpenThirdPartyThemePage(\n    const std::string& theme_id) {\n  open_url_callback_.Run(GURL("https://chromewebstore.9oo91e.qjz9zk/detail/" +\n                              base::EscapePath(theme_id)));',
         'void CustomizeChromePageHandler::OpenThirdPartyThemePage(\n    const std::string& theme_id) {\n  open_url_callback_.Run(GURL("https://chromewebstore.google.com/detail/" +\n                              base::EscapePath(theme_id)));'),
    ),
}


PARSER_HOOKS = (
    ('constexpr char kExpectedGupdateXmlns[] =\n'
     '    "http://www.9oo91e.qjz9zk/update2/response";',
     '// KUMO_STORE_EXTENSION_UPDATES_V1: XML protocol identity; never fetched.\n'
     'constexpr char kExpectedGupdateXmlns[] =\n'
     '    "http://www.google.com/update2/response";'),
)


SCRIPT_GUARD = r'''  // KUMO_STORE_SCRIPT_GUARD_V1
  // Protect the real Store without restoring its global service classifiers.
  // The command-line Kumo helper watches category -> detail SPA navigation, so
  // it needs this exact origin. It must still pass every ordinary host/user/
  // policy permission check below; this is not a script-everywhere allowlist.
  const bool is_kumo_store_helper =
      extension_id_ == "eldkgppmnhligdekahicdcdndcoongio" &&
      location_ == mojom::ManifestLocation::kCommandLine &&
      document_url.is_valid() && document_url.SchemeIs(url::kHttpsScheme) &&
      document_url.host() == "chromewebstore.google.com" &&
      document_url.EffectiveIntPort() == 443 &&
      !document_url.has_username() && !document_url.has_password();
  if ((document_url.DomainIs("chromewebstore.google.com") ||
       document_url.DomainIs("chrome.google.com")) &&
      !is_kumo_store_helper) {
    if (error)
      *error = manifest_errors::kCannotScriptGallery;
    return true;
  }

'''

PERMISSIONS_HOOKS = (
    ("  if (!ExtensionsClient::Get()->IsScriptableURL(document_url, error))\n",
     SCRIPT_GUARD + "  if (!ExtensionsClient::Get()->IsScriptableURL(document_url, error))\n"),
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def approved_url(raw, package=False):
    """Transport matcher; original tasks separately reject query parameters."""
    try:
        url = urlsplit(raw)
        return (url.scheme == "https" and url.username is None and url.password is None
                and "#" not in raw and url.port in (None, 443)
                and url.hostname == ("clients2.googleusercontent.com" if package else "clients2.google.com")
                and (url.path.startswith("/crx/blobs/") if package else url.path == "/service/update2/crx"))
    except (ValueError, TypeError):
        return False


def transform(text, hooks):
    require(MARKER not in text and SCRIPT_GUARD_MARKER not in text,
            "Extension overlay was already applied")
    for index, (old, new) in enumerate(hooks, 1):
        require(text.count(old) == 1, f"Upstream extension hook drift at replacement {index}")
        text = text.replace(old, new, 1)
    return text


def apply_overlay(src):
    src = Path(src).resolve()
    version = dict(line.split("=", 1) for line in (src / "chrome/VERSION").read_text().splitlines() if "=" in line)
    require(".".join(version.get(p, "") for p in ("MAJOR", "MINOR", "BUILD", "PATCH")) == VERSION,
            f"Extension overlay requires Chromium {VERSION}")
    inputs = {}
    for rel in (CC, HEADER, PERMISSIONS_CC, PARSER_CC, *NAVIGATION_HOOKS):
        path = src / rel
        require(path.is_file() and not path.is_symlink() and path.parent == path.parent.resolve(),
                f"Expected real source file: {path}")
        text = path.read_text()
        require(MARKER not in text and SCRIPT_GUARD_MARKER not in text,
                "Extension overlay was already applied")
        require(digest(text) == EXPECTED_SHA256[rel], f"Pinned post-domain extension source checksum differs: {rel}")
        inputs[rel] = text
    outputs = {CC: transform(inputs[CC], CC_HOOKS),
               HEADER: transform(inputs[HEADER], HEADER_HOOKS),
               PERMISSIONS_CC: transform(inputs[PERMISSIONS_CC], PERMISSIONS_HOOKS),
               PARSER_CC: transform(inputs[PARSER_CC], PARSER_HOOKS)}
    outputs.update({rel: transform(inputs[rel], hooks) for rel, hooks in NAVIGATION_HOOKS.items()})
    # Stage every file first. Filesystem interruption between replacements leaves
    # a recognizable marker; preparation must use a new work directory then.
    staged = {}
    try:
        for rel, text in outputs.items():
            path = src / rel
            fd, temporary = tempfile.mkstemp(prefix=".kumo-extension-", dir=path.parent)
            with os.fdopen(fd, "w") as handle:
                handle.write(text)
            os.chmod(temporary, path.stat().st_mode & 0o777)
            staged[rel] = temporary
        for rel, temporary in staged.items():
            os.replace(temporary, src / rel)
        return {rel: {"beforeSha256": digest(inputs[rel]), "afterSha256": digest(outputs[rel])} for rel in outputs}
    finally:
        for temporary in staged.values():
            if os.path.exists(temporary):
                os.unlink(temporary)


def validate_copy(src):
    """Apply only to temporary copies of the pinned upstream fixture files."""
    src = Path(src).resolve()
    with tempfile.TemporaryDirectory(prefix="kumo-extension-overlay-fixture-") as folder:
        fixture = Path(folder)
        for rel in ("chrome/VERSION", CC, HEADER, PERMISSIONS_CC, PARSER_CC, *NAVIGATION_HOOKS):
            destination = fixture / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((src / rel).read_bytes())
        result = apply_overlay(fixture)
        try:
            apply_overlay(fixture)
        except RuntimeError as error:
            require("already applied" in str(error), "Fixture repeat guard reported an unexpected failure")
        else:
            raise RuntimeError("Fixture repeat application was accepted")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--validate-copy", action="store_true", help="Apply only to disposable copies; leave source untouched")
    args = parser.parse_args()
    result = validate_copy(args.source) if args.validate_copy else apply_overlay(args.source)
    print(json.dumps({"version": VERSION, "fixtureOnly": args.validate_copy, "files": result}, indent=2))
    print("Installed internal Store-URL CRXs only; no pending/external/policy/custom-source updates. Runtime install not yet validated.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(f"Extension update overlay: {error}")
