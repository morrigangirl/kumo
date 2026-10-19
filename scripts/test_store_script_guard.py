#!/usr/bin/env python3
"""Offline pinned-body fixtures; these do not prove Chromium runtime behavior.

Compile the actual generated permissions bodies and pinned DomainIs algorithm
against parsed-component/permission shims. Chromium URL parsing, real extension
installation and renderer/browser integration still require the source app.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_extensions_overlay import LOCKED_SOURCE, overlay


def function_body(text, signature):
    """Extract a pinned function including its signature and balanced body."""
    start = text.index(signature)
    opened = text.index("{", start)
    depth = 1
    end = opened + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


class StoreScriptGuardFixtures(unittest.TestCase):
    def pinned_permissions(self):
        path = LOCKED_SOURCE / overlay.PERMISSIONS_CC
        if not path.is_file():
            self.skipTest("The locked Chromium permissions source is unavailable")
        text = path.read_text()
        # A prepared tree may have this one reviewed amendment already applied.
        if overlay.SCRIPT_GUARD_MARKER in text:
            self.assertEqual(text.count(overlay.SCRIPT_GUARD), 1)
            text = text.replace(overlay.SCRIPT_GUARD, "", 1)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         overlay.EXPECTED_SHA256[overlay.PERMISSIONS_CC])
        return text

    def test_exact_single_insertion_preserves_all_existing_gates(self):
        before = self.pinned_permissions()
        after = overlay.transform(before, overlay.PERMISSIONS_HOOKS)
        self.assertEqual(after.replace(overlay.SCRIPT_GUARD, "", 1), before)
        self.assertEqual(after.count(overlay.SCRIPT_GUARD_MARKER), 1)
        restricted = function_body(after, "bool PermissionsData::IsRestrictedUrl(")
        order = ["CanExecuteScriptEverywhere(extension_id_, location_)",
                 "g_policy_delegate->IsRestrictedUrl", "IsValidSchemeForExtensions",
                 overlay.SCRIPT_GUARD_MARKER, "ExtensionsClient::Get()->IsScriptableURL"]
        positions = [restricted.index(fragment) for fragment in order]
        self.assertEqual(positions, sorted(positions))
        # The helper skips the new denial. It never returns an early allow.
        self.assertNotIn("return false", overlay.SCRIPT_GUARD)
        for signature in ("bool PermissionsData::CanExecuteScriptEverywhere(",
                          "PermissionsData::PageAccess PermissionsData::CanRunOnPage(",
                          "PermissionsData::PageAccess PermissionsData::GetPageAccess(",
                          "PermissionsData::PageAccess PermissionsData::GetContentScriptAccess("):
            self.assertEqual(function_body(before, signature), function_body(after, signature))

    def test_guard_replay_and_hook_drift_refuse(self):
        before = self.pinned_permissions()
        after = overlay.transform(before, overlay.PERMISSIONS_HOOKS)
        with self.assertRaisesRegex(RuntimeError, "already applied"):
            overlay.transform(after, overlay.PERMISSIONS_HOOKS)
        old, _ = overlay.PERMISSIONS_HOOKS[0]
        for changed in (before.replace(old, "", 1), before + old):
            with self.assertRaisesRegex(RuntimeError, "hook drift"):
                overlay.transform(changed, overlay.PERMISSIONS_HOOKS)

    def test_guard_external_api_and_original_domain_semantics(self):
        self.pinned_permissions()
        header = (LOCKED_SOURCE / "url/gurl.h").read_text()
        for method in ("is_valid", "SchemeIs", "host", "EffectiveIntPort",
                       "has_username", "has_password", "DomainIs"):
            self.assertIn(method + "(", header)
        self.assertIn("has_username() const { return parsed_.username.is_valid(); }", header)
        self.assertIn("has_password() const { return parsed_.password.is_valid(); }", header)
        urls = (LOCKED_SOURCE / "extensions/common/extension_urls.cc").read_text()
        original = function_body(urls, "bool IsWebstoreDomain(")
        self.assertIn("url.DomainIs(GetWebstoreLaunchURL().host())", original)
        self.assertIn("url.DomainIs(GetNewWebstoreLaunchURL().host())", original)

    def test_compiled_actual_access_bodies_with_parsed_component_shims(self):
        before = self.pinned_permissions()
        source = overlay.transform(before, overlay.PERMISSIONS_HOOKS)
        signatures = ("bool PermissionsData::CanExecuteScriptEverywhere(",
                      "bool PermissionsData::IsRestrictedUrl(",
                      "bool PermissionsData::CanAccessPage(",
                      "PermissionsData::PageAccess PermissionsData::GetPageAccess(",
                      "bool PermissionsData::CanRunContentScriptOnPage(",
                      "PermissionsData::PageAccess PermissionsData::GetContentScriptAccess(",
                      "PermissionsData::PageAccess PermissionsData::CanRunOnPage(")
        domain = function_body((LOCKED_SOURCE / "url/url_util.cc").read_text(),
                               "bool DomainIs(std::string_view canonical_host,")
        # These fixtures supply canonical parsed URL components; they do not
        # replace GURL parsing with a second URL parser or claim to test it.
        harness = r'''
#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
namespace url {
constexpr const char* kHttpsScheme = "https";
constexpr const char* kAboutBlankURL = "about:blank";
constexpr const char* kAboutSrcdocURL = "about:srcdoc";
DOMAIN_BODY
}
struct GURL {
  bool valid = true, username = false, password = false;
  std::string scheme = "https", host_value = "chromewebstore.google.com";
  std::string path = "/", spec_value = "https://chromewebstore.google.com/";
  int port = 443;
  bool is_valid() const { return valid; }
  bool SchemeIs(const char* s) const { return scheme == s; }
  const std::string& GetScheme() const { return scheme; }
  const std::string& GetHost() const { return host_value; }
  const std::string& spec() const { return spec_value; }
  std::string_view host() const { return host_value; }
  int EffectiveIntPort() const { return port; }
  bool has_username() const { return username; }
  bool has_password() const { return password; }
  bool DomainIs(std::string_view d) const { return valid && url::DomainIs(host(), d); }
};
namespace mojom {
enum class ManifestLocation { kInternal, kUnpacked, kExternalPolicy, kCommandLine, kComponent };
enum class APIPermissionID { kTab };
}
using APIPermissionID = mojom::APIPermissionID;
using ExtensionId = std::string;
namespace manifest_errors {
constexpr const char* kCannotScriptGallery = "gallery";
constexpr const char* kCannotAccessPageWithUrl = "page-url";
constexpr const char* kCannotAccessPage = "page";
constexpr const char* kCannotAccessChromeUrl = "chrome";
constexpr const char* kCannotAccessExtensionUrl = "extension";
}
namespace extension_misc { constexpr const char* kPolicyBlockedScripting = "policy"; }
namespace content { constexpr const char* kChromeUIScheme = "chrome"; }
namespace switches {
bool AreExtensionsOnChromeURLsAllowed() { return false; }
bool AreExtensionsOnExtensionURLsAllowed() { return false; }
}
constexpr const char* kExtensionScheme = "chrome-extension";
constexpr const char* kErrorBlocked = "Blocked";
struct ErrorUtils {
  static std::string FormatErrorMessage(const char* s, const std::string&) { return s; }
};
struct URLPattern {
  static bool IsValidSchemeForExtensions(const std::string& s) {
    return s == "https" || s == "http" || s == "file" || s == "chrome" || s == "chrome-extension";
  }
};
struct URLPatternSet { bool matches = false; bool MatchesURL(const GURL&) const { return matches; } };
struct PermissionSet {
  URLPatternSet explicit_set, scriptable_set;
  const URLPatternSet& explicit_hosts() const { return explicit_set; }
  const URLPatternSet& scriptable_hosts() const { return scriptable_set; }
  bool HasAPIPermission(APIPermissionID) const { return false; }
};
struct DummyLock { void AssertAcquired() const {} };
namespace base { struct AutoLock { explicit AutoLock(const DummyLock&) {} }; }
struct ExtensionsClient {
  using ScriptingAllowlist = std::vector<std::string>;
  ScriptingAllowlist allowlist = {"existing-global-allowlist"};
  bool scriptable = true;
  static ExtensionsClient* Get() { static ExtensionsClient client; return &client; }
  const ScriptingAllowlist& GetScriptingAllowlist() { return allowlist; }
  bool IsScriptableURL(const GURL&, std::string* error) {
    if (!scriptable && error) *error = "client";
    return scriptable;
  }
};
struct PermissionsData {
  enum class PageAccess { kDenied, kWithheld, kAllowed };
  struct PolicyDelegate {
    bool deny = false;
    bool IsRestrictedUrl(const GURL&, std::string* error) {
      if (deny && error) *error = "delegate";
      return deny;
    }
  };
  ExtensionId extension_id_ = "ordinary";
  mojom::ManifestLocation location_ = mojom::ManifestLocation::kInternal;
  DummyLock runtime_lock_;
  std::unique_ptr<PermissionSet> active_permissions_unsafe_ = std::make_unique<PermissionSet>();
  std::unique_ptr<PermissionSet> withheld_permissions_unsafe_ = std::make_unique<PermissionSet>();
  PermissionSet tab;
  bool policy_blocked = false, user_blocked = false, has_tab = false;
  const PermissionSet& active_permissions() const { return *active_permissions_unsafe_; }
  const PermissionSet* GetTabSpecificPermissions(int) const { return has_tab ? &tab : nullptr; }
  bool IsPolicyBlockedHostUnsafe(const GURL&) const { return policy_blocked; }
  bool IsUrlBlockedByUser(const GURL&) const { return user_blocked; }
  static bool CanExecuteScriptEverywhere(const ExtensionId&, mojom::ManifestLocation);
  bool IsRestrictedUrl(const GURL&, std::string*) const;
  bool CanAccessPage(const GURL&, int, std::string*) const;
  bool CanRunContentScriptOnPage(const GURL&, int, std::string*) const;
  PageAccess GetPageAccess(const GURL&, int, std::string*) const;
  PageAccess GetContentScriptAccess(const GURL&, int, std::string*) const;
  PageAccess CanRunOnPage(const GURL&, const URLPatternSet&, const URLPatternSet&,
                         const URLPatternSet*, std::string*) const;
};
PermissionsData::PolicyDelegate* g_policy_delegate = nullptr;
ACCESS_BODIES
using Access = PermissionsData::PageAccess;
PermissionsData permitted(bool helper = false) {
  PermissionsData p;
  p.extension_id_ = helper ? "eldkgppmnhligdekahicdcdndcoongio" : "ordinary";
  p.location_ = helper ? mojom::ManifestLocation::kCommandLine : mojom::ManifestLocation::kInternal;
  p.active_permissions_unsafe_->explicit_set.matches = true;
  p.active_permissions_unsafe_->scriptable_set.matches = true;
  return p;
}
void both(const PermissionsData& p, const GURL& url, Access expected, const char* message = nullptr) {
  for (bool content : {false, true}) {
    std::string error;
    auto result = content ? p.GetContentScriptAccess(url, 1, &error) : p.GetPageAccess(url, 1, &error);
    assert(result == expected);
    if (message) assert(error == message);
    // Null error pointers must also work. The legacy bool wrappers deliberately
    // return true for withheld access; injection callers use tri-state access.
    assert((content ? p.CanRunContentScriptOnPage(url, 1, nullptr) : p.CanAccessPage(url, 1, nullptr)) ==
           (expected != Access::kDenied));
  }
}
int main() {
  GURL good;
  for (const char* path : {"/", "/category/extensions", "/detail/name/abcdefghijklmnopabcdefghijklmnop"}) {
    GURL page = good; page.path = path;
    both(permitted(), page, Access::kDenied, "gallery");
    both(permitted(true), page, Access::kAllowed);
  }
  for (const char* host : {"chromewebstore.google.com", "a.chromewebstore.google.com",
                           "chromewebstore.google.com.", "chrome.google.com",
                           "a.chrome.google.com", "chrome.google.com."}) {
    GURL page = good; page.host_value = host;
    auto ordinary = permitted(); ordinary.has_tab = true;
    ordinary.tab.explicit_set.matches = ordinary.tab.scriptable_set.matches = true;
    both(ordinary, page, Access::kDenied, "gallery");
    if (page.host_value != good.host_value) both(permitted(true), page, Access::kDenied, "gallery");
  }
  for (const char* host : {"example.test", "chromewebstore.google.com.attacker.test",
                           "notchromewebstore.google.com", "evilchrome.google.com"}) {
    GURL page = good; page.host_value = host;
    both(permitted(), page, Access::kAllowed);
  }
  for (int mode = 0; mode < 4; ++mode) {
    GURL page = good;
    if (mode == 0) page.scheme = "http";
    if (mode == 1) page.port = 8443;
    if (mode == 2) page.username = true;
    if (mode == 3) page.password = true;
    both(permitted(), page, Access::kDenied, "gallery");
    both(permitted(true), page, Access::kDenied, "gallery");
  }
  for (auto loc : {mojom::ManifestLocation::kInternal, mojom::ManifestLocation::kUnpacked,
                   mojom::ManifestLocation::kExternalPolicy}) {
    auto p = permitted(true); p.location_ = loc;
    both(p, good, Access::kDenied, "gallery");
  }
  auto spoof = permitted(true); spoof.extension_id_ = "eldkgppmnhligdekahicdcdndcoongip";
  both(spoof, good, Access::kDenied, "gallery");
  auto missing = permitted(true);
  missing.active_permissions_unsafe_->explicit_set.matches = false;
  missing.active_permissions_unsafe_->scriptable_set.matches = false;
  both(missing, good, Access::kDenied, "page");
  missing.withheld_permissions_unsafe_->explicit_set.matches = true;
  missing.withheld_permissions_unsafe_->scriptable_set.matches = true;
  both(missing, good, Access::kWithheld);
  missing.has_tab = true;
  missing.tab.explicit_set.matches = missing.tab.scriptable_set.matches = true;
  both(missing, good, Access::kAllowed);
  auto helper = permitted(true); helper.policy_blocked = true;
  both(helper, good, Access::kDenied, "policy");
  helper.policy_blocked = false; helper.user_blocked = true;
  both(helper, good, Access::kDenied, "Blocked");
  PermissionsData::PolicyDelegate delegate; delegate.deny = true; g_policy_delegate = &delegate;
  both(permitted(true), good, Access::kDenied, "delegate");
  g_policy_delegate = nullptr;
  ExtensionsClient::Get()->scriptable = false;
  both(permitted(true), good, Access::kDenied, "client");
  ExtensionsClient::Get()->scriptable = true;
  GURL invalid_scheme = good; invalid_scheme.scheme = "data";
  both(permitted(true), invalid_scheme, Access::kDenied, "page");
  // Existing component/global bypass is unchanged, but policy/user host
  // restrictions retain their original behavior outside IsRestrictedUrl.
  auto component = permitted(); component.location_ = mojom::ManifestLocation::kComponent;
  both(component, good, Access::kAllowed);
  auto global = permitted(); global.extension_id_ = "existing-global-allowlist";
  both(global, good, Access::kAllowed);
  global.policy_blocked = true; both(global, good, Access::kDenied, "policy");
  component.user_blocked = true; both(component, good, Access::kDenied, "Blocked");
  // Explicit/scriptable grants remain separate for unrelated control hosts.
  GURL control = good; control.host_value = "example.test";
  auto p = permitted(); p.active_permissions_unsafe_->scriptable_set.matches = false;
  assert(p.GetPageAccess(control, 1, nullptr) == Access::kAllowed);
  assert(p.GetContentScriptAccess(control, 1, nullptr) == Access::kDenied);
}
'''
        harness = harness.replace("DOMAIN_BODY", domain).replace(
            "ACCESS_BODIES", "\n\n".join(function_body(source, sig) for sig in signatures))
        compiler = shutil.which("clang++") or shutil.which("c++")
        if not compiler:
            self.skipTest("A C++ compiler is unavailable for the standalone access fixture")
        with tempfile.TemporaryDirectory(prefix="kumo-store-guard-fixture-") as folder:
            cc = Path(folder) / "permissions_fixture.cc"
            binary = Path(folder) / "permissions_fixture"
            cc.write_text(harness)
            command = [compiler, "-std=c++23", str(cc), "-o", str(binary)]
            if shutil.which("xcrun"):
                sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
                command.extend(["-isysroot", sdk])
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
