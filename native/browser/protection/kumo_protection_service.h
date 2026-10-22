// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_PROTECTION_KUMO_PROTECTION_SERVICE_H_
#define CHROME_BROWSER_KUMO_PROTECTION_KUMO_PROTECTION_SERVICE_H_

#include <memory>
#include "base/functional/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/supports_user_data.h"
#include "base/values.h"
#include "chrome/browser/kumo/kumo_browser_api.h"

class GURL;
class Profile;
namespace blink { class URLLoaderThrottle; }
namespace content { class WebContents; }
namespace user_prefs { class PrefRegistrySyncable; }

namespace kumo {
class ProtectionObserver;
class KumoProtectionService final : public base::SupportsUserData::Data {
 public:
  static KumoProtectionService* Get(Profile* profile);
  ~KumoProtectionService() override;
  base::DictValue GetStatus();
  void SetPhishingEnabled(bool enabled);
  void SetMalwareEnabled(bool enabled);
  void UpdateDomains(ResultCallback callback);
  void AttachToWebContents(content::WebContents* contents);
  static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);
  bool MigrationComplete() const;
  bool DomainsReady() const;
  bool ShouldBlock(const GURL& url) const;
  void WhenDomainsReady(base::OnceClosure callback);
  base::WeakPtr<KumoProtectionService> GetWeakPtr();
  // Native warning WebUI only. Ticket and initiating WebContents are verified
  // here; no URL supplied by the renderer becomes a navigation target.
  base::DictValue WarningDetails(content::WebContents* contents);
  bool ResolveWarning(content::WebContents* contents, bool continue_site);
 private:
  explicit KumoProtectionService(Profile* profile);
  struct Impl;
  std::unique_ptr<Impl> impl_;
  base::WeakPtrFactory<KumoProtectionService> weak_factory_{this};
  friend class ProtectionObserver;
};

std::unique_ptr<blink::URLLoaderThrottle> CreateProtectionThrottle(Profile* profile);
void AttachProtection(content::WebContents* contents);
void RegisterProtectionPrefs(user_prefs::PrefRegistrySyncable* registry);
}  // namespace kumo
#endif
